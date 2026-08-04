package triage

import (
	"context"
	"encoding/json"
	"fmt"
)

// kevFile is the cache filename. Unlike EPSS there is no dated URL, so this one
// is revalidated with the ETag the catalog serves.
const kevFile = "known_exploited_vulnerabilities.json"

// kevCatalog is the shape of CISA's feed, reduced to what is read.
type kevCatalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// loadKEV returns the catalog keyed by CVE, its version, and whether it came
// off disk because the network could not be reached.
//
// The catalog is not filtered by a wanted set the way EPSS is: 1,657 entries is
// nothing to hold, and the whole map is worth having so a caller can say how
// large the catalog it checked against was.
func (l *Loader) loadKEV(ctx context.Context, c cache) (map[string]KEVEntry, string, bool, error) {
	v := c.readValidators(kevFile)
	body, got, notModified, err := download(ctx, l.client(), l.kevURL(), v)

	switch {
	case err != nil:
		// Fall back to whatever was downloaded last, and say so.
		cached, cacheErr := c.read(kevFile)
		if cacheErr != nil {
			return nil, "", false, err
		}
		entries, version, parseErr := parseKEV(cached)
		if parseErr != nil {
			return nil, "", false, err
		}
		return entries, version, true, nil

	case notModified:
		cached, cacheErr := c.read(kevFile)
		if cacheErr == nil {
			if entries, version, parseErr := parseKEV(cached); parseErr == nil {
				return entries, version, false, nil
			}
		}
		// The server says our copy is current and we no longer have it. Ask
		// again without the validators rather than reporting a failure.
		body, got, _, err = download(ctx, l.client(), l.kevURL(), validators{})
		if err != nil {
			return nil, "", false, err
		}
	}

	entries, version, err := parseKEV(body)
	if err != nil {
		return nil, "", false, err
	}
	if err := c.write(kevFile, body); err != nil {
		l.logf("triage: could not cache the KEV catalog: %v", err)
	} else if err := c.writeValidators(kevFile, got); err != nil {
		l.logf("triage: could not cache the KEV validators: %v", err)
	}
	return entries, version, false, nil
}

func (l *Loader) kevURL() string { return orElse(l.KEVURL, KEVURL) }

func parseKEV(body []byte) (map[string]KEVEntry, string, error) {
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, "", fmt.Errorf("kev: %w", err)
	}
	entries := make(map[string]KEVEntry, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		entries[v.CVEID] = KEVEntry{
			DateAdded: v.DateAdded,
			DueDate:   v.DueDate,
			// The field is the string "Known" / "Unknown", not a boolean, and
			// "Unknown" means nobody has established it either way. Only the
			// affirmative is worth reporting.
			Ransomware: v.KnownRansomwareCampaignUse == "Known",
		}
	}
	return entries, cat.CatalogVersion, nil
}
