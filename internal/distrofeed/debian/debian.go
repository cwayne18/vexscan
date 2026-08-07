// Package debian turns the Debian security tracker into distrofeed statements.
//
// The tracker publishes one big JSON object keyed by source package, then by
// CVE, then by Debian release, with a per-release status and the version a fix
// landed in:
//
//	{ "openssl": { "CVE-2023-0464": { "releases": {
//	    "bookworm": {"status":"resolved","fixed_version":"3.0.9-1","urgency":"not yet assigned"},
//	    "bullseye": {"status":"open","fixed_version":"0"} } } } }
//
// Two of those shapes clear a finding, and only two:
//
//   - fixed_version "0" for the image's release means Debian's build is *not
//     affected* -- the flaw is in code they do not compile, or never applied to
//     their packaging. This is the false positive an upstream OSV range cannot
//     see and the tracker exists to record.
//   - status "resolved" with a real fixed_version that is at or below the
//     installed version means the fix already shipped. OSV flagging it anyway is
//     usually an epoch or backport the generic range did not know about.
//
// Everything else -- "open", "undetermined", a fix newer than what is installed,
// a nodsa note (Debian is affected but will not issue an update) -- is carried
// as evidence and clears nothing. When the image's release cannot be mapped to a
// tracker codename the provider declines rather than guess, because a claim read
// off the wrong release is exactly the kind of wrong answer this tool must not
// produce.
package debian

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cwayne18/vexscan/internal/debver"
	"github.com/cwayne18/vexscan/internal/distrofeed"
)

// DefaultBaseURL is the tracker's bulk JSON. The provider derives its one
// endpoint from it, so pointing BaseURL at a mirror or an offline copy -- the
// same escape hatch osv.Client offers -- reroutes the whole feed.
const DefaultBaseURL = "https://security-tracker.debian.org/tracker/data/json"

// author is recorded on every statement this provider emits.
const author = "Debian Security Tracker"

// Provider reads the Debian security tracker.
type Provider struct {
	// HTTP is the client used to fetch the feed; http.DefaultClient when nil.
	HTTP *http.Client
	// BaseURL is the tracker JSON URL; DefaultBaseURL when empty.
	BaseURL string
}

// New returns a Provider with sane defaults.
func New() *Provider {
	return &Provider{
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		BaseURL: DefaultBaseURL,
	}
}

// Name implements distrofeed.Provider.
func (p *Provider) Name() string { return author }

// Handles claims the Debian tracker's scope: Debian itself. Ubuntu derives from
// Debian but tracks security in a separate database with different verdicts, so
// answering for it here would attach Debian's claims to an Ubuntu build -- a
// wrong answer wearing a real vendor's name. Ubuntu is a separate provider.
func (p *Provider) Handles(osID string) bool {
	return strings.EqualFold(osID, "debian")
}

// trackerEntry is one CVE's record for one source package: its per-release rows.
type trackerEntry struct {
	Releases map[string]releaseInfo `json:"releases"`
}

// releaseInfo is the tracker's verdict for one CVE in one Debian release.
type releaseInfo struct {
	Status       string `json:"status"`        // "resolved" | "open" | "undetermined"
	FixedVersion string `json:"fixed_version"` // a version, or "0" for not-affected
	Urgency      string `json:"urgency"`
	// NoDSA is set when Debian acknowledges the flaw but will not issue an
	// update for this release. It means affected, so it is a reason not to
	// clear, and is carried only to explain why a row Debian "knows about"
	// still stands.
	NoDSA string `json:"nodsa"`
}

// Lookup fetches the tracker and returns statements for the queried packages.
func (p *Provider) Lookup(ctx context.Context, q distrofeed.Query) ([]distrofeed.Statement, error) {
	codename := codenameFor(q.Release)
	if codename == "" {
		// No release to key on: a release-scoped feed cannot answer without
		// risking the wrong release's verdict. Silence, not a guess.
		return nil, nil
	}

	want := wantedSources(q.Packages)
	if len(want) == 0 {
		return nil, nil
	}

	body, err := p.fetch(ctx)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	index, err := decodeFiltered(body, want)
	if err != nil {
		return nil, fmt.Errorf("debian: parse tracker: %w", err)
	}

	var out []distrofeed.Statement
	for _, pkg := range q.Packages {
		for _, key := range sourceKeys(pkg) {
			cves, ok := index[key]
			if !ok {
				continue
			}
			if st, ok := statementFor(pkg, key, codename, cves, p.url()); ok {
				out = append(out, st)
			}
			break // the first key that the tracker knows is the one
		}
	}
	return out, nil
}

// statementFor decides this package's one statement for the release, if the
// tracker has a verdict for any of the finding's ids.
func statementFor(pkg distrofeed.PkgRef, source, codename string, cves map[string]trackerEntry, url string) (distrofeed.Statement, bool) {
	for _, id := range pkg.CVEs {
		entry, ok := cves[id]
		if !ok {
			continue
		}
		rel, ok := entry.Releases[codename]
		if !ok {
			continue
		}
		status, fixed, why := classify(rel, pkg.Version)
		if status == "" {
			continue
		}
		return distrofeed.Statement{
			RefID:         pkg.ID,
			Distro:        "debian",
			Package:       source,
			CVE:           id,
			Status:        status,
			FixedVersion:  fixed,
			Justification: why,
			Source:        url,
			Author:        author,
		}, true
	}
	return distrofeed.Statement{}, false
}

// classify turns one release row into a status, and is where the tool's caution
// lives: only the two shapes that are unambiguously exculpatory clear anything,
// and a published fix clears only once the installed version has actually
// reached it.
func classify(rel releaseInfo, installed string) (status distrofeed.Status, fixed, why string) {
	switch rel.Status {
	case "resolved":
		// Handle resolved before nodsa: the tracker leaves a stale nodsa note on
		// some rows that later became resolved, so checking nodsa first would
		// leave an already-fixed package looking affected. A resolved row with a
		// real fix or the "0" not-affected marker is authoritative.
		//
		// fixed_version "0" is the tracker's marker for a release the vulnerable
		// code never applied to: not affected. It only ever appears under a
		// resolved status, so it is read only there.
		if rel.FixedVersion == "0" {
			return distrofeed.StatusNotAffected, "", "Debian marks this source package not affected in this release"
		}
		if rel.FixedVersion == "" {
			return "", "", ""
		}
		// The fix has to have actually landed in what is installed. A fix newer
		// than the image is a finding that stands, not one the vendor cleared.
		if installed == "" || debver.Compare(installed, rel.FixedVersion) < 0 {
			return distrofeed.StatusAffected, rel.FixedVersion, "fixed in " + rel.FixedVersion + ", newer than what is installed"
		}
		return distrofeed.StatusFixed, rel.FixedVersion, "Debian fixed this in " + rel.FixedVersion
	case "open":
		if rel.NoDSA != "" {
			// Debian acknowledges the flaw and has decided not to fix it in this
			// release. Affected, and never exculpatory; reported so the reader
			// sees the vendor already triaged it.
			return distrofeed.StatusAffected, "", "Debian will not issue an update (nodsa): " + rel.NoDSA
		}
		return distrofeed.StatusAffected, "", "Debian has an open advisory for this release"
	case "undetermined":
		return distrofeed.StatusUnderInvestigation, "", "Debian has not determined whether this release is affected"
	}
	if rel.NoDSA != "" {
		return distrofeed.StatusAffected, "", "Debian will not issue an update (nodsa): " + rel.NoDSA
	}
	return "", "", ""
}

// sourceKeys is the tracker keys to try for one finding, most specific first:
// the source package the advisory is filed under, then the installed binary
// name, since a caller that only knew the binary still gets an answer.
func sourceKeys(pkg distrofeed.PkgRef) []string {
	var keys []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, k := range keys {
			if k == s {
				return
			}
		}
		keys = append(keys, s)
	}
	add(pkg.Source)
	add(pkg.Name)
	return keys
}

// wantedSources is the set of tracker keys the decoder keeps, so the 40 MB feed
// is filtered to the handful of packages the scan actually asked about instead
// of being held in memory whole.
func wantedSources(pkgs []distrofeed.PkgRef) map[string]bool {
	want := map[string]bool{}
	for _, p := range pkgs {
		for _, k := range sourceKeys(p) {
			want[k] = true
		}
	}
	return want
}

func (p *Provider) url() string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	return DefaultBaseURL
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}

func (p *Provider) fetch(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("debian: fetch tracker: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("debian: fetch tracker: %s: %s", p.url(), resp.Status)
	}
	return resp.Body, nil
}

// decodeFiltered streams the tracker object and decodes only the source-package
// entries in want, skipping the rest without buffering them. The top level is
// one object keyed by source package; linux alone is megabytes, so decoding the
// whole thing to pick out a few packages would be wasteful where skipping is
// easy.
func decodeFiltered(r io.Reader, want map[string]bool) (map[string]map[string]trackerEntry, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token() // opening '{'
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected top-level object, got %v", tok)
	}
	out := map[string]map[string]trackerEntry{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		if want[key] {
			var v map[string]trackerEntry
			if err := dec.Decode(&v); err != nil {
				return nil, err
			}
			out[key] = v
			continue
		}
		if err := skipValue(dec); err != nil {
			return nil, err
		}
	}
	// dec.More returns false at a closing '}' *and* at EOF, so a stream
	// truncated mid-object would otherwise look like a clean, complete parse
	// and could clear findings off a feed that never finished downloading.
	// Require the real closing brace and then a real EOF: any short read
	// rejects the whole feed rather than partially trusting it.
	closeTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := closeTok.(json.Delim); !ok || d != '}' {
		return nil, fmt.Errorf("expected closing brace, got %v", closeTok)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing data after tracker object")
		}
		return nil, err
	}
	return out, nil
}

// skipValue reads and discards the next JSON value, descending through nested
// arrays and objects by depth so a large value is walked, not held.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar: one token, already consumed
	}
	if delim != '{' && delim != '[' {
		return nil
	}
	for depth := 1; depth > 0; {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}
