package vexpr

import (
	"encoding/json"
	"fmt"
	"strings"
)

// indexFile is the hub's index.json: the map from product purl to the location
// of that product's document. Unknown top-level fields are not preserved -- the
// format defines only these two -- but the order of existing packages is, so a
// PR that adds one product does not reshuffle the file.
type indexFile struct {
	Version  int            `json:"version"`
	Packages []indexPackage `json:"packages"`
}

type indexPackage struct {
	ID       string `json:"id"`
	Location string `json:"location"`
}

// parseIndex decodes index.json. A missing or unreadable index is a fatal
// condition for this flow, not a recoverable one: without it there is no way to
// know where an existing product's document lives, and guessing would risk
// writing a second document the hub never reads.
func parseIndex(b []byte) (*indexFile, error) {
	var idx indexFile
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("vexpr: parse index.json: %w", err)
	}
	if idx.Version == 0 {
		idx.Version = 1
	}
	return &idx, nil
}

// location returns the stored document path for a product, matching keys the way
// the hub does: percent-encoding aside, an oci key differs from the plain purl,
// so both sides are compared decoded.
func (idx *indexFile) location(product string) (string, bool) {
	want := decodeKey(product)
	for _, p := range idx.Packages {
		if decodeKey(p.ID) == want {
			return p.Location, true
		}
	}
	return "", false
}

// ensure adds a product to the index if it is not already there, returning the
// location it should be written to and whether the index changed.
func (idx *indexFile) ensure(product string) (location string, changed bool, err error) {
	if loc, ok := idx.location(product); ok {
		if err := checkHubLocation(loc); err != nil {
			return "", false, err
		}
		return loc, false, nil
	}
	loc, err := productLocation(product)
	if err != nil {
		return "", false, err
	}
	key, err := indexKey(product)
	if err != nil {
		return "", false, err
	}
	idx.Packages = append(idx.Packages, indexPackage{ID: key, Location: loc})
	return loc, true, nil
}

func (idx *indexFile) marshal() ([]byte, error) {
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vexpr: marshal index.json: %w", err)
	}
	return append(b, '\n'), nil
}

// decodeKey reduces a product key to the spelling used for comparison: the same
// PathUnescape the reader applies, so an encoded oci index key and a plain purl
// line up.
func decodeKey(purl string) string {
	typ, body, ok := splitPurl(purl)
	if !ok {
		return strings.TrimSpace(purl)
	}
	if typ != "oci" {
		return strings.TrimSpace(purl)
	}
	name, _ := splitQualifiers(body)
	repo := repositoryURL(body)
	return fmt.Sprintf("pkg:oci/%s?repository_url=%s", name, repo)
}

// mergeStatements adds a proposal's statements to a document, skipping any the
// document already answers, and returns how many were actually new.
//
// A statement is considered already present when the document holds one for the
// same vulnerability (by name or alias, case-insensitively) that covers the same
// subcomponent -- either by naming it or by covering the whole product. That is
// the same notion of "covers" the reader matches on, so a merge never adds a
// second statement the reader would treat as a duplicate of an existing one.
//
// The document's top-level timestamp is advanced only when something was added,
// so a re-run that changes nothing produces no diff.
func mergeStatements(doc *Doc, prop ProductProposal, author, timestamp string) int {
	var added int
	for _, st := range prop.Statements {
		if documentCovers(doc, prop.Product, st) {
			continue
		}
		doc.Statements = append(doc.Statements, st)
		added++
	}
	if added > 0 {
		doc.Timestamp = timestamp
		if doc.Author == "" {
			doc.Author = author
		}
	}
	return added
}

// documentCovers reports whether the document already has a statement that would
// make the proposed one redundant.
func documentCovers(doc *Doc, product string, want Statement) bool {
	wantIDs := append([]string{want.Vulnerability.Name}, want.Vulnerability.Aliases...)
	wantSub := subcomponentID(want)
	for _, s := range doc.Statements {
		if !sharesVuln(s.Vulnerability, wantIDs) {
			continue
		}
		for _, p := range s.Products {
			if decodeKey(p.ID) != decodeKey(product) {
				continue
			}
			if len(p.Subcomponents) == 0 {
				return true // product-wide statement covers any subcomponent
			}
			for _, sc := range p.Subcomponents {
				if sc.ID == wantSub {
					return true
				}
			}
		}
	}
	return false
}

// sharesVuln reports whether an existing vulnerability names any of the wanted
// ids, comparing case-insensitively across name, @id and aliases.
func sharesVuln(v Vulnerability, wantIDs []string) bool {
	have := append([]string{v.Name, v.ID}, v.Aliases...)
	for _, w := range wantIDs {
		if w == "" {
			continue
		}
		for _, h := range have {
			if h != "" && strings.EqualFold(h, w) {
				return true
			}
		}
	}
	return false
}
