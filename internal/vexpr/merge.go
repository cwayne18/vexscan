package vexpr

import (
	"encoding/json"
	"fmt"
	"strings"
)

// indexFile is the hub's index.json: the map from product purl to the location
// of that product's document.
//
// The file is held as its original bytes, not just as the two fields this code
// reads. A hub's index is its own artifact -- rancher/vexhub's is 208 KB and
// over a thousand entries -- and re-serialising a decoded form would rewrite
// every line of it, dropping any field the format has grown since this was
// written and burying a one-product change in a whole-file diff. So existing
// package entries are re-emitted verbatim, new ones are appended, and unknown
// top-level members are carried through in their original order.
type indexFile struct {
	// packages are the entries in file order, each keeping its raw bytes.
	packages []indexPackage
	// original and order preserve the top-level object, as in Doc. Both are nil
	// for an index built from nothing.
	original map[string]json.RawMessage
	order    []string
	// layout is the formatting of the file it was parsed from, so adding one
	// package does not reflow the other thousand.
	layout layout
}

// indexPackage is one entry in index.json's packages array: the two fields this
// code reads, plus the bytes it was read from.
type indexPackage struct {
	ID       string `json:"id"`
	Location string `json:"location"`

	raw json.RawMessage
}

// newIndex is the index of a hub that does not exist yet -- the --vex-out case
// with no --vexhub to merge against, where the output tree is a hub being
// started rather than one being added to.
func newIndex() *indexFile {
	return &indexFile{
		original: map[string]json.RawMessage{"version": json.RawMessage("1")},
		order:    []string{"version", "packages"},
		layout:   defaultLayout(),
	}
}

// parseIndex decodes index.json. An unreadable index is a fatal condition for
// this flow, not a recoverable one: without it there is no way to know where an
// existing product's document lives, and guessing would risk writing a second
// document the hub never reads.
func parseIndex(b []byte) (*indexFile, error) {
	var shape struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(b, &shape); err != nil {
		return nil, fmt.Errorf("vexpr: parse index.json: %w", err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, fmt.Errorf("vexpr: parse index.json: %w", err)
	}
	order, err := objectKeyOrder(b)
	if err != nil {
		return nil, fmt.Errorf("vexpr: parse index.json: %w", err)
	}
	idx := &indexFile{original: fields, order: order, layout: detectLayout(b)}
	for i, raw := range shape.Packages {
		var p indexPackage
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("vexpr: parse index.json: package %d: %w", i, err)
		}
		p.raw = append(json.RawMessage(nil), raw...)
		idx.packages = append(idx.packages, p)
	}
	return idx, nil
}

// location returns the stored document path for a product, matching keys the way
// the hub does: percent-encoding aside, an oci key differs from the plain purl,
// so both sides are compared decoded.
func (idx *indexFile) location(product string) (string, bool) {
	want := decodeKey(product)
	for _, p := range idx.packages {
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
	idx.packages = append(idx.packages, indexPackage{ID: key, Location: loc})
	return loc, true, nil
}

// marshal renders index.json: every original member in its original place, with
// packages replaced by the same array plus whatever was appended.
func (idx *indexFile) marshal() ([]byte, error) {
	entries := make([]json.RawMessage, 0, len(idx.packages))
	for _, p := range idx.packages {
		if p.raw != nil {
			entries = append(entries, p.raw)
			continue
		}
		b, err := marshalNoEscape(struct {
			ID       string `json:"id"`
			Location string `json:"location"`
		}{p.ID, p.Location})
		if err != nil {
			return nil, fmt.Errorf("vexpr: marshal index.json: %w", err)
		}
		entries = append(entries, b)
	}
	packages, err := marshalNoEscape(entries)
	if err != nil {
		return nil, fmt.Errorf("vexpr: marshal index.json: %w", err)
	}

	fields := make(map[string]json.RawMessage, len(idx.original)+1)
	for k, v := range idx.original {
		fields[k] = v
	}
	order := setRawField(append([]string(nil), idx.order...), fields, "packages", packages)

	compact, err := marshalOrderedObject(order, fields)
	if err != nil {
		return nil, fmt.Errorf("vexpr: marshal index.json: %w", err)
	}
	out, err := idx.layout.render(compact)
	if err != nil {
		return nil, fmt.Errorf("vexpr: indent index.json: %w", err)
	}
	return out, nil
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
