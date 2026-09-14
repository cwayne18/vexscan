package vexpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/csaf"
)

// OpenVEX statuses and the context vexscan writes. Only not_affected is emitted
// here -- a ruled-out finding is the vendor-independent form of that claim --
// but the constant set is kept complete so a reader of this file sees the whole
// vocabulary the format allows.
const (
	openVEXContext = "https://openvex.dev/ns/v0.2.0"

	StatusNotAffected = "not_affected"
)

// openVEXFileName is what a product's OpenVEX document is called in the hub,
// per the VEX Repository layout internal/vex documents.
const openVEXFileName = "scan.openvex.json"

// openvexEncoder writes the OpenVEX serialisation.
type openvexEncoder struct{}

func (openvexEncoder) fileName() string { return openVEXFileName }

// merge appends the proposal's claims to the hub's document, or builds a fresh
// one when the hub has none.
//
// Bytes that are a CSAF document are declined rather than merged into. Nothing
// in the OpenVEX decode below would object to one -- it would parse as a valid
// document with no statements, and the merge would then graft an OpenVEX
// statements array onto somebody's CSAF advisory and write it back. That
// silently corrupts a file the hub publishes, so the format is checked before
// the parse rather than trusted to fail.
func (e openvexEncoder) merge(raw []byte, prop ProductProposal, meta Meta) ([]byte, []string, error) {
	doc := NewDoc(meta.Author, meta.Timestamp)
	if len(bytes.TrimSpace(raw)) > 0 {
		if csaf.Looks(raw) {
			return nil, nil, decline("it is a CSAF document; re-run with --vex-format csaf to add to it")
		}
		parsed, ok := ParseDoc(raw)
		if !ok {
			return nil, nil, errUnreadable
		}
		doc = parsed
	}

	changes := mergeClaims(doc, []ProductProposal{prop}, meta)
	if len(changes) == 0 {
		return nil, nil, nil
	}
	content, err := doc.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return content, changes[0].Vulns, nil
}

// Doc is an OpenVEX document as it is written to a hub.
//
// It is a separate type from vex.Doc, which is the decoded read-side shape: this
// one carries the on-wire nesting and every field a published document needs,
// including the @context and @id that the reader throws away.
//
// A Doc parsed from an existing hub file keeps that file's raw top-level members
// (in their original order) in original/order, and each existing Statement keeps
// its own raw bytes. Re-marshaling then reproduces every field the format allows
// -- not just the subset this type models -- so appending to a vendor-authored
// document never silently strips fields off the statements it already holds. A
// Doc built fresh (original == nil) is marshaled from the typed shape instead.
type Doc struct {
	Context string `json:"@context"`
	ID      string `json:"@id,omitempty"`
	Author  string `json:"author"`
	// Version is any rather than int because published hubs disagree about it:
	// OpenVEX calls for a number and some tooling writes "1" as a string. A
	// typed int made the string form a decode failure, and a decode failure in
	// this package used to mean the document was replaced wholesale. Nothing
	// here reads the value -- a preserved document re-emits it verbatim -- so
	// the loosest type that round-trips is the right one.
	Version    any         `json:"version"`
	Timestamp  string      `json:"timestamp"`
	Statements []Statement `json:"statements"`

	// original holds every top-level member of the parsed document keyed by
	// name, and order records the order they appeared in. Both are nil for a
	// document that did not come from an existing file.
	original map[string]json.RawMessage
	order    []string
	// layout is how the file it was parsed from was formatted, so re-emitting
	// it does not reflow lines nothing changed.
	layout layout
}

// docShape is the typed on-wire form of a Doc, used to marshal a freshly built
// document and to decode the fields this type reads.
type docShape struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author"`
	Version    any         `json:"version"`
	Timestamp  string      `json:"timestamp"`
	Statements []Statement `json:"statements"`
}

// Statement is one claim about one vulnerability in one product.
//
// A Statement decoded from an existing document keeps its raw bytes so that
// re-marshaling reproduces it verbatim, preserving OpenVEX fields (status_notes,
// @id, version, supplier, ...) that this type does not model. A Statement built
// in-process has raw == nil and is marshaled from its typed fields.
type Statement struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Products      []Product     `json:"products"`
	Status        string        `json:"status"`
	Justification string        `json:"justification,omitempty"`
	// ImpactStatement is the author's own sentence explaining the conclusion.
	// For a vexscan-authored statement it is how the tool reached the verdict,
	// which is the single most useful field for a human reviewing the PR.
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`

	raw json.RawMessage
}

// statementShape is the typed on-wire form of a Statement, used both to marshal
// a new statement and to decode the fields this type reads from an existing one.
type statementShape struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
	Timestamp       string        `json:"timestamp,omitempty"`
}

// UnmarshalJSON decodes the fields this type models while keeping the raw bytes,
// so an existing statement round-trips without losing fields Statement omits.
func (s *Statement) UnmarshalJSON(b []byte) error {
	var shape statementShape
	if err := json.Unmarshal(b, &shape); err != nil {
		return err
	}
	s.Vulnerability = shape.Vulnerability
	s.Products = shape.Products
	s.Status = shape.Status
	s.Justification = shape.Justification
	s.ImpactStatement = shape.ImpactStatement
	s.ActionStatement = shape.ActionStatement
	s.Timestamp = shape.Timestamp
	s.raw = append(json.RawMessage(nil), b...)
	return nil
}

// MarshalJSON emits the original bytes for a statement read from an existing
// document, and the typed shape for one built in-process.
func (s Statement) MarshalJSON() ([]byte, error) {
	if s.raw != nil {
		return s.raw, nil
	}
	return marshalNoEscape(statementShape{
		Vulnerability:   s.Vulnerability,
		Products:        s.Products,
		Status:          s.Status,
		Justification:   s.Justification,
		ImpactStatement: s.ImpactStatement,
		ActionStatement: s.ActionStatement,
		Timestamp:       s.Timestamp,
	})
}

// Vulnerability is the id a statement is filed under plus every alias it is also
// known by, so a later lookup keyed on any of them still finds it.
type Vulnerability struct {
	Name    string   `json:"name"`
	ID      string   `json:"@id,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// Product is one artifact a statement covers and, optionally, the components
// inside it the vulnerability actually belongs to.
type Product struct {
	ID            string         `json:"@id"`
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponent is one dependency inside a product a statement is scoped to.
type Subcomponent struct {
	ID string `json:"@id"`
}

// NewDoc starts an empty document for a hub, with the context and author every
// statement in it will share.
func NewDoc(author, timestamp string) *Doc {
	return &Doc{
		Context:    openVEXContext,
		Author:     author,
		Version:    1,
		Timestamp:  timestamp,
		Statements: []Statement{},
	}
}

// ParseDoc decodes a document already published in the hub, so new statements
// can be merged into it without dropping the ones it already holds.
//
// A missing or malformed document is not an error the caller has to distinguish:
// ParseDoc returns ok=false in that case, because "the hub has no file here yet"
// and "start a fresh document" have the same next step.
//
// The parsed document keeps its raw top-level members (and each statement keeps
// its raw bytes), so a later Marshal reproduces every field OpenVEX allows, not
// just the ones this type models.
func ParseDoc(b []byte) (*Doc, bool) {
	body := bytes.TrimSpace(b)
	if len(body) == 0 {
		return nil, false
	}
	var shape docShape
	if err := json.Unmarshal(body, &shape); err != nil {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false
	}
	order, err := objectKeyOrder(body)
	if err != nil {
		return nil, false
	}
	d := &Doc{
		Context:    shape.Context,
		ID:         shape.ID,
		Author:     shape.Author,
		Version:    shape.Version,
		Timestamp:  shape.Timestamp,
		Statements: shape.Statements,
		original:   fields,
		order:      order,
		// Read off the untrimmed bytes, deliberately. The whitespace trimmed for
		// the decode above is the whole of what a layout is, and detecting it on
		// the trimmed form meant lastNL was never true -- so every merge into an
		// existing hub document dropped that document's trailing newline and
		// added a "\ No newline at end of file" to a diff nothing else in it
		// justified.
		layout: detectLayout(b),
	}
	if d.Statements == nil {
		d.Statements = []Statement{}
	}
	return d, true
}

// MarshalJSON renders the document, preserving the original file's fields and
// order when it came from an existing hub document and emitting the typed shape
// otherwise. Only the statements array and the top-level timestamp -- the two
// things a merge changes -- are overwritten on the preserved form.
func (d *Doc) MarshalJSON() ([]byte, error) {
	if d.original == nil {
		ctx := d.Context
		if ctx == "" {
			ctx = openVEXContext
		}
		return marshalNoEscape(docShape{
			Context:    ctx,
			ID:         d.ID,
			Author:     d.Author,
			Version:    d.Version,
			Timestamp:  d.Timestamp,
			Statements: d.Statements,
		})
	}

	fields := make(map[string]json.RawMessage, len(d.original)+2)
	for k, v := range d.original {
		fields[k] = v
	}
	order := append([]string(nil), d.order...)

	stmts, err := marshalNoEscape(d.Statements)
	if err != nil {
		return nil, err
	}
	order = setRawField(order, fields, "statements", stmts)

	ts, err := marshalNoEscape(d.Timestamp)
	if err != nil {
		return nil, err
	}
	order = setRawField(order, fields, "timestamp", ts)

	if _, ok := fields["@context"]; !ok {
		ctx, err := marshalNoEscape(openVEXContext)
		if err != nil {
			return nil, err
		}
		order = setRawField(order, fields, "@context", ctx)
	}

	return marshalOrderedObject(order, fields)
}

// Marshal renders the document as the pretty-printed JSON a hub stores, in the
// formatting of the file it was parsed from -- two spaces and a trailing
// newline for a document created here.
func (d *Doc) Marshal() ([]byte, error) {
	compact, err := marshalNoEscape(d)
	if err != nil {
		return nil, fmt.Errorf("vexpr: marshal document: %w", err)
	}
	out, err := d.layout.render(compact)
	if err != nil {
		return nil, fmt.Errorf("vexpr: indent document: %w", err)
	}
	return out, nil
}

// mergeClaims adds the proposals' claims to a document, skipping any the
// document already answers, and returns what each product actually gained.
//
// It takes a slice rather than one proposal because a document is not always
// one product's. A per-product document gets a slice of one; an aggregate --
// the merged report some hubs publish alongside the per-product tree -- gets
// every product in the run, folded into one file in a single pass.
//
// A claim is considered already present when the document holds a statement for
// the same vulnerability (by name or alias, case-insensitively) that covers the
// same subcomponent -- either by naming it or by covering the whole product.
// That is the same notion of "covers" the reader matches on, so a merge never
// adds a second statement the reader would treat as a duplicate of an existing
// one.
//
// The document's top-level timestamp is advanced only when something was added,
// so a re-run that changes nothing produces no diff.
func mergeClaims(doc *Doc, props []ProductProposal, meta Meta) []ProductChange {
	idx := newCoverIndex(doc)
	var changes []ProductChange
	for _, prop := range props {
		var added []string
		for _, c := range prop.Claims {
			if idx.covers(prop.Product, c) {
				continue
			}
			doc.Statements = append(doc.Statements, claimStatement(c))
			// Filed as it is appended, so two proposals that somehow carry the
			// same claim cannot both write it.
			idx.add(len(doc.Statements) - 1)
			added = append(added, c.Vuln)
		}
		if len(added) == 0 {
			continue
		}
		sort.Strings(added)
		changes = append(changes, ProductChange{Product: prop.Product, Vulns: added})
	}
	if len(changes) > 0 {
		doc.Timestamp = meta.Timestamp
		if doc.Author == "" {
			doc.Author = meta.Author
		}
	}
	return changes
}

// coverIndex answers "does this document already say this?" without walking
// every statement for every claim.
//
// The linear scan this replaces was fine for a product document holding a few
// dozen statements, and is not fine for an aggregate: rancher/vexhub's merged
// report carries 316,236 of them, and the old check allocated a fresh slice of
// ids per statement inspected. The index pays that cost once, filing each
// statement under every id it can be found by, so a claim is only compared
// against the handful of statements that share one of its ids.
type coverIndex struct {
	doc *Doc
	// byVuln maps a lowercased vulnerability id to the statements filed under
	// it, as indexes into doc.Statements rather than copies -- a Statement
	// carries its original bytes, and 316,236 of those are not worth duplicating
	// to save a subscript.
	byVuln map[string][]int
}

func newCoverIndex(doc *Doc) *coverIndex {
	ci := &coverIndex{doc: doc, byVuln: make(map[string][]int, len(doc.Statements))}
	for i := range doc.Statements {
		ci.add(i)
	}
	return ci
}

// add files a statement under every id it can be matched on.
func (ci *coverIndex) add(i int) {
	v := ci.doc.Statements[i].Vulnerability
	ci.file(v.Name, i)
	ci.file(v.ID, i)
	for _, a := range v.Aliases {
		ci.file(a, i)
	}
}

// file records one id for one statement, skipping the repeat when a statement
// names the same id twice -- as one does when its @id and its name agree.
func (ci *coverIndex) file(id string, i int) {
	if id == "" {
		return
	}
	k := strings.ToLower(id)
	if s := ci.byVuln[k]; len(s) > 0 && s[len(s)-1] == i {
		return
	}
	ci.byVuln[k] = append(ci.byVuln[k], i)
}

// covers reports whether the document already has a statement that would make
// the proposed claim redundant.
func (ci *coverIndex) covers(product string, want Claim) bool {
	wantProduct := decodeKey(product)
	for _, id := range append([]string{want.Vuln}, want.Aliases...) {
		if id == "" {
			continue
		}
		for _, i := range ci.byVuln[strings.ToLower(id)] {
			if statementCovers(ci.doc.Statements[i], wantProduct, want.Subcomponent) {
				return true
			}
		}
	}
	return false
}

// statementCovers reports whether a statement already answers a claim about
// this product and subcomponent. Matching the vulnerability is the caller's
// job; getting here means it already matched.
func statementCovers(s Statement, wantProduct, wantSub string) bool {
	for _, p := range s.Products {
		if decodeKey(p.ID) != wantProduct {
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
	return false
}

// claimStatement is the OpenVEX statement a claim becomes. The mapping is
// one-to-one, which is what OpenVEX being the format this package grew up
// writing amounts to.
func claimStatement(c Claim) Statement {
	prod := Product{ID: c.Product}
	if c.Subcomponent != "" {
		prod.Subcomponents = []Subcomponent{{ID: c.Subcomponent}}
	}
	return Statement{
		Vulnerability:   Vulnerability{Name: c.Vuln, Aliases: c.Aliases},
		Products:        []Product{prod},
		Status:          c.Status,
		Justification:   c.Justification,
		ImpactStatement: c.Impact,
		Timestamp:       c.Timestamp,
	}
}

