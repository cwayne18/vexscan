// Package vexpr proposes OpenVEX statements for the findings vexscan ruled out
// and opens a pull request adding them to a VEX Hub repository.
//
// It is the write counterpart to internal/vex, which only reads. The split is
// deliberate and matches the invariant that package documents: nothing that
// reaches a verdict may also publish one. vexpr never touches a finding's
// status -- it reads the verdict local evidence already produced and serialises
// the ruled-out ones into the format a hub distributes, so the PR says exactly
// what the scan said and nothing the scan did not.
package vexpr

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// OpenVEX statuses and the context vexscan writes. Only not_affected is emitted
// here -- a ruled-out finding is the vendor-independent form of that claim --
// but the constant set is kept complete so a reader of this file sees the whole
// vocabulary the format allows.
const (
	openVEXContext = "https://openvex.dev/ns/v0.2.0"

	StatusNotAffected = "not_affected"
)

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
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author"`
	Version    int         `json:"version"`
	Timestamp  string      `json:"timestamp"`
	Statements []Statement `json:"statements"`

	// original holds every top-level member of the parsed document keyed by
	// name, and order records the order they appeared in. Both are nil for a
	// document that did not come from an existing file.
	original map[string]json.RawMessage
	order    []string
}

// docShape is the typed on-wire form of a Doc, used to marshal a freshly built
// document and to decode the fields this type reads.
type docShape struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author"`
	Version    int         `json:"version"`
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
	return json.Marshal(statementShape{
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
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, false
	}
	var shape docShape
	if err := json.Unmarshal(b, &shape); err != nil {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, false
	}
	order, err := objectKeyOrder(b)
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
		return json.Marshal(docShape{
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

	stmts, err := json.Marshal(d.Statements)
	if err != nil {
		return nil, err
	}
	order = setRawField(order, fields, "statements", stmts)

	ts, err := json.Marshal(d.Timestamp)
	if err != nil {
		return nil, err
	}
	order = setRawField(order, fields, "timestamp", ts)

	if _, ok := fields["@context"]; !ok {
		ctx, err := json.Marshal(openVEXContext)
		if err != nil {
			return nil, err
		}
		order = setRawField(order, fields, "@context", ctx)
	}

	return marshalOrderedObject(order, fields)
}

// Marshal renders the document as the pretty-printed JSON a hub stores, with a
// trailing newline so the committed file matches what an editor would save.
func (d *Doc) Marshal() ([]byte, error) {
	compact, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("vexpr: marshal document: %w", err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("vexpr: indent document: %w", err)
	}
	return append(out.Bytes(), '\n'), nil
}

// setRawField sets a field's value, appending its key to order only if it was
// not already present so existing keys keep their position.
func setRawField(order []string, fields map[string]json.RawMessage, key string, val json.RawMessage) []string {
	if _, ok := fields[key]; !ok {
		order = append(order, key)
	}
	fields[key] = val
	return order
}

// marshalOrderedObject renders a JSON object with its keys in the given order,
// writing each field's raw value verbatim.
func marshalOrderedObject(order []string, fields map[string]json.RawMessage) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	seen := make(map[string]bool, len(order))
	first := true
	for _, k := range order {
		v, ok := fields[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// objectKeyOrder returns the top-level keys of a JSON object in the order they
// appear, so a re-marshaled document keeps the original field order.
func objectKeyOrder(b []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, nil
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("vexpr: unexpected object key %v", keyTok)
		}
		keys = append(keys, key)
		if err := skipJSONValue(dec); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// skipJSONValue consumes the next value from dec, descending through nested
// objects and arrays so the decoder is left positioned after it.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}
