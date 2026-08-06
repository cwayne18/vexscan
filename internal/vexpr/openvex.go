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
type Doc struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author"`
	Version    int         `json:"version"`
	Timestamp  string      `json:"timestamp"`
	Statements []Statement `json:"statements"`
}

// Statement is one claim about one vulnerability in one product.
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
func ParseDoc(b []byte) (*Doc, bool) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, false
	}
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, false
	}
	if d.Statements == nil {
		d.Statements = []Statement{}
	}
	return &d, true
}

// Marshal renders the document as the pretty-printed JSON a hub stores, with a
// trailing newline so the committed file matches what an editor would save.
func (d *Doc) Marshal() ([]byte, error) {
	if d.Context == "" {
		d.Context = openVEXContext
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vexpr: marshal document: %w", err)
	}
	return append(b, '\n'), nil
}
