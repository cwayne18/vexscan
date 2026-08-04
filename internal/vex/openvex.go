// Package vex reads OpenVEX documents from a VEX Hub repository and matches
// their statements against findings.
//
// A VEX hub is a vendor saying, in public and in a machine-readable form, "we
// looked at this CVE in this product and here is what we concluded". vexscan
// reaches its own conclusions from local evidence; a hub says whether someone
// with more context has already answered the same question. The two are kept
// apart on purpose -- nothing in this package sets a status.
//
// The shape of a hub, as published:
//
//	vex-repository.json          the repository's own metadata
//	index.json                   product purl -> path of that product's document
//	pkg/<type>/<path>/scan.openvex.json
//
// The unit of a document is a statement about a (vulnerability, product) pair,
// where the product is the shipped artifact -- a container image, a Go main
// module -- and the optional subcomponents are the dependencies inside it that
// the vulnerability is actually filed against. A vexscan finding is one of
// those subcomponents, so matching means agreeing on the product, the
// vulnerability and the subcomponent all three.
package vex

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VEX statuses, as OpenVEX defines them.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Exculpatory reports whether a status says the reader has nothing to do.
//
// not_affected and fixed answer the question; affected and
// under_investigation are the vendor agreeing there is one, or admitting they
// do not know yet, and neither should make a finding quieter.
func Exculpatory(status string) bool {
	switch status {
	case StatusNotAffected, StatusFixed:
		return true
	}
	return false
}

// Doc is one OpenVEX document.
type Doc struct {
	Author     string
	Timestamp  string
	Statements []Statement
}

// Statement is one claim about one vulnerability in one product.
type Statement struct {
	// Vulnerability is the id the vendor filed the statement under. It is not
	// always a CVE: a SUSE-keyed hub writes advisory ids like
	// "SUSE-RU-2026:1228-1", which OSV also publishes, so they still match.
	Vulnerability string
	Aliases       []string
	Products      []Product

	Status        string
	Justification string
	// ImpactStatement is the vendor's own sentence explaining the conclusion,
	// and is usually the single most useful field in the document.
	ImpactStatement string
	ActionStatement string
	Timestamp       string
}

// Product is one artifact a statement covers, and optionally the components
// inside it the vulnerability belongs to.
//
// An entry with no subcomponents covers the whole product. That is a stronger
// claim than a subcomponent-scoped one and is treated as such when two
// statements compete.
type Product struct {
	ID            string
	Subcomponents []string
}

// wireDoc is the on-the-wire shape. It is separate from Doc because OpenVEX
// nests every id one level deeper than anything downstream wants to read.
type wireDoc struct {
	Author     string `json:"author"`
	Timestamp  string `json:"timestamp"`
	Statements []struct {
		Vulnerability struct {
			Name    string   `json:"name"`
			ID      string   `json:"@id"`
			Aliases []string `json:"aliases"`
		} `json:"vulnerability"`
		Products []struct {
			ID            string `json:"@id"`
			Subcomponents []struct {
				ID string `json:"@id"`
			} `json:"subcomponents"`
		} `json:"products"`
		Status          string `json:"status"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
		Timestamp       string `json:"timestamp"`
	} `json:"statements"`
}

// ParseDoc decodes an OpenVEX document.
//
// A statement naming no vulnerability or no product cannot be matched against
// anything, so it is dropped rather than carried as an entry that silently
// never fires.
func ParseDoc(b []byte) (*Doc, error) {
	var w wireDoc
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("vex: parse document: %w", err)
	}
	doc := &Doc{Author: w.Author, Timestamp: w.Timestamp}
	for _, s := range w.Statements {
		name := s.Vulnerability.Name
		if name == "" {
			// Some producers put the id in @id and nothing in name.
			name = s.Vulnerability.ID
		}
		if name == "" || len(s.Products) == 0 {
			continue
		}
		st := Statement{
			Vulnerability:   name,
			Aliases:         s.Vulnerability.Aliases,
			Status:          s.Status,
			Justification:   s.Justification,
			ImpactStatement: s.ImpactStatement,
			ActionStatement: s.ActionStatement,
			Timestamp:       s.Timestamp,
		}
		if st.Timestamp == "" {
			st.Timestamp = w.Timestamp
		}
		for _, p := range s.Products {
			if p.ID == "" {
				continue
			}
			prod := Product{ID: p.ID}
			for _, sc := range p.Subcomponents {
				if sc.ID != "" {
					prod.Subcomponents = append(prod.Subcomponents, sc.ID)
				}
			}
			st.Products = append(st.Products, prod)
		}
		if len(st.Products) == 0 {
			continue
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

// ids returns the vulnerability id and every alias, for matching.
func (s Statement) ids() []string {
	out := make([]string, 0, len(s.Aliases)+1)
	out = append(out, s.Vulnerability)
	out = append(out, s.Aliases...)
	return out
}

// namesVulnerability reports whether the statement is about any of these ids.
//
// Matching is case-insensitive because the id spellings come from four
// different publishers and only agree on the letters.
func (s Statement) namesVulnerability(ids []string) bool {
	for _, want := range ids {
		if want == "" {
			continue
		}
		for _, have := range s.ids() {
			if strings.EqualFold(have, want) {
				return true
			}
		}
	}
	return false
}
