// Package csaf decodes and writes CSAF 2.0 documents -- the OASIS format SUSE,
// Red Hat, Cisco and Oracle publish their VEX in.
//
// It decodes and resolves; it does not judge. The product tree becomes a lookup
// from product id to the purl, CPE and composition that identify it, and the
// vulnerability entries come back with their statuses, flags, threats and
// remediations attached to the product ids they apply to. What any of that
// means for a finding is the caller's business, which is why internal/vex and
// internal/distrofeed/suse can both read this package and still disagree about
// how to match: one joins on purl, the other on a CPE and an rpm name, and each
// is right for the feed it reads.
//
// The shape of the format, as far as anything here cares:
//
//	document      who published it, when, and under what tracking id
//	product_tree  every product id the document will refer to, defined once
//	vulnerabilities[]
//	              per CVE: which product ids are affected, not affected, fixed
//	              or under investigation, plus the flags, threats and
//	              remediations that explain those verdicts
//
// The indirection through product_tree is the whole difference from OpenVEX,
// which writes the purl in place. A CSAF product_status names opaque ids and
// the tree says what they are, so nothing can be matched until the tree is
// resolved.
package csaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Category is the document category the VEX profile requires, and Version the
// only CSAF version this package reads or writes.
const (
	Category = "csaf_vex"
	Version  = "2.0"
)

// The VEX statuses, named for what they mean rather than for the
// product_status member they come from. They are spelled identically in
// OpenVEX, which is why nothing downstream of a parse has to translate them.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Document is a CSAF 2.0 document.
type Document struct {
	Document        Meta            `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Meta is the document-level metadata every CSAF document must carry.
type Meta struct {
	Category    string    `json:"category"`
	CSAFVersion string    `json:"csaf_version"`
	Publisher   Publisher `json:"publisher"`
	Title       string    `json:"title"`
	Tracking    Tracking  `json:"tracking"`
	Notes       []Note    `json:"notes,omitempty"`
}

// Publisher is who is answerable for the document.
//
// The VEX profile makes all three fields mandatory, which is why writing CSAF
// needs more from the caller than writing OpenVEX does: OpenVEX asks for an
// author string, CSAF asks for an identity.
type Publisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// PublisherCategories are the values CSAF allows for Publisher.Category.
var PublisherCategories = []string{"coordinator", "discoverer", "other", "translator", "user", "vendor"}

// ValidPublisherCategory reports whether c is one CSAF allows.
func ValidPublisherCategory(c string) bool {
	for _, want := range PublisherCategories {
		if c == want {
			return true
		}
	}
	return false
}

// Tracking is the document's identity and revision history.
//
// This is the largest difference from OpenVEX and the one that shapes how a
// document may be amended. An OpenVEX document is a bag of statements you can
// append to in silence. A CSAF document is an advisory: changing it means
// publishing a new version of it, with the change recorded and the release date
// moved. A writer that appends a statement and leaves the tracking block alone
// has produced a document that lies about itself.
type Tracking struct {
	ID                 string     `json:"id"`
	InitialReleaseDate string     `json:"initial_release_date"`
	CurrentReleaseDate string     `json:"current_release_date"`
	RevisionHistory    []Revision `json:"revision_history"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
}

// Revision is one entry in a document's revision history.
type Revision struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

// Note is prose attached to a document or a vulnerability.
type Note struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

// ProductTree defines every product id the document refers to.
//
// All three members can define ids and real documents use all three: SUSE nests
// everything in branches, a hand-written VEX tends to use full_product_names,
// and relationships are the only way to say "this component, inside that
// artifact" -- the claim vexscan's matching is built around.
type ProductTree struct {
	Branches         []Branch       `json:"branches,omitempty"`
	FullProductNames []FullProduct  `json:"full_product_names,omitempty"`
	Relationships    []Relationship `json:"relationships,omitempty"`
}

// Branch is a node in the product tree: either a product, or more branches.
type Branch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *FullProduct `json:"product,omitempty"`
	Branches []Branch     `json:"branches,omitempty"`
}

// FullProduct is one product id and what identifies it.
type FullProduct struct {
	ProductID string  `json:"product_id"`
	Name      string  `json:"name"`
	Helper    *Helper `json:"product_identification_helper,omitempty"`
}

// PURL is the product's package URL, or "" when it carries none.
func (p FullProduct) PURL() string {
	if p.Helper == nil {
		return ""
	}
	return strings.TrimSpace(p.Helper.PURL)
}

// CPE is the product's CPE, or "" when it carries none.
func (p FullProduct) CPE() string {
	if p.Helper == nil {
		return ""
	}
	return strings.TrimSpace(p.Helper.CPE)
}

// Helper is the identifiers attached to a product.
//
// CSAF allows several more (hashes, sbom_urls, serial_numbers, model_numbers,
// x_generic_uris); only the two anything here joins on are modelled. Nothing is
// lost by that: a document this package writes never carries them, and one it
// reads is only ever read.
type Helper struct {
	CPE  string `json:"cpe,omitempty"`
	PURL string `json:"purl,omitempty"`
}

// Relationship joins a component to the artifact it is part of, and defines a
// new product id standing for the pair.
//
// ProductReference is the component and RelatesToProductReference is what it
// sits inside, for every category CSAF defines -- default_component_of,
// optional_component_of, external_component_of, installed_on, installed_with.
// The direction is fixed by the format, so the category only says how loosely
// the component is attached, which is not a distinction anything here draws.
type Relationship struct {
	Category                  string      `json:"category"`
	FullProductName           FullProduct `json:"full_product_name"`
	ProductReference          string      `json:"product_reference"`
	RelatesToProductReference string      `json:"relates_to_product_reference"`
}

// ComponentOf is the relationship category a writer here uses: the component is
// shipped as part of the artifact, which is what a scanned image's dependency
// is.
const ComponentOf = "default_component_of"

// Vulnerability is one CVE and its per-product verdicts.
type Vulnerability struct {
	CVE           string        `json:"cve,omitempty"`
	IDs           []VulnID      `json:"ids,omitempty"`
	Notes         []Note        `json:"notes,omitempty"`
	ReleaseDate   string        `json:"release_date,omitempty"`
	Flags         []Flag        `json:"flags,omitempty"`
	ProductStatus ProductStatus `json:"product_status"`
	Remediations  []Remediation `json:"remediations,omitempty"`
	Scores        []Score       `json:"scores,omitempty"`
	Threats       []Threat      `json:"threats,omitempty"`
}

// VulnID is another name the vulnerability goes by. It is CSAF's equivalent of
// an OpenVEX alias list, and matters for the same reason: the two sides of a
// match rarely spell an advisory the same way.
type VulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// ProductStatus is the per-product verdict lists.
//
// Only four of the eight are verdicts. first_affected, last_affected and
// first_fixed mark the edges of a version range, and recommended names the
// package to upgrade to -- none of them says "this product has this status",
// and reading them as if they did would clear findings the document never spoke
// to. Statuses maps only the four the VEX profile defines.
type ProductStatus struct {
	FirstAffected      []string `json:"first_affected,omitempty"`
	FirstFixed         []string `json:"first_fixed,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	LastAffected       []string `json:"last_affected,omitempty"`
	Recommended        []string `json:"recommended,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

// StatusList is one product_status member: the VEX status it means and the
// product ids in it.
type StatusList struct {
	Status     string
	ProductIDs []string
}

// Statuses returns the four VEX verdicts this product_status carries, in a
// fixed order so a caller that walks them twice gets the same answer twice.
func (ps ProductStatus) Statuses() []StatusList {
	out := make([]StatusList, 0, 4)
	for _, l := range []StatusList{
		{StatusNotAffected, ps.KnownNotAffected},
		{StatusAffected, ps.KnownAffected},
		{StatusFixed, ps.Fixed},
		{StatusUnderInvestigation, ps.UnderInvestigation},
	} {
		if len(l.ProductIDs) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// Flag is the justification for a not-affected verdict, scoped to the products
// it applies to.
//
// The label vocabulary is byte-identical to OpenVEX's justification vocabulary
// -- component_not_present, vulnerable_code_not_present,
// vulnerable_code_not_in_execute_path,
// vulnerable_code_cannot_be_controlled_by_adversary,
// inline_mitigations_already_exist. That agreement is the reason nothing past
// the parse, in either direction, has to know which format it is looking at.
type Flag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// Threat is an assessment attached to some products. The VEX profile uses
// category "impact" to carry the sentence explaining a not-affected verdict,
// which is OpenVEX's impact_statement under another name.
type Threat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// ThreatImpact is the threat category carrying an impact statement.
const ThreatImpact = "impact"

// Remediation is what to do about an affected product: OpenVEX's
// action_statement, with a category saying what kind of action it is.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// Score is one CVSS rating for the vulnerability, scoped to products.
type Score struct {
	CVSSV3     CVSSV3   `json:"cvss_v3"`
	ProductIDs []string `json:"products,omitempty"`
}

// CVSSV3 is the v3.0/v3.1 rating inside a score entry. Only the base score and
// the vector are read: internal/cvss scores v3 and nothing else, matching how
// every other advisory in this tool is rated.
type CVSSV3 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// Parse decodes a CSAF document, requiring a single well-formed JSON object and
// nothing after it.
//
// The strictness is deliberate and is carried over from the SUSE reader this
// replaced: a truncated response that decoded to a document with no
// vulnerabilities would be indistinguishable from a publisher who has nothing
// to say, and the two must never be confused -- one is a failure to read and
// the other is an answer.
func Parse(b []byte) (*Document, error) { return Decode(bytes.NewReader(b)) }

// Decode is Parse over a stream, for a caller holding an HTTP body it has no
// reason to buffer.
func Decode(r io.Reader) (*Document, error) {
	dec := json.NewDecoder(r)
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("csaf: parse document: %w", err)
	}
	// Anything at all after the object is a reason to refuse, including bytes
	// that are not even valid JSON: those are the shape a truncated or
	// concatenated response actually arrives in.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("csaf: parse document: unexpected trailing data")
		}
		return nil, fmt.Errorf("csaf: parse document: %w", err)
	}
	return &doc, nil
}

// Looks reports whether these bytes are a CSAF document rather than some other
// JSON.
//
// The test is document.csaf_version, which the format requires and no other VEX
// serialisation carries. Sniffing beats a command-line flag here: both formats
// are JSON, both say what they are, a hub is free to hold a mixture, and asking
// the operator to declare it would add nothing but a way to get it wrong.
func Looks(b []byte) bool {
	var probe struct {
		Document *struct {
			CSAFVersion string `json:"csaf_version"`
			Category    string `json:"category"`
		} `json:"document"`
	}
	if err := json.Unmarshal(b, &probe); err != nil || probe.Document == nil {
		return false
	}
	return probe.Document.CSAFVersion != "" || strings.HasPrefix(probe.Document.Category, "csaf_")
}

// Names is every name the vulnerability goes by: the CVE first, then each entry
// in its ids array, so a lookup keyed on any of them lands.
func (v Vulnerability) Names() []string {
	out := make([]string, 0, len(v.IDs)+1)
	add := func(s string) {
		if s = strings.TrimSpace(s); s == "" {
			return
		}
		for _, have := range out {
			if strings.EqualFold(have, s) {
				return
			}
		}
		out = append(out, s)
	}
	add(v.CVE)
	for _, id := range v.IDs {
		add(id.Text)
	}
	return out
}

// FlagFor is the justification label that applies to a product id, or "" when
// none does.
//
// A flag with no product_ids applies to every product of the vulnerability,
// which is CSAF's way of saying "the same reason for all of them" and has to be
// honoured -- a document written that way would otherwise read as having no
// justification at all.
func (v Vulnerability) FlagFor(productID string) string {
	for _, f := range v.Flags {
		if appliesTo(f.ProductIDs, productID) {
			return f.Label
		}
	}
	return ""
}

// ImpactFor is the impact threat's prose for a product id, or "" when none
// applies.
func (v Vulnerability) ImpactFor(productID string) string {
	for _, t := range v.Threats {
		if t.Category == ThreatImpact && appliesTo(t.ProductIDs, productID) {
			return t.Details
		}
	}
	return ""
}

// ActionFor is the remediation prose for a product id, or "" when none applies.
func (v Vulnerability) ActionFor(productID string) string {
	for _, r := range v.Remediations {
		if appliesTo(r.ProductIDs, productID) {
			return r.Details
		}
	}
	return ""
}

// Covers reports whether the vulnerability already states any verdict about a
// product id.
//
// Any verdict, not just an exculpatory one: a writer merging into a document
// uses this to decide whether the document has already spoken, and a vendor who
// called a product affected has spoken just as definitively as one who cleared
// it.
func (v Vulnerability) Covers(productID string) bool {
	for _, l := range v.ProductStatus.Statuses() {
		for _, id := range l.ProductIDs {
			if id == productID {
				return true
			}
		}
	}
	return false
}

// appliesTo reports whether a scoped list covers a product id. An empty list is
// document-wide scope, not an empty scope.
func appliesTo(ids []string, productID string) bool {
	if len(ids) == 0 {
		return true
	}
	for _, id := range ids {
		if id == productID {
			return true
		}
	}
	return false
}
