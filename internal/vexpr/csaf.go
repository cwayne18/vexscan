package vexpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/cwayne18/vexscan/internal/csaf"
)

// csafFileName is what a product's CSAF document is called in the hub.
//
// The VEX Repository spec fixes the index and the pkg/ tree but says nothing
// about the file at the end of a location -- locations are data, not
// convention, which is why the reader never assumes a name. Sitting next to
// scan.openvex.json under a name that says which format it is keeps a hub
// legible when it holds both.
const csafFileName = "scan.csaf.json"

// csafEncoder writes the CSAF 2.0 VEX serialisation.
type csafEncoder struct{}

func (csafEncoder) fileName() string { return csafFileName }

// merge folds the proposal's claims into a CSAF advisory.
//
// It amends only documents vexscan itself wrote, identified by the tracking id
// this package derives from the product. That restriction is the whole of the
// difference from the OpenVEX side, and it comes from what the format is: an
// OpenVEX document is a bag of statements anyone can append to, while a CSAF
// document is a published advisory with a version, a release date and a
// revision history. Adding a statement to somebody else's advisory means
// issuing a new version of it in their name -- claiming they said something
// they did not -- so a document with a tracking id that is not ours is left
// exactly as published and reported instead.
//
// The same reasoning is why the document is re-marshaled from the typed shape
// rather than byte-preserved the way the OpenVEX side preserves a vendor's
// file. There is no vendor field to lose: the only documents this ever rewrites
// are ones it wrote, and internal/csaf models everything it writes.
func (e csafEncoder) merge(raw []byte, prop ProductProposal, meta Meta) ([]byte, []string, error) {
	want, err := trackingID(prop.Product)
	if err != nil {
		return nil, nil, err
	}

	doc := newCSAFDoc(prop.Product, want, meta)
	lay := defaultLayout()
	existing := false
	if len(bytes.TrimSpace(raw)) > 0 {
		// The two refusals below are told apart by whether the bytes are JSON
		// at all, not by whether they parse as CSAF. A truncated CSAF document
		// fails the sniff exactly as an OpenVEX one does, and answering it with
		// "try --vex-format openvex" would send the operator after a flag that
		// cannot help them.
		switch {
		case csaf.Looks(raw):
			parsed, err := csaf.Parse(raw)
			if err != nil {
				return nil, nil, errUnreadable
			}
			if got := parsed.Document.Tracking.ID; got != want {
				return nil, nil, decline("it is advisory %s, published by somebody else; "+
					"amending it would issue a new version of their document in their name", got)
			}
			doc, lay, existing = parsed, detectLayout(raw), true
		case json.Valid(raw):
			return nil, nil, decline("the hub already publishes a non-CSAF document for this product; " +
				"a hub index points a product at one document, so re-run with --vex-format openvex")
		default:
			return nil, nil, errUnreadable
		}
	}

	added := addClaims(doc, prop, meta)
	if len(added) == 0 {
		return nil, nil, nil
	}
	if existing {
		if err := revise(doc, meta.Timestamp, len(added)); err != nil {
			return nil, nil, err
		}
	}

	compact, err := marshalNoEscape(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("vexpr: marshal CSAF document: %w", err)
	}
	out, err := lay.render(compact)
	if err != nil {
		return nil, nil, fmt.Errorf("vexpr: indent CSAF document: %w", err)
	}
	return out, added, nil
}

// newCSAFDoc is the advisory a product gets when the hub has none.
func newCSAFDoc(product, trackingID string, meta Meta) *csaf.Document {
	return &csaf.Document{
		Document: csaf.Meta{
			Category:    csaf.Category,
			CSAFVersion: csaf.Version,
			Publisher: csaf.Publisher{
				Category:  meta.publisherCategory(),
				Name:      meta.Author,
				Namespace: meta.PublisherNamespace,
			},
			Title: "Vulnerabilities ruled out in " + purlName(product),
			Tracking: csaf.Tracking{
				ID:                 trackingID,
				InitialReleaseDate: meta.Timestamp,
				CurrentReleaseDate: meta.Timestamp,
				RevisionHistory: []csaf.Revision{{
					Number:  "1",
					Date:    meta.Timestamp,
					Summary: "Initial release.",
				}},
				Status:  "final",
				Version: "1",
			},
		},
	}
}

// revise records that an existing advisory has changed.
//
// A CSAF document that gains a statement and keeps its version and release date
// is a document lying about itself: every consumer caching it by version would
// keep serving the old contents. So the version advances, the current release
// date moves, and the revision history says what happened.
func revise(doc *csaf.Document, timestamp string, added int) error {
	next, ok := nextVersion(doc.Document.Tracking.Version)
	if !ok {
		return decline("its tracking version %q is not a number this can advance; "+
			"a CSAF document that gains a statement must be re-versioned",
			doc.Document.Tracking.Version)
	}
	doc.Document.Tracking.Version = next
	doc.Document.Tracking.CurrentReleaseDate = timestamp
	doc.Document.Tracking.RevisionHistory = append(doc.Document.Tracking.RevisionHistory, csaf.Revision{
		Number:  next,
		Date:    timestamp,
		Summary: fmt.Sprintf("Recorded %d further vulnerability finding(s) ruled out by vexscan.", added),
	})
	return nil
}

// nextVersion advances an integer document version.
//
// CSAF allows either an integer or a semantic version, and only the integer
// form is advanced here because it is the only form this package ever writes.
// Refusing the other is the conservative half of the same rule that refuses
// somebody else's tracking id: a version scheme vexscan did not choose is one
// it should not be guessing the successor of.
func nextVersion(cur string) (string, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(cur))
	if err != nil || n < 0 {
		return "", false
	}
	return strconv.Itoa(n + 1), true
}

// addClaims folds a proposal's claims into a document's product tree and
// vulnerability entries, and returns the vulnerabilities actually added.
//
// A claim the document already answers changes nothing at all -- not the
// vulnerability entry, and not the product tree either. Allocating tree entries
// for a claim that turns out to be redundant would make a re-run of an
// unchanged scan produce a diff, which is the one thing this whole design is
// arranged to avoid.
func addClaims(doc *csaf.Document, prop ProductProposal, meta Meta) []string {
	tree := csafTree{doc: doc}
	var added []string
	for _, c := range prop.Claims {
		if c.Status != StatusNotAffected {
			// Nothing else is ever selected -- a ruled-out finding is the whole
			// of what this package publishes -- and writing an unmapped status
			// into a product_status member would be a guess.
			continue
		}
		// Both ids are derived from the purls alone, so coverage can be
		// answered before anything is allocated.
		relID := relationshipID(c.Subcomponent, c.Product)
		v := findVuln(doc, c)
		if v != nil && (v.Covers(relID) || v.Covers(c.Product)) {
			continue
		}
		if v == nil {
			doc.Vulnerabilities = append(doc.Vulnerabilities, newCSAFVuln(c))
			v = &doc.Vulnerabilities[len(doc.Vulnerabilities)-1]
		}

		container := tree.product(c.Product)
		target := container
		if c.Subcomponent != "" {
			target = tree.relationship(tree.product(c.Subcomponent), container)
		}
		v.ProductStatus.KnownNotAffected = append(v.ProductStatus.KnownNotAffected, target)
		addFlag(v, c.Justification, target)
		addThreat(v, c.Impact, target)
		added = append(added, c.Vuln)
	}
	return added
}

// csafTree adds products and relationships to a document's product tree,
// reusing the ids it already allocated.
//
// Every id is the purl it stands for, verbatim. CSAF places no constraint on
// the shape of a product id beyond uniqueness, so an opaque "CSAFPID-0001"
// buys nothing but a second thing to keep consistent, while a purl is unique by
// construction, self-describing in a diff, and lets a merge find the id a
// previous run allocated by looking rather than by remembering.
type csafTree struct{ doc *csaf.Document }

// product returns the id for an artifact or component purl, defining it if the
// tree does not carry it yet.
func (t csafTree) product(purl string) string {
	for _, p := range t.doc.ProductTree.FullProductNames {
		if p.ProductID == purl {
			return purl
		}
	}
	t.doc.ProductTree.FullProductNames = append(t.doc.ProductTree.FullProductNames, csaf.FullProduct{
		ProductID: purl,
		Name:      purlName(purl),
		Helper:    &csaf.Helper{PURL: purl},
	})
	return purl
}

// relationship returns the id standing for a component inside a container,
// defining it if the tree does not carry it yet.
func (t csafTree) relationship(component, container string) string {
	id := relationshipID(component, container)
	for _, r := range t.doc.ProductTree.Relationships {
		if r.FullProductName.ProductID == id {
			return id
		}
	}
	t.doc.ProductTree.Relationships = append(t.doc.ProductTree.Relationships, csaf.Relationship{
		Category: csaf.ComponentOf,
		FullProductName: csaf.FullProduct{
			ProductID: id,
			Name:      purlName(component) + " as a component of " + purlName(container),
		},
		ProductReference:          component,
		RelatesToProductReference: container,
	})
	return id
}

// relationshipID is the composite id for a component inside a container.
//
// "|" is the separator because it is not legal unencoded anywhere in a package
// URL, so the pair cannot collide with either of the two leaf ids or with any
// other pair.
func relationshipID(component, container string) string {
	if component == "" {
		return container
	}
	return component + "|" + container
}

// findVuln returns the document's entry for the vulnerability a claim is about,
// matching on any id either side knows it by, or nil when there is none.
func findVuln(doc *csaf.Document, c Claim) *csaf.Vulnerability {
	want := append([]string{c.Vuln}, c.Aliases...)
	for i := range doc.Vulnerabilities {
		for _, have := range doc.Vulnerabilities[i].Names() {
			for _, w := range want {
				if w != "" && strings.EqualFold(have, w) {
					return &doc.Vulnerabilities[i]
				}
			}
		}
	}
	return nil
}

// newCSAFVuln starts the entry for a vulnerability the document does not carry.
//
// The cve member takes a CVE and nothing else -- CSAF validates its format --
// so a finding known only as GO-2025-1234 or GHSA-xxxx goes entirely into ids,
// each paired with the database that issued it.
func newCSAFVuln(c Claim) csaf.Vulnerability {
	v := csaf.Vulnerability{ReleaseDate: c.Timestamp}
	for _, id := range append([]string{c.Vuln}, c.Aliases...) {
		if id == "" {
			continue
		}
		if v.CVE == "" && isCVE(id) {
			v.CVE = id
			continue
		}
		v.IDs = append(v.IDs, csaf.VulnID{SystemName: systemName(id), Text: id})
	}
	return v
}

// addFlag records the justification for a product id.
//
// Flags are reused by label rather than written one per product: a scan that
// rules out one CVE across forty components produces one flag naming forty
// products, which is both how the format is meant to be used and the difference
// between a readable diff and an unreadable one.
func addFlag(v *csaf.Vulnerability, label, productID string) {
	if label == "" {
		return
	}
	for i := range v.Flags {
		if v.Flags[i].Label != label {
			continue
		}
		if len(v.Flags[i].ProductIDs) == 0 {
			// An unscoped flag is document-wide scope, so it already covers
			// this product. Listing the product would narrow it to just this
			// one, quietly stripping the justification off every other.
			return
		}
		v.Flags[i].ProductIDs = append(v.Flags[i].ProductIDs, productID)
		return
	}
	v.Flags = append(v.Flags, csaf.Flag{Label: label, ProductIDs: []string{productID}})
}

// addThreat records the impact statement for a product id, grouping products
// that share the same sentence for the same reason flags are grouped.
func addThreat(v *csaf.Vulnerability, details, productID string) {
	if details == "" {
		return
	}
	for i := range v.Threats {
		if v.Threats[i].Category != csaf.ThreatImpact || v.Threats[i].Details != details {
			continue
		}
		if len(v.Threats[i].ProductIDs) == 0 {
			return
		}
		v.Threats[i].ProductIDs = append(v.Threats[i].ProductIDs, productID)
		return
	}
	v.Threats = append(v.Threats, csaf.Threat{
		Category:   csaf.ThreatImpact,
		Details:    details,
		ProductIDs: []string{productID},
	})
}

// trackingID is the document id vexscan files a product's advisory under.
//
// It is derived from the product rather than generated, and that is the point:
// the tracking id is how a later run recognises the document as its own, and
// how it knows a document at the same location is not. A random or
// timestamped id would make every run publish a new advisory alongside the last
// one.
func trackingID(product string) (string, error) {
	typ, name, err := productParts(product)
	if err != nil {
		return "", err
	}
	return "VEXSCAN-" + strings.ToUpper(typ) + "-" + trackingSlug(name), nil
}

// trackingSlug reduces a product name to the characters a tracking id carries.
func trackingSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// purlName is a human-readable name for a purl, for the CSAF name member, which
// is mandatory and is prose rather than an identifier.
func purlName(purl string) string {
	typ, body, ok := splitPurl(purl)
	if !ok {
		return purl
	}
	if typ == "oci" {
		if repo := repositoryURL(body); repo != "" {
			return repo
		}
	}
	name, _ := splitQualifiers(body)
	if name == "" {
		return purl
	}
	// A purl percent-encodes the separators inside a namespace, so the raw form
	// reads as "golang.org%2Fx%2Fmod@v0.38.0". That is the right thing to keep in
	// product_id, which is an identifier and has to match byte for byte across
	// re-runs, and the wrong thing to put in name, which is the string a person
	// reviewing the advisory reads.
	if decoded, err := url.PathUnescape(name); err == nil {
		return decoded
	}
	return name
}

// isCVE reports whether an id is a CVE, which is the only thing the cve member
// accepts.
func isCVE(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") }

// systemName names the database that issued an id.
//
// CSAF requires it alongside the id itself, and unlike an OpenVEX alias list --
// which is a bare array of strings -- there is no way to write the id without
// saying where it came from. The prefixes below are the issuers vexscan's own
// sources use; anything else is "Other", which is what the format's own
// examples use for an id whose issuer is not one of the well-known ones.
func systemName(id string) string {
	up := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(up, "CVE-"):
		return "Common Vulnerabilities and Exposures"
	case strings.HasPrefix(up, "GHSA-"):
		return "GitHub Security Advisory"
	case strings.HasPrefix(up, "GO-"):
		return "Go Vulnerability Database"
	case strings.HasPrefix(up, "OSV-"):
		return "Open Source Vulnerabilities"
	case strings.HasPrefix(up, "RHSA-"), strings.HasPrefix(up, "RHBA-"), strings.HasPrefix(up, "RHEA-"):
		return "Red Hat Errata"
	case strings.HasPrefix(up, "SUSE-"), strings.HasPrefix(up, "OPENSUSE-"):
		return "SUSE Update Advisory"
	case strings.HasPrefix(up, "DSA-"), strings.HasPrefix(up, "DLA-"):
		return "Debian Security Advisory"
	case strings.HasPrefix(up, "USN-"):
		return "Ubuntu Security Notice"
	case strings.HasPrefix(up, "ALAS"):
		return "Amazon Linux Security Advisory"
	case strings.HasPrefix(up, "PYSEC-"):
		return "Python Packaging Advisory Database"
	case strings.HasPrefix(up, "RUSTSEC-"):
		return "RustSec Advisory Database"
	default:
		return "Other"
	}
}

// checkCSAFMeta rejects a run that cannot produce a valid CSAF document.
//
// The namespace has no default for the same reason the author does not: it is
// the URI that says who is answerable for the advisory, and inventing one would
// publish a claim in a name nobody chose.
func checkCSAFMeta(m Meta) error {
	if m.PublisherNamespace == "" {
		return fmt.Errorf("vexpr: CSAF needs a publisher namespace to identify who is asserting the statements")
	}
	if c := m.PublisherCategory; c != "" && !csaf.ValidPublisherCategory(c) {
		return fmt.Errorf("vexpr: %q is not a CSAF publisher category; want one of %s",
			c, strings.Join(csaf.PublisherCategories, ", "))
	}
	return nil
}
