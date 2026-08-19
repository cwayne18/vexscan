// Package suse turns SUSE's CSAF-VEX feed into distrofeed statements.
//
// SUSE publishes one CSAF VEX document per CVE at a stable URL, so unlike
// Debian's one bulk file this provider fetches exactly the advisories the scan
// found and nothing else. Each document names, per product, which binary
// packages are affected, which are not, and which have a fix and at what version:
//
//	product_tree.branches:  product name  -> CPE   (the join key)
//	vulnerabilities[].product_status:
//	    known_not_affected:  "<product>:<pkg>"            not affected
//	    known_affected:      "<product>:<pkg>"            affected
//	    recommended:         "<product>:<pkg>-<version>"  fix shipped in <version>
//
// The join is by CPE, read from the image's own os-release CPE_NAME. A SUSE
// document lists dozens of products -- Server, Desktop, HPC, the SLE modules,
// SUSE Micro, several service packs -- and their verdicts differ, so matching the
// image's exact CPE to the one product it names is what keeps a Desktop
// not-affected off a Server image. When os-release carries no CPE, or the
// document names no product with it, the provider declines rather than pick a
// product, for the same reason the Debian provider declines an unmappable
// release: a verdict read off the wrong product is the false clean this tool must
// never emit.
//
// Two shapes clear a finding: a package in known_not_affected (SUSE did not build
// the vulnerable code into it), and a package in recommended whose fixed version
// the installed one has reached (compared by rpm's own rules). known_affected, a
// no-fix-planned remediation, and a fix newer than what is installed all stand.
package suse

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/rpmver"
)

// DefaultBaseURL is the directory of per-CVE CSAF-VEX documents. A document is
// DefaultBaseURL + "/cve-YYYY-NNNN.json". Point BaseURL at a mirror or an
// offline copy to reroute the whole feed, the same escape hatch the other
// providers offer.
const DefaultBaseURL = "https://ftp.suse.com/pub/projects/security/csaf-vex"

// author is recorded on every statement this provider emits.
const author = "SUSE Security Team"

// maxParallel bounds the concurrent per-CVE fetches so a findings list with many
// advisories does not open a connection per CVE all at once.
const maxParallel = 8

// Provider reads SUSE's CSAF-VEX feed.
type Provider struct {
	// HTTP is the client used to fetch documents; http.DefaultClient when nil.
	HTTP *http.Client
	// BaseURL is the CSAF-VEX directory; DefaultBaseURL when empty.
	BaseURL string

	// mu guards docs, the per-run cache of fetched documents. A single scan
	// looks a CVE up at most twice -- once before the severity filter to read
	// SUSE's score for --prefer-vendor, and once after to apply its verdict --
	// and caching the parsed document means the second pass costs no network.
	// A successful fetch is cached, including a 404 as a nil document; a
	// transient error is not, so it can be retried on the next pass.
	mu   sync.Mutex
	docs map[string]cachedDoc
}

// cachedDoc is one memoised fetch. adv is nil for a 404 (SUSE has no record),
// which is a real answer worth caching, not a miss.
type cachedDoc struct {
	adv *advisory
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

// Handles claims the SUSE Linux Enterprise family, the products the CSAF feed
// carries verdicts for. SLE BCI container images identify as "sles" with an
// sles CPE, so they are covered here too. openSUSE Leap and Tumbleweed track
// separately and are left to a future provider rather than answered for with SLE
// verdicts.
func (p *Provider) Handles(osID string) bool {
	switch strings.ToLower(strings.TrimSpace(osID)) {
	case "sles", "sled", "sles_sap", "sle_hpc", "sle-micro", "sle-micro-rt":
		return true
	}
	return false
}

var cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)

// Lookup fetches the CSAF document for each CVE the scan is carrying and returns
// the SUSE verdicts for the queried packages under the image's product.
func (p *Provider) Lookup(ctx context.Context, q distrofeed.Query) ([]distrofeed.Statement, error) {
	if q.CPE == "" {
		// No product to key on. A CPE-scoped feed cannot answer without risking
		// the wrong product's verdict, so it declines, exactly as the Debian
		// provider does for an unmappable release.
		return nil, nil
	}
	cves := uniqueCVEs(q.Packages)
	if len(cves) == 0 {
		return nil, nil
	}

	docs, err := p.fetchAll(ctx, cves)
	// docs holds every advisory that was read; err aggregates the ones that
	// could not be. Both are returned: the overlay applies the verdicts that
	// arrived and records the failures, because an unread advisory only leaves a
	// finding affected and never invents a clean.

	var out []distrofeed.Statement
	for _, pkg := range q.Packages {
		if st, ok := statementFor(pkg, q.CPE, docs); ok {
			out = append(out, st)
		}
	}
	return out, err
}

// statementFor decides one finding's verdict from whichever of its CVE ids SUSE
// has a document for. The ids are aliases of a single vulnerability, so any one
// of them speaking is the vendor's verdict for that finding. It fails closed: if
// any alias leaves the package affected, that stands and the finding is not
// cleared, even when another alias would clear it. Only when no alias says
// affected does an exculpatory verdict win.
func statementFor(pkg distrofeed.PkgRef, cpe string, docs map[string]*advisory) (distrofeed.Statement, bool) {
	var cleared distrofeed.Statement
	var haveCleared bool
	for _, id := range pkg.CVEs {
		doc := docs[strings.ToUpper(id)]
		if doc == nil {
			continue
		}
		status, fixed, why := doc.classify(cpe, strings.ToUpper(id), pkg)
		if status == "" {
			continue
		}
		st := distrofeed.Statement{
			RefID:         pkg.ID,
			Distro:        "suse",
			Package:       pkg.Name,
			CVE:           id,
			Status:        status,
			FixedVersion:  fixed,
			Justification: why,
			Source:        doc.url,
			Author:        author,
			CVSSVector:    doc.scores[strings.ToUpper(id)],
		}
		if !status.Exculpatory() {
			// An affected verdict from any alias vetoes a clear from another.
			return st, true
		}
		if !haveCleared {
			cleared, haveCleared = st, true
		}
	}
	return cleared, haveCleared
}

// advisory is one parsed CSAF-VEX document, reduced to what a verdict needs.
type advisory struct {
	url string
	// cpeToProducts maps a CPE to the product names that carry it, so the
	// image's CPE selects the products whose verdicts apply.
	cpeToProducts map[string][]string
	// per vulnerability id, the product-status sets.
	vulns map[string]*vulnStatus
	// scores maps a CVE id to the CVSS v3 vector SUSE published for it, when
	// the document carried one. SUSE rates a CVE once across all its products,
	// so a single vector per id is enough; it is read so --prefer-vendor can
	// favour SUSE's own rating over the OSV-derived one. Empty when the
	// document published no v3 vector.
	scores map[string]string
}

// vulnStatus is one CVE's product-status lists, indexed for lookup by
// (product, package).
type vulnStatus struct {
	// notAffected[product][pkg] and affected[product][pkg] hold bare package
	// names; fixed[product][pkg] holds the version the fix shipped in.
	notAffected map[string]map[string]bool
	affected    map[string]map[string]bool
	fixed       map[string]map[string]string
}

// classify returns this document's verdict for one package under the image's
// CPE for a given CVE. Within a product it checks not-affected first
// (version-independent), then an available fix (cleared only once the installed
// version has reached it), then plain affected. Across the products the CPE
// selected it fails closed: if any matched product leaves the package affected,
// that answer wins over another product's clear. The SUSE tree is denormalized
// so an image's CPE almost always selects exactly one product and there is no
// conflict, but should one CPE name several, an affected verdict must never be
// hidden by a not-affected sibling.
func (a *advisory) classify(cpe, cve string, pkg distrofeed.PkgRef) (status distrofeed.Status, fixed, why string) {
	products := a.cpeToProducts[cpe]
	if len(products) == 0 {
		return "", "", ""
	}
	vs := a.vulns[cve]
	if vs == nil {
		return "", "", ""
	}
	// SUSE keys its product-status lists by *binary* package name, so a finding
	// is matched on its binary name alone. The source name is deliberately not a
	// fallback: one SUSE source builds several binaries with opposite verdicts
	// -- libopenssl1_1 not affected while libopenssl1_0_0 is affected by the same
	// CVE -- so matching a source name against a binary list would clear the
	// wrong package. A finding with no binary name simply goes unmatched.
	name := pkg.Name
	if name == "" {
		return "", "", ""
	}

	var clearedStatus distrofeed.Status
	var clearedFixed, clearedWhy string
	for _, product := range products {
		st, fv, w := a.classifyProduct(vs, product, name, pkg.Version)
		switch st {
		case distrofeed.StatusAffected:
			// Fail closed: an affected verdict in any matched product ends the
			// search and stands, whatever another product says.
			return distrofeed.StatusAffected, fv, w
		case distrofeed.StatusNotAffected:
			// Not affected is version-independent and authoritative; prefer it
			// over a fixed clear from another product, but keep scanning in case
			// a later product says affected.
			clearedStatus, clearedFixed, clearedWhy = st, fv, w
		case distrofeed.StatusFixed:
			if clearedStatus != distrofeed.StatusNotAffected {
				clearedStatus, clearedFixed, clearedWhy = st, fv, w
			}
		}
	}
	return clearedStatus, clearedFixed, clearedWhy
}

// classifyProduct is one product's verdict for a package, with not-affected
// taking precedence over a fix, and a fix over plain affected. A fix is only a
// clear once the installed version has reached it; below the fix the package is
// affected. An affected package that also carries a fix appears in both lists,
// so the fix is consulted before the affected list.
func (a *advisory) classifyProduct(vs *vulnStatus, product, name, installed string) (distrofeed.Status, string, string) {
	if vs.notAffected[product][name] {
		return distrofeed.StatusNotAffected, "", "SUSE marks " + name + " not affected in " + product
	}
	if fv := vs.fixed[product][name]; fv != "" {
		if installed != "" && rpmver.CompareInstalledToFix(installed, fv) >= 0 {
			return distrofeed.StatusFixed, fv, "SUSE fixed " + name + " in " + fv
		}
		return distrofeed.StatusAffected, fv, "SUSE fix for " + name + " is " + fv + ", newer than what is installed"
	}
	if vs.affected[product][name] {
		return distrofeed.StatusAffected, "", "SUSE lists " + name + " as affected in " + product
	}
	return "", "", ""
}
