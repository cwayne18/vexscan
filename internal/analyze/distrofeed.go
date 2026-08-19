package analyze

import (
	"context"
	"strconv"
	"strings"

	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// OriginDistroFeed is the evidence origin on a statement a distribution's own
// security feed contributed. It is a sibling of "vendor-vex": both are a
// vendor's published second opinion, recorded and never allowed to set a status.
const OriginDistroFeed = "distro-feed"

// OriginPreferVendor is the evidence origin recorded when --prefer-vendor
// replaces a finding's rating with a vendor's own CVSS score. Unlike the other
// origins this one marks a change to Severity/CVSS, so it exists to leave an
// audit trail of which vendor's score won and what it displaced.
const OriginPreferVendor = "prefer-vendor"

// distroOverlay annotates OS-package findings with a distribution's own security
// feed, in place, and reports what each feed contributed.
//
// It is the vexOverlay of distro feeds and shares its contract exactly. It never
// touches Status: a finding's verdict is what the local closure concluded, and a
// feed can only add a vendor's reason to relax attention, never a clean the scan
// did not reach. It runs after vexOverlay, so a finding a user's --vexhub has
// already spoken to keeps that statement -- an explicit hub outranks an
// automatic feed, the same first-writer-wins rule --vexhub uses among itself.
//
// A feed that cannot be read is recorded and warned about but does not fail the
// run, for the reason spelled out on vexOverlay: an unreadable feed only leaves
// rows in AFFECTED that a vendor might have cleared, which over-reports, and this
// tool's one unforgivable direction is under-reporting.
//
// ids must be the wide set -- advisoryResolver.cveSets().All, which folds in
// each record's Upstream -- and not aliases(). Every distro feed is keyed by
// CVE, and no distro advisory in OSV carries a CVE in its own id or its
// aliases: a Debian finding is DEBIAN-CVE-2026-54369 and a SUSE one is
// SUSE-SU-2026:0885-1, with the CVEs they fix in upstream. Handed the narrow
// set, every provider here matches nothing at all and the feature is a silent
// no-op -- silent because a feed that matches nothing looks exactly like a feed
// with nothing to say. See cveSets for why upstream is kept out of aliases.
func distroOverlay(ctx context.Context, providers []distrofeed.Provider, os *OSInfo, findings []Finding, ids map[string][]string, logf func(string, ...any)) []ecosystem.DistroFeedResult {
	if len(providers) == 0 || os == nil || os.ID == "" {
		return nil
	}
	refs, index := osFindings(findings, ids)
	if len(refs) == 0 {
		return nil
	}

	var out []ecosystem.DistroFeedResult
	for _, p := range providers {
		if !p.Handles(os.ID) {
			continue
		}
		res := ecosystem.DistroFeedResult{Name: p.Name()}
		stmts, err := p.Lookup(ctx, distrofeed.Query{OSID: os.ID, Release: os.VersionID, CPE: os.CPEName, Packages: refs})
		if err != nil {
			// An error is recorded and warned about but never discards the
			// statements that did come back. A bulk-file feed like Debian
			// returns no statements on failure, so this applies nothing extra;
			// a per-CVE feed like SUSE can fetch most advisories and fail one,
			// and the ones it read are still a valid second opinion. This is
			// safe because a finding's several ids are aliases of one
			// vulnerability and a clear is only recorded from an advisory that
			// was actually read: an unread advisory leaves its finding in
			// AFFECTED and can never, by its absence, invent a clean.
			res.Error = err.Error()
			logf("  ! distro feed %s: %v", p.Name(), err)
			logf("    (any OS-package false positive it could not read is still reported as affected)")
		}
		for _, st := range stmts {
			matched, cleared := applyStatement(index, st)
			res.Matched += matched
			res.Cleared += cleared
		}
		if res.Cleared > 0 {
			logf("distro feed %s: cleared %d OS finding(s) a vendor ruled out", p.Name(), res.Cleared)
		}
		out = append(out, res)
	}
	return out
}

// applyStatement attaches one feed statement to the single finding it was
// computed for.
//
// The statement is bound to its finding by RefID, the opaque token the overlay
// stamped on the PkgRef it sent and the provider echoed back. Matching on that
// identity -- not on (package, CVE) -- is what keeps a version-specific verdict
// on the version it was decided against: one source package fans out into
// several binary packages under the same advisory, at versions that differ, so a
// "fixed" verdict for the newer binary must never land on an older one that is
// still vulnerable. RefID makes that impossible.
//
// Only an exculpatory statement clears: the feature exists to clear false
// positives, and stamping a vendor's "still affected" on a row the local scan
// already flagged would add noise without changing the answer. A finding that a
// higher-precedence statement already claimed is left alone. Matched counts
// every statement that reached a real finding; Cleared only the ones that
// actually relaxed it.
func applyStatement(index map[string]*Finding, st distrofeed.Statement) (matched, cleared int) {
	f := index[st.RefID]
	if f == nil {
		return 0, 0
	}
	matched = 1
	if !st.Status.Exculpatory() {
		return matched, 0
	}
	if f.VEX != nil {
		return matched, 0
	}
	f.VEX = &ecosystem.VEXStatement{
		Status:        string(st.Status),
		Justification: st.Justification,
		Author:        st.Author,
		Product:       st.Package,
		Hub:           st.Source,
	}
	f.Evidence = append(f.Evidence, ecosystem.Evidence{
		Origin: OriginDistroFeed,
		Detail: distroDetail(st),
		// Never blocking, exactly like vendor-vex: a feed is a second
		// opinion, not a taint, and cannot stop the local analysis from
		// reaching its own verdict in either direction.
	})
	return matched, 1
}

// distroDetail is the one-line evidence summary of a feed statement.
func distroDetail(st distrofeed.Statement) string {
	var b strings.Builder
	b.WriteString(st.Author)
	b.WriteString(" published ")
	b.WriteString(string(st.Status))
	b.WriteString(" for ")
	b.WriteString(st.Package)
	if st.CVE != "" {
		b.WriteString(" (")
		b.WriteString(st.CVE)
		b.WriteString(")")
	}
	if st.Justification != "" {
		b.WriteString(": ")
		b.WriteString(st.Justification)
	}
	return b.String()
}

// osFindings collects the OS-package findings a feed can speak to, returning the
// PkgRefs to ask about and an index from each ref's opaque ID to its finding.
//
// Each finding gets a unique ID, stamped on its PkgRef and echoed back on any
// Statement the provider derives from it, so a verdict is applied to exactly the
// finding -- and the version -- it was computed against, never a sibling package
// that happens to share a source name and advisory.
func osFindings(findings []Finding, idSets map[string][]string) ([]distrofeed.PkgRef, map[string]*Finding) {
	index := map[string]*Finding{}
	var refs []distrofeed.PkgRef
	for i := range findings {
		f := &findings[i]
		if !isOSPackage(*f) {
			continue
		}
		ids := findingIDs(*f, idSets)
		id := strconv.Itoa(i)
		refs = append(refs, distrofeed.PkgRef{
			ID:      id,
			Source:  f.Package,
			Name:    f.Component(),
			Version: f.Version,
			CVEs:    ids,
		})
		index[id] = f
	}
	return refs, index
}

// isOSPackage reports whether a finding came from the OS plugin, the only
// findings a distro feed is about.
func isOSPackage(f Finding) bool {
	return f.Ecosystem == "os"
}

// preferVendorScores overrides each finding's Severity and CVSS with a preferred
// vendor's own score, in place, wherever --prefer-vendor named a vendor that
// scored one of the finding's CVEs.
//
// Unlike distroOverlay this is CVE-keyed, not product-keyed, and that is the
// whole point of the redesign: a vendor rates a CVE once, and that rating is as
// true of a Go module or an npm package that bundles the flaw as of an OS
// package, so this speaks to a finding in *any* ecosystem. It needs no
// os-release, no CPE and no package join -- it asks each scorer for the CVEs the
// findings are about and applies what comes back. A finding reported under a
// GO-2026-xxxx id is reached through the advisory alias set (findingCVEs), which
// resolves it to the CVE the vendor feed is actually keyed by.
//
// It is the one overlay that deliberately changes Severity and CVSS. The rule is
// that the vendor's score is authoritative: it wins even when it is lower than
// the OSV-derived rating, because "trust this vendor's rating of this CVE" is
// exactly what the flag asks for. The scorers are consulted in --prefer-vendor
// priority order and the first that scored a finding wins, the same
// earliest-wins order --vexhub uses. It records what it did as evidence so the
// change is auditable, and never touches Status: the local verdict on whether
// the code is present stands.
//
// A scorer that errors is logged and skipped, never fatal: a score that could
// not be read only leaves the OSV rating in place, which over-reports at worst
// and can never invent a clean.
func preferVendorScores(ctx context.Context, scorers []distrofeed.Scorer, findings []Finding, ids map[string][]string, logf func(string, ...any)) {
	if len(scorers) == 0 || len(findings) == 0 {
		return
	}

	// The CVEs each finding is about, resolved through the alias set so a
	// GO/GHSA-named finding still yields the CVE a vendor feed is keyed by, and
	// their union to ask every scorer about in one batch.
	perFinding := make([][]string, len(findings))
	seen := map[string]bool{}
	var query []string
	for i := range findings {
		cves := findingCVEs(findings[i], ids)
		perFinding[i] = cves
		for _, cve := range cves {
			if !seen[cve] {
				seen[cve] = true
				query = append(query, cve)
			}
		}
	}
	if len(query) == 0 {
		return
	}

	// Fetch each vendor's scores once, in priority order. A vendor's map is
	// keyed by uppercase CVE.
	type vendorScores struct {
		name   string
		scores map[string]string
	}
	fetched := make([]vendorScores, 0, len(scorers))
	for _, s := range scorers {
		scores, err := s.Scores(ctx, query)
		if err != nil {
			logf("  ! prefer-vendor %s: %v", s.Name(), err)
			logf("    (its OSV-derived rating stands for any score it could not read)")
		}
		if len(scores) > 0 {
			fetched = append(fetched, vendorScores{name: s.Name(), scores: scores})
		}
	}

	var overridden int
	for i := range findings {
		f := &findings[i]
		for _, v := range fetched {
			vec, label, ok := bestVendorVector(v.scores, perFinding[i])
			if !ok {
				continue
			}
			f.Evidence = append(f.Evidence, ecosystem.Evidence{
				Origin: OriginPreferVendor,
				Detail: preferDetail(v.name, label, f.Severity),
			})
			f.Severity = label
			f.CVSS = vec
			overridden++
			// Earliest-listed vendor wins: stop at the first that scored it.
			break
		}
	}
	if overridden > 0 {
		logf("prefer-vendor: %d finding(s) rated from a preferred vendor's own CVSS score", overridden)
	}
}

// bestVendorVector returns the vendor's CVSS vector and label for a finding,
// choosing the highest-scoring one among the finding's CVEs.
//
// A finding usually has one CVE, but a bundle addresses several, and a vendor may
// have scored more than one of them. Taking the most severe is the same
// fail-towards-severe rule the rest of the tool uses when one row relates to
// several ratings: the vendor's opinion is preferred, but among the vendor's own
// numbers for this row the worst is the safe one. A vector the tool cannot score
// is treated as no score -- the OSV rating stands rather than a finding being
// blanked on a vendor typo.
func bestVendorVector(scores map[string]string, cves []string) (vector, label string, ok bool) {
	best := -1.0
	for _, cve := range cves {
		vec := scores[strings.ToUpper(cve)]
		if vec == "" {
			continue
		}
		score, valid := cvss.Score(vec)
		if !valid {
			continue
		}
		if score > best {
			best, vector, label, ok = score, vec, cvss.Label(score), true
		}
	}
	return vector, label, ok
}

// preferDetail is the one-line evidence summary of a prefer-vendor override,
// naming the vendor, the rating used, and the OSV rating it displaced when they
// differ.
func preferDetail(vendor, label, was string) string {
	var b strings.Builder
	b.WriteString(vendor)
	b.WriteString(" rates this ")
	b.WriteString(label)
	if was != "" && !strings.EqualFold(was, label) {
		b.WriteString(", used instead of ")
		b.WriteString(was)
	}
	b.WriteString(" (preferred vendor score)")
	return b.String()
}
