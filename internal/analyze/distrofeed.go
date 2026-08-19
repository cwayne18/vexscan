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

// distroScores fetches every provider's statements for the current findings and
// returns them without applying any verdict, together with the index that ties a
// statement's RefID back to its finding.
//
// It exists so --prefer-vendor can read a vendor's CVSS score before the
// severity filter runs, where distroOverlay -- which runs after it, for the
// precedence reasons on that function -- would be too late to change what the
// filter and the fail gate weigh. The two share a fetch: each provider caches
// the documents it reads, so distroOverlay's later pass costs no extra network.
//
// A provider that errors is logged and skipped, never fatal: a score that could
// not be read only leaves the OSV rating in place, which over-reports at worst
// and can never invent a clean.
func distroScores(ctx context.Context, providers []distrofeed.Provider, os *OSInfo, findings []Finding, ids map[string][]string, logf func(string, ...any)) ([]distrofeed.Statement, map[string]*Finding) {
	if len(providers) == 0 || os == nil || os.ID == "" {
		return nil, nil
	}
	refs, index := osFindings(findings, ids)
	if len(refs) == 0 {
		return nil, index
	}
	var out []distrofeed.Statement
	for _, p := range providers {
		if !p.Handles(os.ID) {
			continue
		}
		stmts, err := p.Lookup(ctx, distrofeed.Query{OSID: os.ID, Release: os.VersionID, CPE: os.CPEName, Packages: refs})
		if err != nil {
			logf("  ! distro feed %s: %v", p.Name(), err)
			logf("    (its OSV-derived rating stands for any score it could not read)")
		}
		out = append(out, stmts...)
	}
	return out, index
}

// preferVendorOverlay overrides a finding's severity with a preferred vendor's
// own CVSS score, in place, when --prefer-vendor named one that scored the
// finding's CVE.
//
// It is the one overlay that deliberately changes Severity and CVSS. The rule is
// that the vendor's score is authoritative: it wins even when it is lower than
// the OSV-derived rating, because "trust my distribution's rating of this CVE"
// is exactly what the flag asks for. When several preferred vendors scored the
// same finding, the earliest in the --prefer-vendor list wins, the same
// earliest-wins order --vexhub uses.
//
// It records what it did as evidence so the change is auditable, and never
// touches Status: the local verdict on whether the code is present stands.
func preferVendorOverlay(stmts []distrofeed.Statement, index map[string]*Finding, prefer []string, logf func(string, ...any)) {
	if len(stmts) == 0 || len(prefer) == 0 || len(index) == 0 {
		return
	}
	// pick is the winning vendor's score for one finding so far, kept so a
	// higher-priority vendor listed later in the statements can still displace a
	// lower-priority one seen first.
	type pick struct {
		rank   int
		vendor string
		vector string
		label  string
		was    string
	}
	best := map[*Finding]pick{}
	for _, st := range stmts {
		if st.CVSSVector == "" {
			continue
		}
		rank := vendorRank(st.Author, prefer)
		if rank < 0 {
			continue
		}
		f := index[st.RefID]
		if f == nil {
			continue
		}
		score, ok := cvss.Score(st.CVSSVector)
		if !ok {
			// A vector this tool cannot score is no better than no score: leave
			// the OSV rating rather than blank a finding on a vendor typo.
			continue
		}
		if cur, seen := best[f]; seen && cur.rank <= rank {
			continue
		}
		best[f] = pick{rank: rank, vendor: st.Author, vector: st.CVSSVector, label: cvss.Label(score), was: f.Severity}
	}
	var overridden int
	for f, p := range best {
		f.Severity = p.label
		f.CVSS = p.vector
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: OriginPreferVendor,
			Detail: preferDetail(p.vendor, p.label, p.was),
		})
		overridden++
	}
	if overridden > 0 {
		logf("prefer-vendor: %d finding(s) rated from a preferred vendor's own CVSS score", overridden)
	}
}

// vendorRank returns the position of the first --prefer-vendor entry that names
// the statement's author, or -1 for none. The match is a case-insensitive
// substring so a user types the vendor ("suse") rather than the feed's full
// author string ("SUSE Security Team").
func vendorRank(author string, prefer []string) int {
	a := strings.ToLower(author)
	for i, v := range prefer {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && strings.Contains(a, v) {
			return i
		}
	}
	return -1
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
