package analyze

import (
	"context"
	"strconv"
	"strings"

	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// OriginDistroFeed is the evidence origin on a statement a distribution's own
// security feed contributed. It is a sibling of "vendor-vex": both are a
// vendor's published second opinion, recorded and never allowed to set a status.
const OriginDistroFeed = "distro-feed"

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
func distroOverlay(ctx context.Context, providers []distrofeed.Provider, os *OSInfo, findings []Finding, aliases map[string][]string, logf func(string, ...any)) []ecosystem.DistroFeedResult {
	if len(providers) == 0 || os == nil || os.ID == "" {
		return nil
	}
	refs, index := osFindings(findings, aliases)
	if len(refs) == 0 {
		return nil
	}

	var out []ecosystem.DistroFeedResult
	for _, p := range providers {
		if !p.Handles(os.ID) {
			continue
		}
		res := ecosystem.DistroFeedResult{Name: p.Name()}
		stmts, err := p.Lookup(ctx, distrofeed.Query{OSID: os.ID, Release: os.VersionID, Packages: refs})
		if err != nil {
			res.Error = err.Error()
			logf("  ! distro feed %s could not be read: %v", p.Name(), err)
			logf("    (OS-package false positives it would have cleared are still reported as affected)")
			out = append(out, res)
			continue
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
func osFindings(findings []Finding, aliases map[string][]string) ([]distrofeed.PkgRef, map[string]*Finding) {
	index := map[string]*Finding{}
	var refs []distrofeed.PkgRef
	for i := range findings {
		f := &findings[i]
		if !isOSPackage(*f) {
			continue
		}
		ids := findingIDs(*f, aliases)
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
