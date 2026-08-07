package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/ecosystem/ospkg"
)

// The text report.
//
// The shape is a table rather than a block per finding because of what a real
// scan produces: debian:12 --all is 159 findings, which as blocks was 647 lines
// nobody reads to the end of. The per-finding detail is not gone, it moved
// behind --details.
//
// Plain aligned columns, not box drawing. These reports are pasted into gists,
// CI logs and terminals of every width, and are grepped and cut. A row that
// survives all of that is worth more than one that looks better in a
// screenshot.
//
// Colour is the one exception, and is held to the same rule: it is carried in a
// palette that is empty unless a human is watching (color.go), it is never the
// only thing saying something, and stripping the escapes from a coloured report
// reproduces the uncoloured one byte for byte. A file, a gist and a pipe get the
// empty palette, so the bytes that get diffed and grepped are unchanged --
// including the footer below, whose threshold is counted in the report's own
// lines and never in the terminal's height.

// renderOpts is how a report is rendered, as opposed to what is in it.
//
// One struct rather than two parameters because the palette has to reach the
// same writers --details does, and threading a second argument through sixteen
// of them makes every one of their signatures a list. The zero value is the
// plain, uncoloured, summary-only report, which is what the tests want and what
// a pipe gets.
type renderOpts struct {
	details bool
	pal     palette
}

// renderText renders a scan result for humans.
func renderText(res *analyze.Result, o renderOpts) string {
	var b strings.Builder
	writeHeader(&b, res, o.pal)

	if len(res.Findings) == 0 {
		writeNoFindings(&b, res)
		return b.String()
	}

	writeSummary(&b, res, false)
	for _, s := range sections(res) {
		writeSection(&b, s, o)
	}

	// Long enough that the header is gone: say it all again. Measured on the
	// report rather than on the terminal, so a file, a gist and a paged
	// terminal all get the same bytes.
	if strings.Count(b.String(), "\n") > footerThreshold {
		writeFooter(&b, res, o.pal)
	}
	return b.String()
}

// writeNoFindings explains an empty report. Three ways to be empty, and only
// one of them is good news: nothing was wrong; nothing was read; or something
// was found and the reader's own filter hid all of it. Shared by every
// human-readable format so an empty --format fixplan cannot claim a clean
// result that --format text would have called incomplete.
func writeNoFindings(b *strings.Builder, res *analyze.Result) {
	switch {
	case res.Failed():
		b.WriteString("No findings, but the scan was incomplete: see above.\n")
		b.WriteString("This is not a clean result.\n")
	case res.Withheld != nil:
		// The --repo case: govulncheck publishes no severity, so every Go
		// finding is UNKNOWN and a --severity that does not name UNKNOWN
		// empties the report. Printing the bare "no findings" line there
		// would be this tool telling its worst available lie.
		b.WriteString("No findings at these severities.\n")
		fmt.Fprintf(b, "--severity %s withheld all %d finding(s): %s.\n",
			strings.Join(res.Withheld.Severities, ","), res.Withheld.Count,
			withheldSpread(res.Withheld))
		b.WriteString("This is a filtered view, not a clean result.\n")
	default:
		b.WriteString("No findings: nothing selected was found in this target,\n")
		b.WriteString("or no matching advisories were published for it.\n")
	}
}

// writeHeader prints what was scanned, and anything that makes the answer
// incomplete.
//
// The INCOMPLETE banners come before everything else and are unconditional.
// They are the guarantee that a scan which could not read part of the target
// never renders as a clean one, and no amount of table formatting below is
// allowed to push them out of sight. That last promise is why writeFooter
// exists: at 172 lines, the table below pushes them out of sight anyway.
func writeHeader(b *strings.Builder, res *analyze.Result, pal palette) {
	fmt.Fprintf(b, "vexscan report (%s) for %s\n", res.Mode, res.Target)
	if res.Module != "" {
		fmt.Fprintf(b, "module: %s\n", res.Module)
	}
	writeProvenance(b, res.Descriptor)
	writeCaveats(b, res, pal)
	b.WriteString("\n")
}

// writeProvenance names the build that ran and the advisories it read.
//
// One line, in the header and deliberately not in the footer: it is not a
// caveat, and repeating it would put it beside the INCOMPLETE banners that are
// repeated because they matter. It is here at all because a saved report is
// read long after the run, and an empty one raises exactly two questions --
// which build produced it, and how old the advisories behind it are.
func writeProvenance(b *strings.Builder, d *analyze.Descriptor) {
	if d == nil {
		return
	}
	parts := make([]string, 0, 3)
	if d.Version != "" {
		name := d.Tool
		if name == "" {
			name = "vexscan"
		}
		parts = append(parts, name+" "+d.Version)
	}
	if !d.Started.IsZero() {
		when := d.Started.UTC().Format("2006-01-02 15:04 MST")
		if d.Duration != "" {
			when += ", " + d.Duration
		}
		parts = append(parts, when)
	}
	if !d.AdvisoriesAsOf.IsZero() && d.AdvisorySource != "" {
		parts = append(parts, "advisories from "+d.AdvisorySource)
	}
	if len(parts) == 0 {
		return
	}
	fmt.Fprintf(b, "scanned by: %s\n", strings.Join(parts, " -- "))
}

// writeCaveats writes everything that changes how the rows should be read: the
// INCOMPLETE banners, what --severity withheld, and a VEX hub that could not be
// reached.
//
// Split out of writeHeader so the footer can repeat it verbatim. A caveat that
// appeared at one end of a long report and not the other would be worse than
// one printed twice.
func writeCaveats(dst *strings.Builder, res *analyze.Result, pal palette) {
	// Rendered into a sub-builder so palette.banners can bold every caveat
	// prefix in one pass; see its comment for why that beats ten call sites.
	b := &strings.Builder{}
	defer func() { dst.WriteString(pal.banners(b.String())) }()

	for _, e := range res.Ecosystems {
		if e.Error != "" {
			fmt.Fprintf(b, "INCOMPLETE: ecosystem %s did not run - %s\n", e.ID, e.Error)
		}
	}
	if u := res.Unreadable; u != nil && u.Any() {
		// The paths are named because the usual cause is scanning a root-owned
		// tree as someone else, and the fix -- re-run it as root -- is only
		// obvious once you can see what was missed.
		fmt.Fprintf(b, "INCOMPLETE: %d path(s) could not be read, so this report does not account for them:\n", u.Count)
		for _, p := range u.Paths {
			fmt.Fprintf(b, "  %s\n", p)
		}
		if u.Count > len(u.Paths) {
			fmt.Fprintf(b, "  ... and %d more\n", u.Count-len(u.Paths))
		}
	}
	if w := res.Withheld; w != nil && len(res.Findings) > 0 {
		// Above the VEX notes, because this one changes which rows exist at all
		// while those only change how the rows are grouped. Not an INCOMPLETE
		// banner: the scan read everything it meant to and the reader asked for
		// the subset. But loud, because a filtered report and a clean one are
		// otherwise the same document.
		//
		// Skipped when nothing survived, where renderText says the same thing at
		// more length and the two together read as a stutter.
		fmt.Fprintf(b, "NOTE: --severity %s withheld %d of %d findings:\n",
			strings.Join(w.Severities, ","), w.Count, w.Count+len(res.Findings))
		fmt.Fprintf(b, "      %s\n", withheldSpread(w))
	}
	writeCorrectionsCaveat(b, res)
	for _, h := range res.VEXHubs {
		if h.Error == "" {
			continue
		}
		// Not an INCOMPLETE banner, and deliberately not: the scan itself is
		// complete. What was lost is the grouping, so findings the vendor had
		// already answered are still sitting in AFFECTED. Saying so is still
		// necessary -- a hub that contributed nothing because it could not be
		// reached looks exactly like one with nothing to say.
		fmt.Fprintf(b, "NOTE: VEX hub %s could not be read, so nothing was moved to ALREADY VEXED - %s\n", h.URL, h.Error)
	}
	writeMetadataCaveat(b, res)
	writeGovulncheckCaveat(b, res)
	writeTriageCaveats(b, res)
}

// writeGovulncheckCaveat warns that the Go reachability test was skipped because
// govulncheck was not on PATH.
//
// A NOTE and not an INCOMPLETE banner: the scan read everything and every status
// is sound. What is lost is precision -- a linked, package-granularity Go
// finding on a binary that kept its symbols is exactly the shape govulncheck can
// rule not_in_execute_path, and without the binary those findings stay linked
// for want of the test. The finding carries the reason as evidence; this counts
// them so the reader learns the one install that would sharpen the report.
func writeGovulncheckCaveat(b *strings.Builder, res *analyze.Result) {
	n := 0
	for _, f := range res.Findings {
		for _, e := range f.Evidence {
			if e.Origin == ecosystem.OriginGovulncheckUnavailable {
				n++
				break
			}
		}
	}
	if n == 0 {
		return
	}
	fmt.Fprintf(b, "NOTE: govulncheck was not found, so %d linked Go finding(s) could not be\n", n)
	b.WriteString("      tested for reachability. Install govulncheck and re-run to let any whose\n")
	b.WriteString("      vulnerable code is unreachable be ruled not_in_execute_path:\n")
	b.WriteString("      go install golang.org/x/vuln/cmd/govulncheck@latest\n")
}

// writeCorrectionsCaveat names the advisories the database matched and this
// scan did not report.
//
// Every other caveat here exists because something was lost. This one exists
// because something was *removed*, on purpose, by this tool -- which is the one
// thing it must never do quietly. On rancher:v2.15.0 it is 27 findings, and
// without this the report is indistinguishable from an image the database
// simply has nothing to say about.
//
// So it prints the ids, not just a count. The claim being made is checkable --
// each of these is one `osv.dev/vulnerability/<id>` away from the ranges quoted
// -- and a reader who thinks the drop is wrong needs to be able to go and look.
// Unlike the withheld note it prints even when no findings survived, because
// that is precisely the case where the reader most needs to know.
func writeCorrectionsCaveat(b *strings.Builder, res *analyze.Result) {
	c := res.Corrections
	if c == nil || c.Count == 0 {
		return
	}
	fmt.Fprintf(b, "NOTE: %d advisory match(es) were not reported. The advisory record itself\n", c.Count)
	b.WriteString("      carries precise affected ranges that exclude the version installed,\n")
	b.WriteString("      while the range OSV matched on was left open because the database\n")
	b.WriteString("      could not express those versions. Nothing else disagreed:\n")
	// Capped, and the remainder counted rather than dropped: the caveat sits
	// above the findings, and a hundred lines of it would bury the report it is
	// annotating. The JSON carries all of them.
	const shown = 20
	for i, d := range c.Details {
		if i == shown {
			fmt.Fprintf(b, "      ... and %d more (see corrections in --format json)\n", len(c.Details)-shown)
			break
		}
		fmt.Fprintf(b, "      %s\n", d)
	}
}

// writeMetadataCaveat says that --rpm or --sbom described the packages rather
// than a system holding them.
//
// It is a NOTE and not an INCOMPLETE banner: nothing failed, and the scan read
// everything there was to read. What it changes is what the rows are allowed to
// mean -- an undetermined row here is not one the tool gave up on, it is one
// the input cannot answer. Without this the report is indistinguishable from an
// image scan that could not close over anything.
//
// Both modes, with different wording, because they lose different amounts. An
// rpm header still lists the files the package installs, so --rpm can rule a
// package out for shipping no code; a CycloneDX component lists nothing, so
// --sbom cannot rule anything out at all. Saying the same sentence over both
// would overstate the weaker one.
func writeMetadataCaveat(b *strings.Builder, res *analyze.Result) {
	if res.Mode != "rpm" && res.Mode != "sbom" {
		return
	}
	undetermined, noCode := 0, 0
	for _, f := range res.Findings {
		switch {
		case f.Reason == ospkg.ReasonNoReachabilityTest:
			undetermined++
		case f.Status == analyze.StatusNotPresent && f.Method == ospkg.MethodNoCode:
			noCode++
		}
	}
	// The opening lines are unconditional. They are worth printing even with no
	// findings at all to explain: "No findings" out of a document is a weaker
	// statement than the same words out of an image, and this is the whole of
	// the difference.
	if res.Mode == "sbom" {
		b.WriteString("NOTE: this read a bill of materials, not an installed system. No ELF\n")
		b.WriteString("      reachability test could run -- there is no filesystem to trace -- and a\n")
		b.WriteString("      CycloneDX component does not list the files it installs, so unlike a\n")
		b.WriteString("      package file it cannot rule a package out for shipping no code either.\n")
		b.WriteString("      Every row below is a package the document says is installed, and\n")
		b.WriteString("      nothing here can say whether its code would ever run.\n")
	} else {
		b.WriteString("NOTE: this read package metadata, not an installed system. No ELF\n")
		b.WriteString("      reachability test could run -- there is no filesystem to trace.\n")
	}

	if undetermined > 0 {
		if res.Mode == "sbom" {
			fmt.Fprintf(b, "      %d finding(s) below are undetermined for that reason. Scan the image\n", undetermined)
			b.WriteString("      or tree these components came from to get an answer.\n")
		} else {
			fmt.Fprintf(b, "      %d finding(s) below are undetermined for that reason. For scale: on a\n", undetermined)
			// The reference measurement is here because the obvious next
			// question is what the missing test would have been worth, and the
			// honest answer on the distribution this was built against is:
			// about one finding.
			b.WriteString("      measured SUSE 15.6 image that test ruled out 1 finding of 47.\n")
		}
	}
	if noCode > 0 {
		fmt.Fprintf(b, "      %d finding(s) below are ruled out on the header alone, which is the\n", noCode)
		b.WriteString("      same evidence an installed scan would have used: the package ships no\n")
		b.WriteString("      ELF object at all.\n")
	}
}

// writeTriageCaveats explains anything --triage could not do.
//
// Three things can go wrong and they are not interchangeable. A feed that could
// not be read at all means the rows below are in their old order. A feed served
// from yesterday's cache means the percentiles are yesterday's. And a finding
// that could not be looked up sorts to the bottom, which in a list ordered by
// exploitation probability reads exactly like "least urgent" -- so the reason
// it is down there has to be on the page. Both feeds are keyed by CVE, and an
// advisory that never got one is unscoreable rather than safe.
func writeTriageCaveats(b *strings.Builder, res *analyze.Result) {
	t := res.Triage
	if t == nil {
		return
	}
	if t.EPSSError != "" {
		fmt.Fprintf(b, "NOTE: --triage could not read the EPSS feed, so nothing below is ordered by "+
			"exploitation probability - %s\n", t.EPSSError)
	} else if t.EPSSStale {
		fmt.Fprintf(b, "NOTE: --triage could not reach the EPSS feed and used the cached scores from %s; "+
			"the percentiles below are that day's\n", t.EPSSDate)
	}
	if t.KEVError != "" {
		fmt.Fprintf(b, "NOTE: --triage could not read CISA's known-exploited catalog, so no row below "+
			"is marked as exploited - %s\n", t.KEVError)
	} else if t.KEVStale {
		fmt.Fprintf(b, "NOTE: --triage could not reach CISA's catalog and used the cached copy %s\n", t.KEVDate)
	}

	if t.EPSSError != "" || t.Unscored() == 0 {
		return
	}
	var why []string
	if t.NoCVE > 0 {
		why = append(why, fmt.Sprintf("%d carry no CVE id, which is the only key either feed has", t.NoCVE))
	}
	if t.NotInFeed > 0 {
		why = append(why, fmt.Sprintf("%d have a CVE the feed has not scored yet, which usually means "+
			"it was published in the last day or two", t.NotInFeed))
	}
	fmt.Fprintf(b, "NOTE: --triage could not score %d of %d findings, so they sort last for lack of "+
		"data rather than lack of risk:\n", t.Unscored(), t.Scored+t.Unscored())
	for _, w := range why {
		fmt.Fprintf(b, "      %s\n", w)
	}
}

// footerThreshold is how many lines a report may be before it needs its summary
// repeated at the bottom.
//
// A proxy for one screen, and deliberately a count of the report's own lines
// rather than the terminal's height: the output has to be identical whether it
// is paged, redirected into a file, or uploaded to a gist, because those are
// the same bytes and get diffed against each other. Under the threshold nothing
// has scrolled and the header is still visible, where a second copy of it four
// lines further down is just noise.
const footerThreshold = 30

// writeFooter repeats, at the bottom of a long report, the things a reader
// needed and has already scrolled past.
//
// The counts, because "how bad is this" is the question someone asks again
// after reading 154 rows. The caveats, because an INCOMPLETE banner that only
// appears above 154 rows is one nobody sees -- and this is also the end a CI
// log, a piped file and a gist all land on.
func writeFooter(b *strings.Builder, res *analyze.Result, pal palette) {
	writeCaveats(b, res, pal)
	writeSummary(b, res, true)
}

// writeSections lists what the report was divided into, with the counts.
//
// Built from sections() rather than recounted, so the index cannot claim a
// heading the report does not have or disagree with one it does.
func writeSections(b *strings.Builder, res *analyze.Result) {
	secs := sections(res)
	parts := make([]string, 0, len(secs))
	for _, s := range secs {
		parts = append(parts, fmt.Sprintf("%s (%d)", s.title, len(s.findings)))
	}
	if len(parts) == 0 {
		return
	}
	fmt.Fprintf(b, "  %d findings in %d section(s): %s\n",
		len(res.Findings), len(secs), strings.Join(parts, ", "))
}

// writeSummary prints one line per ecosystem that ran, then the severity
// spread, and for the footer an index of the sections below.
//
// The index is footer-only because at the top of the report the section
// headings are the next thing on screen, and listing them there would be
// telling a reader what they can already see.
func writeSummary(b *strings.Builder, res *analyze.Result, index bool) {
	perEco := map[string]int{}
	for _, f := range res.Findings {
		perEco[f.Ecosystem]++
	}
	for _, e := range res.Ecosystems {
		if e.Error != "" {
			continue // already reported above, in stronger terms
		}
		// The OSV ecosystem names are worth printing next to the plugin id -- "os
		// Debian:12" is what a reader checks before trusting the rows below --
		// but a plugin whose ecosystem is just its own name is not worth saying
		// twice.
		name := strings.Join(e.Ecosystems, ", ")
		if strings.EqualFold(name, e.ID) {
			name = ""
		}
		fmt.Fprintf(b, "  %-8s %-24s %4d components  %4d findings\n",
			e.ID, name, e.Components, perEco[e.ID])
	}

	// The severity spread is the one number a reader wants before deciding how
	// much of the rest to read. Findings a vendor has already answered are left
	// out of it, so the count is what is still open rather than what was found.
	counts := map[string]int{}
	vexed := 0
	for _, f := range res.Findings {
		if !f.Affected() {
			continue
		}
		if alreadyVexed(f) {
			vexed++
			continue
		}
		counts[displaySeverity(f)]++
	}
	if spread := severitySpread(counts, false); spread != "" {
		fmt.Fprintf(b, "  affected by severity: %s\n", spread)
	}
	writeRemediation(b, res)
	if vexed > 0 {
		fmt.Fprintf(b, "  already vexed: %d by %s\n", vexed, vexAuthors(res))
	}
	writePriority(b, res)
	if index {
		writeSections(b, res)
	}
	b.WriteString("\n")
}

// highPercentile is where "worth looking at first" begins. Arbitrary, like
// every threshold, and chosen because the EPSS distribution is steep enough
// that the top tenth is a genuinely short list: on debian:12 it is four rows
// out of a hundred and fifty-four.
const highPercentile = 0.90

// writeRemediation summarises what the affected rows cost to fix, over the same
// population the severity spread counts: everything affected that a vendor has
// not already answered.
//
// Two facts, both of which a wall of 150 rows hides. How many of the rows are
// the same advisory seen on more than one package -- CVE-2022-27943 is one
// advisory and three rows -- so "154 findings" is not "154 things to chase".
// And how many have a published fix, because a report that cannot say which of
// its findings are actionable leaves the reader to open all of them.
//
// The fix clause is printed even when nothing is fixable, where it reads "154
// with no fix yet". An earlier cut dropped it there to avoid a line saying "0
// fixable", which was the wrong instinct: a fully-patched image is the case a
// reader most wants confirmed, and silence in a summary reads as a missing
// measurement rather than as a measured zero. The clause never phrases it as a
// zero, so both facts get said.
func writeRemediation(b *strings.Builder, res *analyze.Result) {
	total, fixable := 0, 0
	advisories := map[string]bool{}
	for _, f := range res.Findings {
		if !f.Affected() || alreadyVexed(f) {
			continue
		}
		total++
		advisories[shortAdvisory(f)] = true
		if f.FixedVersion != "" {
			fixable++
		}
	}
	if total == 0 {
		return
	}
	var parts []string
	if len(advisories) != total {
		// Only worth saying when the two disagree: on a report where every row
		// is its own advisory, "N affected = N unique" is a tautology.
		parts = append(parts, fmt.Sprintf("%d unique advisories", len(advisories)))
	}
	if fixable > 0 {
		parts = append(parts, fmt.Sprintf("%d fixable, %d with no fix yet", fixable, total-fixable))
	} else {
		parts = append(parts, fmt.Sprintf("%d with no fix yet", total))
	}
	fmt.Fprintf(b, "  %d affected: %s\n", total, strings.Join(parts, ", "))
}

// writePriority summarises the exploitation evidence, over exactly the rows the
// severity spread above it counts.
//
// Same population on purpose. Two summary lines describing different subsets of
// the same report is the kind of small dishonesty a reader only discovers by
// adding the numbers up and finding they disagree.
//
// The KEV clause is the one exception, and it earns it. Everything else here is
// a count of work to do, which is a question about the affected rows only. "Is
// this in the catalog" is a question about the scan, and it is asked in two
// other places -- the --triage log line and TriageResult.KnownExploited in the
// JSON -- both of which count every finding. Scoping the text summary silently
// let it print "none in CISA's known-exploited catalog" over a run whose own
// log line said three. So a hit outside the population is still counted; it is
// just reported as being outside it.
func writePriority(b *strings.Builder, res *analyze.Result) {
	t := res.Triage
	if t == nil {
		return
	}
	var kev, elsewhere, high, scored, unscored int
	for _, f := range res.Findings {
		p := f.Priority
		if !f.Affected() || alreadyVexed(f) {
			// Ruled out, undetermined, or already answered by a vendor. Not
			// work to do, so not in any of the counts below -- but if the
			// catalog fired on it, it fired.
			if p != nil && p.KEV != nil {
				elsewhere++
			}
			continue
		}
		switch {
		case p == nil || !p.Scored:
			unscored++
		default:
			scored++
			if p.Percentile >= highPercentile {
				high++
			}
		}
		if p != nil && p.KEV != nil {
			kev++
		}
	}
	// Every counted row lands in scored or unscored before kev is considered,
	// so this is the size of the population and kev > 0 implies it is not zero.
	//
	// Nothing in the population is not the same as nothing scored, and a
	// metadata-only scan makes the difference visible: every row there is
	// undetermined, so the affected population is empty by construction while
	// the rows themselves carry percentiles. "0 scored" printed over a table of
	// EPSS columns is a summary the report contradicts three lines later, so
	// the clauses that count the population are gated on there being one.
	population := scored + unscored

	var parts []string
	switch {
	case kev > 0 && elsewhere > 0:
		parts = append(parts, fmt.Sprintf("%d known exploited (CISA KEV), %d more outside the affected rows", kev, elsewhere))
	case kev > 0:
		parts = append(parts, fmt.Sprintf("%d known exploited (CISA KEV)", kev))
	case elsewhere > 0:
		// Said even over an empty population, and said without softening. The
		// rows it refers to are ones this scan ruled out or a vendor already
		// answered, and that is what "outside" carries -- but a catalog hit
		// this report holds and does not mention is a fact a reader has to
		// find by reading the JSON.
		parts = append(parts, fmt.Sprintf("no affected row is in CISA's known-exploited catalog, but %s", otherRows(elsewhere)))
	case t.KEVError == "" && population > 0:
		// Worth saying out loud that the catalog was consulted and had nothing.
		// Not worth reading as reassurance: it holds a few thousand entries and
		// covers almost nothing a base image ships.
		parts = append(parts, "none in CISA's known-exploited catalog")
	}
	if t.EPSSError == "" && population > 0 {
		parts = append(parts,
			fmt.Sprintf("%d at or above the %dth EPSS percentile", high, int(highPercentile*100)),
			fmt.Sprintf("%d scored", scored))
		if unscored > 0 {
			parts = append(parts, fmt.Sprintf("%d unscored", unscored))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(b, "  priority: %s\n", strings.Join(parts, ", "))
	}

	// A percentile is a claim about a day. A report read next month, or a CI
	// log read after an incident, must be able to see which day.
	var dates []string
	if t.EPSSDate != "" {
		dates = append(dates, "EPSS "+t.EPSSDate+stale(t.EPSSStale))
	}
	if t.KEVDate != "" {
		dates = append(dates, "KEV catalog "+t.KEVDate+stale(t.KEVStale))
	}
	if len(dates) > 0 {
		fmt.Fprintf(b, "  priority data: %s\n", strings.Join(dates, ", "))
	}
}

// otherRows renders the count of catalog hits that fell outside the affected
// population, agreeing with itself about number.
func otherRows(n int) string {
	if n == 1 {
		return "1 other row is"
	}
	return fmt.Sprintf("%d other rows are", n)
}

func stale(b bool) string {
	if b {
		return " (cached)"
	}
	return ""
}

// withheldSpread is what --severity hid, by severity.
func withheldSpread(w *analyze.Withheld) string {
	return severitySpread(w.BySeverity, true)
}

// severitySpread renders a count-per-label as "10 critical, 26 high", in the
// order the ranking puts them rather than the order a map iterates.
//
// gloss adds "(no rating was published)" to the unknown count. It is on for the
// withheld line and off for the affected one, and it is the sentence that keeps
// a severity filter honest: without it, 36 findings whose records are CVSS
// v4-only disappear behind a number that reads like low-priority noise. UNKNOWN
// outranks MEDIUM here for exactly that reason, and a reader who just hid it
// deserves to be told what they hid.
func severitySpread(counts map[string]int, gloss bool) string {
	var parts []string
	for _, label := range cvss.Labels {
		n := counts[label]
		if n == 0 {
			continue
		}
		part := fmt.Sprintf("%d %s", n, strings.ToLower(label))
		if gloss && label == cvss.Unknown {
			part += " (no rating was published)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

// vexAuthors names who published the statements, for the summary line. A
// reader deciding whether to trust 61 rows moving out of AFFECTED needs to know
// whose word it is on.
func vexAuthors(res *analyze.Result) string {
	var names []string
	seen := map[string]bool{}
	for _, h := range res.VEXHubs {
		name := h.Author
		if name == "" {
			name = h.URL
		}
		if h.Matched == 0 || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return "a published VEX statement"
	}
	return strings.Join(names, ", ")
}

// section is one heading and the findings under it.
type section struct {
	title string
	note  string
	// vex swaps the trailing columns for the vendor's status and reasoning,
	// which is the only thing worth reading about a row nobody has to act on.
	vex      bool
	findings []analyze.Finding
}

// alreadyVexed reports whether a finding is one the vendor has published an
// answer to.
//
// Only an exculpatory statement counts. A vendor saying "affected" or "still
// looking" has spoken, but not in a way that lets a reader skip the row, and
// moving it out of AFFECTED on that basis would be the one mistake this tool
// must not make.
func alreadyVexed(f analyze.Finding) bool {
	return f.VEX.Exculpatory()
}

// sections splits findings into what to act on, what a vendor has already
// answered, what could not be decided, and what was ruled out.
//
// Affected comes first because it is the part that requires action. Already
// vexed sits directly beneath it, because it is the same evidence with somebody
// else's conclusion attached, and a reader comparing the two should not have to
// scroll. Ruled out comes last and is still printed in full: it is the tool's
// proof of work, and the reason a reader can believe the short list above it.
//
// A vexed finding keeps its status. Nothing here rewrites a verdict -- the row
// simply moves, so the affected count reflects what nobody has spoken to yet
// while --format json stays identical to a run without --vexhub.
func sections(res *analyze.Result) []section {
	var affected, vexed, undetermined, ruledOut []analyze.Finding
	for _, f := range res.Findings {
		switch f.Status {
		case analyze.StatusLinked, analyze.StatusReachable:
			if alreadyVexed(f) {
				vexed = append(vexed, f)
			} else {
				affected = append(affected, f)
			}
		case analyze.StatusNotPresent, analyze.StatusNotInPath:
			ruledOut = append(ruledOut, f)
		default:
			undetermined = append(undetermined, f)
		}
	}
	out := []section{
		{title: "AFFECTED", note: "vulnerable code is present and can be loaded", findings: affected},
		{
			title:    "ALREADY VEXED",
			note:     "a published statement answers these; vexscan's own verdict is unchanged",
			vex:      true,
			findings: vexed,
		},
		{title: "UNDETERMINED", note: "not enough evidence to decide either way", findings: undetermined},
		{title: "RULED OUT", note: "the vulnerable code is not present or cannot run", findings: ruledOut},
	}
	var kept []section
	for _, s := range out {
		if len(s.findings) > 0 {
			kept = append(kept, s)
		}
	}
	return kept
}

// writeSection prints one heading and its table.
func writeSection(b *strings.Builder, s section, o renderOpts) {
	rows := make([]analyze.Finding, len(s.findings))
	copy(rows, s.findings)
	sortForDisplay(rows)

	fmt.Fprintf(b, "%s - %s\n", o.pal.heading(fmt.Sprintf("%s (%d)", s.title, len(rows))), s.note)

	// The VERDICT column earns its place only when the section holds more than
	// one status. In a Debian image everything affected is "linked", and a
	// column repeating that on all 152 rows is noise; a repo scan mixing linked
	// and reachable gets the column automatically.
	showVerdict := distinctStatuses(rows) > 1

	// The triage columns earn their place the same way VERDICT does. EPSS
	// appears when --triage scored anything in this section; KEV only when
	// something in it is actually listed, which on most images is never, and a
	// column of blanks would be a daily reminder of a rare event.
	showEPSS, showKEV := triageColumns(rows)

	// FIXED IN earns its place the same way: it appears only when the section
	// holds at least one row with a published fix, so a scan of an ecosystem
	// that publishes none (or a --repo run) does not get a column of dashes.
	showFixed := fixedColumn(rows)

	header := []string{"SEVERITY", "ADVISORY", "PACKAGE", "VERSION"}
	if showFixed {
		header = append(header, "FIXED IN")
	}
	if showEPSS {
		header = append(header, "EPSS")
	}
	if showKEV {
		header = append(header, "KEV")
	}
	if showVerdict {
		header = append(header, "VERDICT")
	}
	if s.vex {
		// BASIS is how vexscan reached its verdict, which for these rows is not
		// the question -- the reader already knows the code is linked and is
		// here to see what the vendor said about it instead.
		header = append(header, "VEX STATUS", "JUSTIFICATION")
	} else {
		header = append(header, "BASIS")
	}

	table := [][]string{header}
	for _, f := range rows {
		cells := []string{
			o.pal.severity(displaySeverity(f)),
			shortAdvisory(f),
			truncate(f.Component(), 40),
			truncate(f.Version, 28),
		}
		if showFixed {
			cells = append(cells, displayFixed(f))
		}
		if showEPSS {
			cells = append(cells, displayEPSS(f))
		}
		if showKEV {
			cells = append(cells, displayKEV(f))
		}
		if showVerdict {
			cells = append(cells, o.pal.status(f.Status, string(f.Status)))
		}
		if s.vex {
			cells = append(cells, f.VEX.Status, truncate(vexReason(f.VEX), 44))
		} else {
			cells = append(cells, f.Method)
		}
		table = append(table, cells)
	}
	writeTable(b, table)

	if o.details {
		b.WriteString("\n")
		for _, f := range rows {
			writeDetail(b, f, o.pal)
		}
	}
	b.WriteString("\n")
}

// vexReason is the short why for a statement's table cell.
//
// The justification is a fixed OpenVEX term and fits a column. Its absence is
// legal -- a "fixed" statement needs no excuse -- and the impact statement is
// the next best thing, truncated by the caller. The full sentence is in
// --details and in the JSON.
func vexReason(v *ecosystem.VEXStatement) string {
	switch {
	case v == nil:
		return ""
	case v.Justification != "":
		return v.Justification
	default:
		return v.ImpactStatement
	}
}

// distinctStatuses counts how many different verdicts a set of rows holds.
func distinctStatuses(rows []analyze.Finding) int {
	seen := map[analyze.Status]bool{}
	for _, f := range rows {
		seen[f.Status] = true
	}
	return len(seen)
}

// sortForDisplay orders rows by exploitation evidence where --triage supplied
// any, then by severity, then by the names a reader scans for.
//
// The triage comparisons come first and cost nothing when the flag was off:
// every row is then in the same band with the same percentile, both tests fall
// through, and what remains is exactly the severity ordering this function has
// always done. That is what keeps an untriaged report byte-identical.
//
// Display order only. The JSON order is published and belongs to
// analyze.sortFindings, which is deliberately left alone.
func sortForDisplay(rows []analyze.Finding) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, c := rows[i], rows[j]
		if ba, bc := priorityBand(a), priorityBand(c); ba != bc {
			return ba < bc
		}
		if pa, pc := percentile(a), percentile(c); pa != pc {
			return pa > pc // likeliest first
		}
		if ra, rc := cvss.Rank(displaySeverity(a)), cvss.Rank(displaySeverity(c)); ra != rc {
			return ra < rc
		}
		if ca, cc := a.Component(), c.Component(); ca != cc {
			return ca < cc
		}
		return shortAdvisory(a) < shortAdvisory(c)
	})
}

// Bands for the triage sort. Known-exploited outranks every probability there
// is, because it is not a probability: someone has already done it.
//
// Unscored rows land in the same band as untriaged ones, at the bottom. That
// placement is a compromise and it is the reason writeTriageCaveats exists --
// in a list ordered by likelihood, last reads as "least likely", and for these
// rows it means "nobody knows". The alternative, scattering unscored rows
// through the middle by severity, hides them instead, which is worse.
const (
	bandKEV = iota
	bandScored
	bandUnscored
)

func priorityBand(f analyze.Finding) int {
	switch p := f.Priority; {
	case p == nil:
		return bandUnscored
	case p.KEV != nil:
		return bandKEV
	case p.Scored:
		return bandScored
	default:
		return bandUnscored
	}
}

func percentile(f analyze.Finding) float64 {
	if f.Priority == nil {
		return 0
	}
	return f.Priority.Percentile
}

// triageColumns reports which of the two triage columns this section has
// anything to put in.
func triageColumns(rows []analyze.Finding) (epss, kev bool) {
	for _, f := range rows {
		if f.Priority == nil {
			continue
		}
		if f.Priority.Scored {
			epss = true
		}
		if f.Priority.KEV != nil {
			kev = true
		}
	}
	return epss, kev
}

// fixedColumn reports whether any row in the section has a published fix, which
// is what earns the FIXED IN column its place. A section where nothing has a
// fix -- or an ecosystem that publishes no fixed versions at all -- gets no
// column rather than one reading "no fix" on every row.
func fixedColumn(rows []analyze.Finding) bool {
	for _, f := range rows {
		if f.FixedVersion != "" {
			return true
		}
	}
	return false
}

// displayFixed is the version to upgrade to, or "no fix" when the advisory
// published none. The two are deliberately distinct: a blank cell reads as
// missing data, while "no fix" is data -- the flaw is acknowledged and no patch
// has shipped.
func displayFixed(f analyze.Finding) string {
	if f.FixedVersion == "" {
		return "no fix"
	}
	return truncate(f.FixedVersion, 28)
}

// otherFixes is the published fixes the row is not recommending: the branches
// the advisory also patched, minus the one FixedVersion names.
//
// It stays out of the table on purpose. The FIXED IN column is one target per
// row because the table is a scan and a cell holding three versions is not
// scannable; the alternatives belong in --details, where there is room to say
// what they are. Empty in the ordinary case, where the advisory fixed one
// branch and there is nothing withheld.
func otherFixes(f analyze.Finding) []string {
	var out []string
	for _, v := range f.FixedVersions {
		if v != f.FixedVersion {
			out = append(out, v)
		}
	}
	return out
}

// displayEPSS is the percentile as a percentage, which is the form a human can
// reason about. The raw score is in --details and in the JSON: 0.03 reads as
// "negligible" and is in fact the 87th percentile of every scored CVE there is,
// because the distribution is extremely skewed.
//
// An unscored row gets a dash rather than 0.0%, since the two mean opposite
// things.
func displayEPSS(f analyze.Finding) string {
	if f.Priority == nil || !f.Priority.Scored {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", f.Priority.Percentile*100)
}

// writePriorityDetail is the --details view of the exploitation evidence.
//
// It names the CVE the score was looked up under, which for a Go finding is not
// the id at the top of the block -- GO-2025-3547 is scored as CVE-2024-7598 --
// so the reader can check the join rather than take it on faith.
func writePriorityDetail(b *strings.Builder, f analyze.Finding) {
	p := f.Priority
	if p == nil {
		return
	}
	switch {
	case p.Scored:
		line := fmt.Sprintf("%.1f%% percentile (epss %.5f)", p.Percentile*100, p.EPSS)
		if p.CVE != f.CVE {
			line += " for " + p.CVE
		}
		// An advisory that bundles a patch is reported at its worst member, so
		// the row's rank is one CVE's and the row is about several. Saying which
		// of how many is what lets the reader check that rather than assume it.
		if p.OfSet > 1 {
			line += fmt.Sprintf(", highest of %d", p.OfSet)
		}
		fmt.Fprintf(b, "  epss:     %s\n", line)
	case p.CVE == "":
		fmt.Fprintf(b, "  epss:     not scored - this advisory has no CVE id, and both feeds are keyed by CVE\n")
	case p.OfSet > 1:
		fmt.Fprintf(b, "  epss:     not scored - none of this advisory's %d CVEs are in the feed yet\n", p.OfSet)
	default:
		fmt.Fprintf(b, "  epss:     not scored - %s is not in the feed yet\n", p.CVE)
	}
	if p.KEV != nil {
		line := fmt.Sprintf("in CISA's known-exploited catalog since %s", p.KEV.DateAdded)
		if p.KEV.DueDate != "" {
			line += fmt.Sprintf(", federal remediation due %s", p.KEV.DueDate)
		}
		if p.KEV.Ransomware {
			line += "; known ransomware campaign use"
		}
		fmt.Fprintf(b, "  kev:      %s\n", line)
	}
}

func displayKEV(f analyze.Finding) string {
	if f.Priority == nil || f.Priority.KEV == nil {
		return ""
	}
	if f.Priority.KEV.Ransomware {
		return "ransomware"
	}
	return "yes"
}

// displaySeverity is the finding's severity, as a label that always sorts.
//
// An empty Severity means no advisory was resolved for this finding, which is
// reported as UNKNOWN rather than as a blank cell. cvss.Rank puts UNKNOWN above
// MEDIUM on purpose: a severity nobody published is not evidence that the
// problem is small, and a report several hundred rows long is one where
// anything sorted to the bottom stops being read.
//
// The mapping itself lives in cvss because --severity filters on it too, in
// another package. A renderer and a filter disagreeing about what an unrated
// finding is would show a row the filter thought it had removed.
func displaySeverity(f analyze.Finding) string {
	return cvss.Display(f.Severity)
}

// cveSuffix matches a bare CVE id, which is what has to be left behind when a
// distro prefix is stripped.
var cveSuffix = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// shortAdvisory is the id to print.
//
// A distro prefix is dropped only when what remains is a well-formed CVE id, so
// DEBIAN-CVE-2022-27943 shortens to CVE-2022-27943 -- the id a reader will look
// up, and the one that matches every other tool's output -- while DSA-5678-1,
// which is not a CVE and has no shorter spelling, is left exactly as it is. The
// full OSV id is still in the JSON and in --details.
func shortAdvisory(f analyze.Finding) string {
	id := f.CVE
	if id == "" {
		id = f.ID
	}
	if _, rest, found := strings.Cut(id, "-"); found && cveSuffix.MatchString(rest) {
		return rest
	}
	return id
}

// writeTable prints rows in aligned columns, sizing each from its contents.
//
// Two spaces between columns and no padding after the last one, matching
// renderInventory. Trailing whitespace is not written, so a row can be diffed
// and a column can be cut without picking up invisible padding.
//
// Widths are measured with visibleWidth and not with len([]rune(cell)), because
// a coloured cell is runes that occupy no columns; see its comment.
func writeTable(b *strings.Builder, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, cell := range r {
			if i < len(widths) && visibleWidth(cell) > widths[i] {
				widths[i] = visibleWidth(cell)
			}
		}
	}
	for _, r := range rows {
		var line strings.Builder
		for i, cell := range r {
			if i > 0 {
				line.WriteString("  ")
			}
			line.WriteString(cell)
			if i < len(r)-1 {
				line.WriteString(strings.Repeat(" ", widths[i]-visibleWidth(cell)))
			}
		}
		b.WriteString(strings.TrimRight(line.String(), " "))
		b.WriteString("\n")
	}
}

// truncate caps a cell so one pathological name cannot widen every row.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

// listCVEs joins the CVEs an advisory bundles, naming at most max of them and
// counting the rest.
//
// The count is not decoration. A distro advisory that fixes fourteen CVEs is a
// different object from one that fixes two, and a line that stopped at five
// with no remainder would read as the whole list.
func listCVEs(cves []string, max int) string {
	if len(cves) <= max {
		return strings.Join(cves, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(cves[:max], ", "), len(cves)-max)
}

// writeDetail prints everything known about one finding: the block the report
// used to print for every finding, plus the evidence and the plugin's own
// characterisation, neither of which the text output has ever shown.
func writeDetail(b *strings.Builder, f analyze.Finding, pal palette) {
	id := f.CVE
	if f.GoID != "" && f.GoID != f.CVE {
		id = fmt.Sprintf("%s (%s)", f.CVE, f.GoID)
	}
	// Padded before it is coloured: %-22s counts the escape bytes, and the
	// verdict is the first column of every detail block.
	fmt.Fprintf(b, "%s %s\n", pal.status(f.Status, fmt.Sprintf("%-22s", statusLabel(f.Status))), component(f))
	fmt.Fprintf(b, "  cve:      %s\n", id)
	if len(f.Upstream) > 0 {
		fmt.Fprintf(b, "  fixes:    %s\n", listCVEs(f.Upstream, 5))
	}
	if f.Ecosystem != "" {
		fmt.Fprintf(b, "  from:     %s\n", f.Ecosystem)
	}
	if sev := displaySeverity(f); sev != cvss.Unknown || f.CVSS != "" {
		line := sev
		if f.CVSS != "" {
			if score, ok := cvss.Score(f.CVSS); ok {
				line = fmt.Sprintf("%s (%.1f %s)", sev, score, f.CVSS)
			} else {
				line = fmt.Sprintf("%s (%s)", sev, f.CVSS)
			}
		}
		fmt.Fprintf(b, "  severity: %s\n", line)
	}
	if f.FixedVersion != "" {
		// The versions not chosen are named on the same line, because an
		// advisory that fixed three maintained branches offers three upgrades
		// and only one of them is the small one. Showing the target alone would
		// present a pick as the only option -- and where the ecosystem cannot be
		// ordered the pick is the highest, which is the expensive option.
		line := f.FixedVersion
		if others := otherFixes(f); len(others) > 0 {
			line += fmt.Sprintf(" (also fixed in %s)", strings.Join(others, ", "))
		}
		fmt.Fprintf(b, "  fixed in: %s\n", line)
	}
	writePriorityDetail(b, f)
	if f.Component() != f.Package && f.Package != "" {
		// The source package is worth showing precisely where it differs: it is
		// what the advisory is filed against, and what a reader will find if
		// they go looking for the fix.
		fmt.Fprintf(b, "  source:   %s\n", f.Package)
	}
	if f.PURL != "" {
		fmt.Fprintf(b, "  purl:     %s\n", f.PURL)
	}
	if f.Binary != "" {
		fmt.Fprintf(b, "  binary:   %s%s\n", f.Binary, strippedNote(f.Stripped))
	}
	if len(f.Packages) > 0 {
		fmt.Fprintf(b, "  packages: %s (%s)\n", strings.Join(f.Packages, ", "), f.Granularity)
	}
	if f.Justification != "" {
		fmt.Fprintf(b, "  vex:      %s [%s]\n", f.Justification, f.Method)
	} else if f.Method != "" && f.Status == analyze.StatusReachable {
		fmt.Fprintf(b, "  method:   %s\n", f.Method)
	}
	if f.Reachability != "" {
		fmt.Fprintf(b, "  detail:   %s\n", f.Reachability)
	}
	if f.Reason != "" {
		fmt.Fprintf(b, "  reason:   %s\n", f.Reason)
	}
	for _, e := range f.Evidence {
		marker := ""
		if e.Blocking {
			// A blocking taint is why a finding could not be ruled out, so it
			// must not read as one more supporting note.
			marker = " (blocking)"
		}
		fmt.Fprintf(b, "  evidence: [%s]%s %s\n", e.Origin, marker, e.Detail)
	}
	if v := f.VEX; v != nil {
		// The impact statement is the vendor's own sentence about this
		// vulnerability in this product, and is usually the most useful line in
		// the whole block -- the table has no room for it, so this is where it
		// goes.
		author := v.Author
		if author == "" {
			author = v.Hub
		}
		fmt.Fprintf(b, "  vendor:   %s says %s", author, v.Status)
		if v.Justification != "" {
			fmt.Fprintf(b, " (%s)", v.Justification)
		}
		b.WriteString("\n")
		for _, line := range []string{v.ImpactStatement, v.ActionStatement} {
			if line != "" {
				fmt.Fprintf(b, "            %s\n", line)
			}
		}
		fmt.Fprintf(b, "            product %s", v.Product)
		if v.Timestamp != "" {
			fmt.Fprintf(b, ", published %s", v.Timestamp)
		}
		b.WriteString("\n")
		if v.Match != "" {
			// The component match was deliberately loose about spelling, so the
			// disagreement it accepted is shown rather than hidden.
			fmt.Fprintf(b, "            matched loosely: %s\n", v.Match)
		}
	}
	if f.LLM != nil {
		fmt.Fprintf(b, "  llm:      exploitable=%s confidence=%s\n", f.LLM.Exploitable, f.LLM.Confidence)
		if f.LLM.Rationale != "" {
			fmt.Fprintf(b, "            %s\n", f.LLM.Rationale)
		}
	}
	b.WriteString("\n")
}

func statusLabel(s analyze.Status) string {
	switch s {
	case analyze.StatusNotPresent:
		return "[NOT PRESENT]"
	case analyze.StatusNotInPath:
		return "[NOT REACHABLE]"
	case analyze.StatusLinked:
		return "[LINKED]"
	case analyze.StatusReachable:
		return "[REACHABLE]"
	default:
		return "[UNDETERMINED]"
	}
}

// component names what a finding is about. An id that matched nothing in the
// target has no component at all, and printing "@" for it would look like a
// package whose name failed to render.
func component(f analyze.Finding) string {
	switch {
	case f.Component() == "":
		return "(no matching component)"
	case f.Version == "":
		return f.Component()
	default:
		return f.Component() + "@" + f.Version
	}
}

// strippedNote annotates a binary that carries no symbol table. Nil means the
// question does not apply: an OS package is not a Go binary.
func strippedNote(stripped *bool) string {
	if stripped != nil && *stripped {
		return " (stripped)"
	}
	return ""
}
