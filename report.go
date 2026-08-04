package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/ecosystem"
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
// screenshot. There is no colour for the same reason.
//
// pager.go does look at whether stdout is a tty, which is not a reversal of
// that: it decides whether to run less, and changes no bytes. Everything here
// renders identically for a terminal, a file and a pipe -- including the footer
// below, whose threshold is counted in the report's own lines and never in the
// terminal's height.

// renderText renders a scan result for humans.
func renderText(res *analyze.Result, details bool) string {
	var b strings.Builder
	writeHeader(&b, res)

	if len(res.Findings) == 0 {
		// Three ways to be empty, and only one of them is good news. Nothing
		// was wrong; nothing was read; or something was found and the reader's
		// own filter hid all of it.
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
			fmt.Fprintf(&b, "--severity %s withheld all %d finding(s): %s.\n",
				strings.Join(res.Withheld.Severities, ","), res.Withheld.Count,
				withheldSpread(res.Withheld))
			b.WriteString("This is a filtered view, not a clean result.\n")
		default:
			b.WriteString("No findings: nothing selected was found in this target,\n")
			b.WriteString("or no matching advisories were published for it.\n")
		}
		return b.String()
	}

	writeSummary(&b, res, false)
	for _, s := range sections(res) {
		writeSection(&b, s, details)
	}

	// Long enough that the header is gone: say it all again. Measured on the
	// report rather than on the terminal, so a file, a gist and a paged
	// terminal all get the same bytes.
	if strings.Count(b.String(), "\n") > footerThreshold {
		writeFooter(&b, res)
	}
	return b.String()
}

// writeHeader prints what was scanned, and anything that makes the answer
// incomplete.
//
// The INCOMPLETE banners come before everything else and are unconditional.
// They are the guarantee that a scan which could not read part of the target
// never renders as a clean one, and no amount of table formatting below is
// allowed to push them out of sight. That last promise is why writeFooter
// exists: at 172 lines, the table below pushes them out of sight anyway.
func writeHeader(b *strings.Builder, res *analyze.Result) {
	fmt.Fprintf(b, "vexscan report (%s) for %s\n", res.Mode, res.Target)
	if res.Module != "" {
		fmt.Fprintf(b, "module: %s\n", res.Module)
	}
	writeCaveats(b, res)
	b.WriteString("\n")
}

// writeCaveats writes everything that changes how the rows should be read: the
// INCOMPLETE banners, what --severity withheld, and a VEX hub that could not be
// reached.
//
// Split out of writeHeader so the footer can repeat it verbatim. A caveat that
// appeared at one end of a long report and not the other would be worse than
// one printed twice.
func writeCaveats(b *strings.Builder, res *analyze.Result) {
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
func writeFooter(b *strings.Builder, res *analyze.Result) {
	writeCaveats(b, res)
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
	if vexed > 0 {
		fmt.Fprintf(b, "  already vexed: %d by %s\n", vexed, vexAuthors(res))
	}
	if index {
		writeSections(b, res)
	}
	b.WriteString("\n")
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
func writeSection(b *strings.Builder, s section, details bool) {
	rows := make([]analyze.Finding, len(s.findings))
	copy(rows, s.findings)
	sortForDisplay(rows)

	fmt.Fprintf(b, "%s (%d) - %s\n", s.title, len(rows), s.note)

	// The VERDICT column earns its place only when the section holds more than
	// one status. In a Debian image everything affected is "linked", and a
	// column repeating that on all 152 rows is noise; a repo scan mixing linked
	// and reachable gets the column automatically.
	showVerdict := distinctStatuses(rows) > 1

	header := []string{"SEVERITY", "ADVISORY", "PACKAGE", "VERSION"}
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
			displaySeverity(f),
			shortAdvisory(f),
			truncate(f.Component(), 40),
			truncate(f.Version, 28),
		}
		if showVerdict {
			cells = append(cells, string(f.Status))
		}
		if s.vex {
			cells = append(cells, f.VEX.Status, truncate(vexReason(f.VEX), 44))
		} else {
			cells = append(cells, f.Method)
		}
		table = append(table, cells)
	}
	writeTable(b, table)

	if details {
		b.WriteString("\n")
		for _, f := range rows {
			writeDetail(b, f)
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

// sortForDisplay orders rows by severity, then by the names a reader scans for.
//
// Display order only. The JSON order is published and belongs to
// analyze.sortFindings, which is deliberately left alone.
func sortForDisplay(rows []analyze.Finding) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, c := rows[i], rows[j]
		if ra, rc := cvss.Rank(displaySeverity(a)), cvss.Rank(displaySeverity(c)); ra != rc {
			return ra < rc
		}
		if ca, cc := a.Component(), c.Component(); ca != cc {
			return ca < cc
		}
		return shortAdvisory(a) < shortAdvisory(c)
	})
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
func writeTable(b *strings.Builder, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, cell := range r {
			if i < len(widths) && len([]rune(cell)) > widths[i] {
				widths[i] = len([]rune(cell))
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
				line.WriteString(strings.Repeat(" ", widths[i]-len([]rune(cell))))
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

// writeDetail prints everything known about one finding: the block the report
// used to print for every finding, plus the evidence and the plugin's own
// characterisation, neither of which the text output has ever shown.
func writeDetail(b *strings.Builder, f analyze.Finding) {
	id := f.CVE
	if f.GoID != "" && f.GoID != f.CVE {
		id = fmt.Sprintf("%s (%s)", f.CVE, f.GoID)
	}
	fmt.Fprintf(b, "%-22s %s\n", statusLabel(f.Status), component(f))
	fmt.Fprintf(b, "  cve:      %s\n", id)
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
