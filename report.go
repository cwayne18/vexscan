package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
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
// screenshot. There is no colour for the same reason, and because nothing in
// this tree detects a tty.

// renderText renders a scan result for humans.
func renderText(res *analyze.Result, details bool) string {
	var b strings.Builder
	writeHeader(&b, res)

	if len(res.Findings) == 0 {
		// Empty because nothing was wrong and empty because nothing was read
		// look identical, and only one of them is good news.
		if res.Failed() {
			b.WriteString("No findings, but the scan was incomplete: see above.\n")
			b.WriteString("This is not a clean result.\n")
		} else {
			b.WriteString("No findings: nothing selected was found in this target,\n")
			b.WriteString("or no matching advisories were published for it.\n")
		}
		return b.String()
	}

	writeSummary(&b, res)
	for _, s := range sections(res.Findings) {
		writeSection(&b, s, details)
	}
	return b.String()
}

// writeHeader prints what was scanned, and anything that makes the answer
// incomplete.
//
// The INCOMPLETE banners come before everything else and are unconditional.
// They are the guarantee that a scan which could not read part of the target
// never renders as a clean one, and no amount of table formatting below is
// allowed to push them out of sight.
func writeHeader(b *strings.Builder, res *analyze.Result) {
	fmt.Fprintf(b, "vexscan report (%s) for %s\n", res.Mode, res.Target)
	if res.Module != "" {
		fmt.Fprintf(b, "module: %s\n", res.Module)
	}
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
	b.WriteString("\n")
}

// writeSummary prints one line per ecosystem that ran, then the severity spread.
func writeSummary(b *strings.Builder, res *analyze.Result) {
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
	// much of the rest to read.
	counts := map[string]int{}
	for _, f := range res.Findings {
		if f.Affected() {
			counts[displaySeverity(f)]++
		}
	}
	var parts []string
	for _, label := range []string{cvss.Critical, cvss.High, cvss.Unknown, cvss.Medium, cvss.Low, cvss.None} {
		if counts[label] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[label], strings.ToLower(label)))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(b, "  affected by severity: %s\n", strings.Join(parts, ", "))
	}
	b.WriteString("\n")
}

// section is one heading and the findings under it.
type section struct {
	title    string
	note     string
	findings []analyze.Finding
}

// sections splits findings into what to act on, what could not be decided, and
// what was ruled out.
//
// Affected comes first because it is the part that requires action. Ruled out
// comes last and is still printed in full: it is the tool's proof of work, and
// the reason a reader can believe the short list above it.
func sections(findings []analyze.Finding) []section {
	var affected, undetermined, ruledOut []analyze.Finding
	for _, f := range findings {
		switch f.Status {
		case analyze.StatusLinked, analyze.StatusReachable:
			affected = append(affected, f)
		case analyze.StatusNotPresent, analyze.StatusNotInPath:
			ruledOut = append(ruledOut, f)
		default:
			undetermined = append(undetermined, f)
		}
	}
	out := []section{
		{title: "AFFECTED", note: "vulnerable code is present and can be loaded", findings: affected},
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
	header = append(header, "BASIS")

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
		cells = append(cells, f.Method)
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
func displaySeverity(f analyze.Finding) string {
	if f.Severity == "" {
		return cvss.Unknown
	}
	return f.Severity
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
