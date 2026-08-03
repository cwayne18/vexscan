package main

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/target"
)

// report renders a result from a bare list of findings.
func report(t *testing.T, details bool, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "debian:12",
		Mode:          "image",
		Findings:      findings,
	}, details)
}

// lineWith returns the single rendered line containing want, failing if there
// is not exactly one.
func lineWith(t *testing.T, out, want string) string {
	t.Helper()
	var found []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, want) {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one line containing %q, got %d:\n%s", want, len(found), out)
	}
	return found[0]
}

// section returns the lines of the named section, heading excluded.
func sectionOf(t *testing.T, out, title string) []string {
	t.Helper()
	var lines []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, title+" ("):
			in = true
		case in && strings.TrimSpace(l) == "":
			return lines
		case in:
			lines = append(lines, l)
		}
	}
	if !in {
		t.Fatalf("no %s section in:\n%s", title, out)
	}
	return lines
}

// gccTrio is the real debian:12 data behind this whole change: one advisory
// against one source package, fanned out over three binary packages, with two
// different verdicts between them.
var gccTrio = []analyze.Finding{
	{
		Ecosystem: "os", CVE: "DEBIAN-CVE-2022-27943", ID: "DEBIAN-CVE-2022-27943",
		Package: "gcc-12", Module: "gcc-12", Version: "12.2.0-14+deb12u1",
		PURL:     "pkg:deb/debian/gcc-12-base@12.2.0-14+deb12u1?arch=amd64",
		Status:   analyze.StatusNotPresent,
		Method:   "pkgdb-no-code",
		Severity: "MEDIUM", CVSS: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
		Justification: "vulnerable_code_not_present",
	},
	{
		Ecosystem: "os", CVE: "DEBIAN-CVE-2022-27943", ID: "DEBIAN-CVE-2022-27943",
		Package: "gcc-12", Module: "gcc-12", Version: "12.2.0-14+deb12u1",
		PURL:     "pkg:deb/debian/libgcc-s1@12.2.0-14+deb12u1?arch=amd64",
		Status:   analyze.StatusLinked,
		Method:   "elf-needed-closure",
		Severity: "MEDIUM", CVSS: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
	},
	{
		Ecosystem: "os", CVE: "DEBIAN-CVE-2022-27943", ID: "DEBIAN-CVE-2022-27943",
		Package: "gcc-12", Module: "gcc-12", Version: "12.2.0-14+deb12u1",
		PURL:     "pkg:deb/debian/libstdc++6@12.2.0-14+deb12u1?arch=amd64",
		Status:   analyze.StatusLinked,
		Method:   "elf-needed-closure",
		Severity: "MEDIUM", CVSS: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
	},
}

// TestTheGCCTrioNoLongerContradictsItself is the defect this work started from.
// The report used to print these three as "gcc-12", twice as [LINKED] and once
// as [NOT PRESENT], with nothing on screen to tell them apart.
func TestTheGCCTrioNoLongerContradictsItself(t *testing.T) {
	out := report(t, false, gccTrio...)

	for _, name := range []string{"gcc-12-base", "libgcc-s1", "libstdc++6"} {
		lineWith(t, out, name)
	}
	// The verdicts land in the sections that state them, so the same advisory
	// appearing twice is no longer a contradiction but an answer per package.
	affected := strings.Join(sectionOf(t, out, "AFFECTED"), "\n")
	ruled := strings.Join(sectionOf(t, out, "RULED OUT"), "\n")
	if !strings.Contains(affected, "libgcc-s1") || !strings.Contains(affected, "libstdc++6") {
		t.Errorf("linked packages are not under AFFECTED:\n%s", out)
	}
	if !strings.Contains(ruled, "gcc-12-base") {
		t.Errorf("the not_present package is not under RULED OUT:\n%s", out)
	}
	if strings.Contains(affected, "gcc-12-base") {
		t.Errorf("gcc-12-base must not appear under AFFECTED:\n%s", out)
	}
}

func TestSectionsAppearInTriageOrder(t *testing.T) {
	out := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "a", Status: analyze.StatusNotPresent},
		analyze.Finding{CVE: "CVE-2", Package: "b", Status: analyze.StatusUndetermined},
		analyze.Finding{CVE: "CVE-3", Package: "c", Status: analyze.StatusLinked},
	)
	af, un, ru := strings.Index(out, "AFFECTED"), strings.Index(out, "UNDETERMINED"), strings.Index(out, "RULED OUT")
	if !(af < un && un < ru) {
		t.Errorf("sections out of order (affected %d, undetermined %d, ruled out %d):\n%s", af, un, ru, out)
	}
}

// A section nobody has findings for is not printed as an empty heading.
func TestEmptySectionsAreOmitted(t *testing.T) {
	out := report(t, false, analyze.Finding{CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked})
	if strings.Contains(out, "RULED OUT") || strings.Contains(out, "UNDETERMINED") {
		t.Errorf("empty sections printed:\n%s", out)
	}
}

// TestVerdictColumnOnlyAppearsWhenItSaysSomething: in a Debian image every
// affected finding is "linked", and a column repeating that on 152 rows is
// noise. A section holding more than one status gets the column.
func TestVerdictColumnOnlyAppearsWhenItSaysSomething(t *testing.T) {
	uniform := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked},
		analyze.Finding{CVE: "CVE-2", Package: "b", Status: analyze.StatusLinked},
	)
	if strings.Contains(uniform, "VERDICT") {
		t.Errorf("VERDICT column printed for a single-status section:\n%s", uniform)
	}

	mixed := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked},
		analyze.Finding{CVE: "CVE-2", Package: "b", Status: analyze.StatusReachable},
	)
	if !strings.Contains(mixed, "VERDICT") {
		t.Errorf("VERDICT column missing from a mixed section:\n%s", mixed)
	}
	if !strings.Contains(lineWith(t, mixed, "CVE-2"), string(analyze.StatusReachable)) {
		t.Errorf("the verdict is not on the row:\n%s", mixed)
	}
}

// TestUnknownSeveritySortsAboveMedium pins the one ordering choice that is not
// simply the severity scale. A rating nobody published must not be dismissible
// by scrolling past it.
func TestUnknownSeveritySortsAboveMedium(t *testing.T) {
	out := report(t, false,
		analyze.Finding{CVE: "CVE-LOW", Package: "a", Status: analyze.StatusLinked, Severity: "LOW"},
		analyze.Finding{CVE: "CVE-MED", Package: "b", Status: analyze.StatusLinked, Severity: "MEDIUM"},
		analyze.Finding{CVE: "CVE-UNK", Package: "c", Status: analyze.StatusLinked, Severity: "UNKNOWN"},
		analyze.Finding{CVE: "CVE-CRIT", Package: "d", Status: analyze.StatusLinked, Severity: "CRITICAL"},
		analyze.Finding{CVE: "CVE-HIGH", Package: "e", Status: analyze.StatusLinked, Severity: "HIGH"},
	)
	want := []string{"CVE-CRIT", "CVE-HIGH", "CVE-UNK", "CVE-MED", "CVE-LOW"}
	var got []string
	for _, l := range sectionOf(t, out, "AFFECTED")[1:] { // [1:] skips the header row
		got = append(got, strings.Fields(l)[1])
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("severity order = %v, want %v\n%s", got, want, out)
	}
}

// A finding whose advisory was never resolved has no severity at all, and must
// render as UNKNOWN rather than as a blank cell that sorts to the bottom. This
// is the Go repo-mode case.
func TestAnUnratedFindingRendersAsUnknown(t *testing.T) {
	out := report(t, false,
		analyze.Finding{CVE: "CVE-MED", Package: "a", Status: analyze.StatusLinked, Severity: "MEDIUM"},
		analyze.Finding{CVE: "CVE-NONE", Package: "b", Status: analyze.StatusLinked},
	)
	line := lineWith(t, out, "CVE-NONE")
	if !strings.HasPrefix(line, "UNKNOWN") {
		t.Errorf("an unrated finding did not render as UNKNOWN: %q", line)
	}
	if strings.Index(out, "CVE-NONE") > strings.Index(out, "CVE-MED") {
		t.Errorf("UNKNOWN sorted below MEDIUM:\n%s", out)
	}
}

// TestAdvisoryIdIsShortenedOnlyWhenItIsACVE: a distro prefix is dropped when
// what remains is a real CVE id, because that is the id a reader looks up and
// the one every other tool prints. Anything else is left exactly as it is.
func TestAdvisoryIdIsShortenedOnlyWhenItIsACVE(t *testing.T) {
	cases := []struct{ id, want string }{
		{"DEBIAN-CVE-2022-27943", "CVE-2022-27943"},
		{"UBUNTU-CVE-2023-45853", "CVE-2023-45853"},
		{"CVE-2023-45853", "CVE-2023-45853"},
		// Not a CVE and with no shorter spelling.
		{"DSA-5678-1", "DSA-5678-1"},
		{"GHSA-3jxr-9vmj-r5cp", "GHSA-3jxr-9vmj-r5cp"},
		{"GO-2023-2102", "GO-2023-2102"},
		{"RUSTSEC-2021-0093", "RUSTSEC-2021-0093"},
		// A prefix over something CVE-shaped but malformed stays whole.
		{"DEBIAN-CVE-22-1", "DEBIAN-CVE-22-1"},
	}
	for _, tc := range cases {
		got := shortAdvisory(analyze.Finding{CVE: tc.id})
		if got != tc.want {
			t.Errorf("shortAdvisory(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
	// The full id survives in --details even when the table shortens it.
	out := report(t, true, gccTrio[0])
	if !strings.Contains(out, "DEBIAN-CVE-2022-27943") {
		t.Errorf("--details lost the full OSV id:\n%s", out)
	}
}

// TestIncompleteBannersComeFirst: these are the "never silently report nothing"
// guarantee, and no amount of table below them may push them out of sight.
func TestIncompleteBannersComeFirst(t *testing.T) {
	out := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "npm", Error: "could not read /usr/lib/node_modules"},
		},
		Unreadable: &target.Unreadable{Count: 12, Paths: []string{"/opt/vendor", "/srv/data"}},
		Findings: []analyze.Finding{
			{CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "CRITICAL"},
		},
	}, false)

	banner := strings.Index(out, "INCOMPLETE: ecosystem npm did not run")
	paths := strings.Index(out, "INCOMPLETE: 12 path(s)")
	table := strings.Index(out, "AFFECTED")
	if banner < 0 || paths < 0 {
		t.Fatalf("a banner is missing:\n%s", out)
	}
	if banner > table || paths > table {
		t.Errorf("banners printed below the table:\n%s", out)
	}
	if !strings.Contains(out, "/opt/vendor") || !strings.Contains(out, "and 10 more") {
		t.Errorf("the unreadable paths are not accounted for:\n%s", out)
	}
	// The ecosystem that failed must not also be summarised as if it ran.
	if strings.Contains(out, "  npm      ") {
		t.Errorf("a failed ecosystem was summarised as a normal one:\n%s", out)
	}
}

// An empty report has to distinguish "nothing was wrong" from "nothing was
// read". Only one of them is good news.
func TestEmptyReportDistinguishesCleanFromIncomplete(t *testing.T) {
	clean := report(t, false)
	if !strings.Contains(clean, "No findings: nothing selected was found") {
		t.Errorf("clean empty report:\n%s", clean)
	}
	if strings.Contains(clean, "not a clean result") {
		t.Errorf("a clean report claimed to be incomplete:\n%s", clean)
	}

	incomplete := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{{ID: "os", Error: "no package database"}},
	}, false)
	if !strings.Contains(incomplete, "This is not a clean result.") {
		t.Errorf("an incomplete empty report reads as clean:\n%s", incomplete)
	}
}

// TestDetailsPrintsTheFullBlock covers the flag the per-finding blocks moved
// behind. Nothing was deleted, only moved -- plus the evidence and the plugin's
// own characterisation, which the text output never showed at all.
func TestDetailsPrintsTheFullBlock(t *testing.T) {
	yes := true
	f := analyze.Finding{
		Ecosystem: "golang", CVE: "CVE-2023-39325", ID: "CVE-2023-39325", GoID: "GO-2023-2102",
		Package: "golang.org/x/net", Module: "golang.org/x/net", Version: "v0.10.0",
		Binary: "/usr/bin/app", Location: "/usr/bin/app", Stripped: &yes,
		Packages: []string{"golang.org/x/net/http2"}, Granularity: "package",
		Status: analyze.StatusReachable, Method: "pclntab-live",
		Severity: "HIGH", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		Reachability: "linked (symbols retained; reachability not asserted)",
		Reason:       "govulncheck could not load the package",
		Evidence: []ecosystem.Evidence{
			{Origin: "pclntab", Detail: "http2.canonicalHeader retained"},
			{Origin: "dlopen", Detail: "reachable dlopen of a computed name", Blocking: true},
		},
		LLM: &llm.Verdict{Exploitable: "likely", Confidence: "medium", Rationale: "the server path is exposed"},
	}

	table := report(t, false, f)
	if strings.Contains(table, "pclntab-live\n  cve:") {
		t.Error("the detail block leaked into the default output")
	}
	if strings.Contains(table, "http2.canonicalHeader") {
		t.Errorf("evidence printed without --details:\n%s", table)
	}

	out := report(t, true, f)
	for _, want := range []string{
		"[REACHABLE]",
		"CVE-2023-39325 (GO-2023-2102)",
		"from:     golang",
		// The score and the vector, so a rating can be checked rather than
		// taken on trust.
		"severity: HIGH (7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
		"binary:   /usr/bin/app (stripped)",
		"packages: golang.org/x/net/http2 (package)",
		"method:   pclntab-live",
		"detail:   linked (symbols retained",
		"reason:   govulncheck could not load the package",
		"evidence: [pclntab] http2.canonicalHeader retained",
		// A blocking taint is why a finding could not be ruled out, and must
		// not read as one more supporting note.
		"evidence: [dlopen] (blocking) reachable dlopen",
		"llm:      exploitable=likely confidence=medium",
		"the server path is exposed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--details is missing %q:\n%s", want, out)
		}
	}
}

// The source package is shown in --details only where it differs from the
// installed one: it is what the advisory is filed against and what a reader
// will search for, but repeating the same name twice is noise.
func TestDetailsShowsTheSourcePackageOnlyWhenItDiffers(t *testing.T) {
	differs := report(t, true, gccTrio[1])
	if !strings.Contains(differs, "source:   gcc-12") {
		t.Errorf("the source package is missing:\n%s", differs)
	}

	same := report(t, true, analyze.Finding{
		CVE: "CVE-1", Package: "zlib1g", Module: "zlib1g", Version: "1.0",
		PURL: "pkg:deb/debian/zlib1g@1.0", Status: analyze.StatusLinked,
	})
	if strings.Contains(same, "source:") {
		t.Errorf("the source package was repeated:\n%s", same)
	}
}

// TestTableRowsAreGreppable: no trailing whitespace, two spaces between
// columns, and columns that line up. These reports get cut, grepped and diffed.
func TestTableRowsAreGreppable(t *testing.T) {
	out := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "short", Version: "1.0", Status: analyze.StatusLinked, Severity: "HIGH", Method: "m"},
		analyze.Finding{CVE: "CVE-2", Package: "a-much-longer-package-name", Version: "2.0", Status: analyze.StatusLinked, Severity: "HIGH", Method: "m"},
	)
	for _, l := range strings.Split(out, "\n") {
		if l != strings.TrimRight(l, " \t") {
			t.Errorf("line has trailing whitespace: %q", l)
		}
	}
	// The BASIS column starts at the same offset on every row of the section.
	rows := sectionOf(t, out, "AFFECTED")
	want := strings.Index(rows[0], "BASIS")
	for _, r := range rows[1:] {
		if got := strings.LastIndex(r, "m"); got != want {
			t.Errorf("column not aligned: header at %d, row %q has it at %d", want, r, got)
		}
	}
}

// A pathological name must not widen every row in the table.
func TestLongCellsAreTruncated(t *testing.T) {
	long := strings.Repeat("x", 200)
	out := report(t, false, analyze.Finding{
		CVE: "CVE-1", Package: long, Version: "1.0", Status: analyze.StatusLinked,
	})
	for _, l := range strings.Split(out, "\n") {
		if len([]rune(l)) > 120 {
			t.Errorf("line is %d runes: %q", len([]rune(l)), l)
		}
	}
	if !strings.Contains(out, "…") {
		t.Errorf("truncation is not marked:\n%s", out)
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly-10", 10, "exactly-10"},
		{"eleven-char", 10, "eleven-ch…"},
		{"", 5, ""},
		{"ab", 1, "a"},
		// Counted in runes, not bytes: a multibyte name must not be cut mid
		// character.
		{"日本語のパッケージ", 4, "日本語…"},
	}
	for _, tc := range cases {
		if got := truncate(tc.in, tc.max); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

// An id that matched nothing in the target has no component at all, and
// printing "@" for it would look like a name that failed to render.
func TestComponentWithNothingMatched(t *testing.T) {
	if got := component(analyze.Finding{CVE: "CVE-1"}); got != "(no matching component)" {
		t.Errorf("component() = %q", got)
	}
	if got := component(analyze.Finding{Package: "zlib1g"}); got != "zlib1g" {
		t.Errorf("component() = %q", got)
	}
	// The binary package name, not the source package, and with the version.
	got := component(analyze.Finding{
		Package: "gcc-12", Version: "12.2.0", PURL: "pkg:deb/debian/libgcc-s1@12.2.0",
	})
	if got != "libgcc-s1@12.2.0" {
		t.Errorf("component() = %q, want the binary package", got)
	}
}

// The summary counts what a reader is deciding about: the affected rows.
func TestSummaryCountsAffectedBySeverity(t *testing.T) {
	out := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "os", Ecosystems: []string{"Debian:12"}, Components: 88},
		},
		Findings: []analyze.Finding{
			{Ecosystem: "os", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "CRITICAL"},
			{Ecosystem: "os", CVE: "CVE-2", Package: "b", Status: analyze.StatusLinked, Severity: "CRITICAL"},
			{Ecosystem: "os", CVE: "CVE-3", Package: "c", Status: analyze.StatusLinked, Severity: "LOW"},
			// Ruled out, so not part of what has to be acted on.
			{Ecosystem: "os", CVE: "CVE-4", Package: "d", Status: analyze.StatusNotPresent, Severity: "CRITICAL"},
		},
	}, false)

	if !strings.Contains(out, "affected by severity: 2 critical, 1 low") {
		t.Errorf("severity spread wrong:\n%s", out)
	}
	if !strings.Contains(out, "88 components") || !strings.Contains(out, "4 findings") {
		t.Errorf("per-ecosystem summary wrong:\n%s", out)
	}
	// The OSV ecosystem is printed next to the plugin id, because "Debian:12" is
	// what a reader checks before trusting the rows under it.
	if !strings.Contains(out, "os       Debian:12") {
		t.Errorf("the OSV ecosystem is missing from the summary:\n%s", out)
	}
}

// A plugin whose ecosystem is just its own name is not worth saying twice.
func TestSummaryDoesNotRepeatTheEcosystemName(t *testing.T) {
	out := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "node:22-slim", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "npm", Ecosystems: []string{"npm"}, Components: 186},
		},
		Findings: []analyze.Finding{
			{Ecosystem: "npm", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked},
		},
	}, false)
	if strings.Contains(out, "npm      npm") {
		t.Errorf("the ecosystem name is repeated:\n%s", out)
	}
	if !strings.Contains(out, "186 components") {
		t.Errorf("the summary line is missing:\n%s", out)
	}
}
