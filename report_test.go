package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/ecosystem/ospkg"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/target"
	"github.com/cwayne18/vexscan/internal/triage"
)

// report renders a result from a bare list of findings.
func report(t *testing.T, details bool, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "debian:12",
		Mode:          "image",
		Findings:      findings,
	}, renderOpts{details: details})
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
	}, renderOpts{})

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
	}, renderOpts{})
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

// The FIXED IN column earns its place only when a section has a fix to show,
// and a row with none reads "no fix" rather than blank.
func TestFixedInColumnAppearsOnlyWithData(t *testing.T) {
	// No finding has a fix: the column must not appear at all.
	none := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "a", Version: "1.0", Status: analyze.StatusLinked, Severity: "HIGH", Method: "m"},
	)
	if strings.Contains(none, "FIXED IN") {
		t.Errorf("FIXED IN column appeared with nothing to put in it:\n%s", none)
	}

	// One finding has a fix and one does not: the column appears, and the
	// unfixed row reads "no fix".
	some := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "a", Version: "1.0", Status: analyze.StatusLinked, Severity: "HIGH", Method: "m", FixedVersion: "1.1"},
		analyze.Finding{CVE: "CVE-2", Package: "b", Version: "2.0", Status: analyze.StatusLinked, Severity: "HIGH", Method: "m"},
	)
	rows := sectionOf(t, some, "AFFECTED")
	if !strings.Contains(rows[0], "FIXED IN") {
		t.Fatalf("FIXED IN header missing:\n%s", some)
	}
	if !strings.Contains(lineWith(t, some, "CVE-1"), "1.1") {
		t.Errorf("fixed version missing from the CVE-1 row:\n%s", some)
	}
	if !strings.Contains(lineWith(t, some, "CVE-2"), "no fix") {
		t.Errorf("an unfixed row should read \"no fix\":\n%s", some)
	}
}

// The LOCATION column names the specific binary a linked finding lives in. One
// module can be linked into several binaries at the same version, so without it
// those rows are identical. An OS scan sets no binary, so the column must not
// appear there.
func TestLocationColumnNamesTheBinaryForGoFindings(t *testing.T) {
	// Two Go findings, same module and version, different binaries: the column
	// appears and tells the rows apart.
	go2 := report(t, false,
		analyze.Finding{
			CVE: "CVE-1", Package: "golang.org/x/net", Version: "0.1.0",
			Binary: "usr/bin/api", Location: "usr/bin/api",
			Status: analyze.StatusLinked, Severity: "HIGH", Method: "govulncheck",
		},
		analyze.Finding{
			CVE: "CVE-1", Package: "golang.org/x/net", Version: "0.1.0",
			Binary: "usr/bin/worker", Location: "usr/bin/worker",
			Status: analyze.StatusLinked, Severity: "HIGH", Method: "govulncheck",
		},
	)
	rows := sectionOf(t, go2, "AFFECTED")
	if !strings.Contains(rows[0], "LOCATION") {
		t.Fatalf("LOCATION header missing:\n%s", go2)
	}
	if !strings.Contains(lineWith(t, go2, "usr/bin/api"), "usr/bin/api") ||
		!strings.Contains(lineWith(t, go2, "usr/bin/worker"), "usr/bin/worker") {
		t.Errorf("each binary should identify its own row:\n%s", go2)
	}

	// An OS finding has no binary: the column must not appear.
	os := report(t, false,
		analyze.Finding{CVE: "CVE-2", Package: "libc6", Version: "2.36", Status: analyze.StatusLinked, Severity: "HIGH", Method: "elf-needed-closure"},
	)
	if strings.Contains(os, "LOCATION") {
		t.Errorf("LOCATION column appeared for an OS scan that sets no binary:\n%s", os)
	}
}

// maxTableWidth is how wide a default findings row may print.
//
// Not a style rule. The pager wraps rather than chops (see pager.go), so a row
// past the terminal folds onto a second line and the alignment that makes the
// table legible is gone -- the report looks broken. v0.8.1 added LOCATION at
// the same 40 the other columns carried, took the Go table from 143 columns to
// 180, and nothing here noticed, because the banked regression scan is
// debian:12 and an OS scan sets no Location so the column never appeared.
//
// The number is the sum of the column budgets plus the fixed columns and their
// gaps, rounded up. It is a ceiling to be argued with, not a target: raising it
// is a decision to make a table that fits fewer terminals, and the point of the
// test is that the decision gets made rather than discovered in a release.
const maxTableWidth = 155

func TestAFindingsRowFitsATerminal(t *testing.T) {
	// Every budgeted cell over its cap and every optional column switched on,
	// so the row prints at the full width the budgets allow.
	wide := func(cve, bin string) analyze.Finding {
		return analyze.Finding{
			CVE: cve, ID: cve,
			Package:      "github.com/kube-logging/logging-operator/pkg/resources",
			Version:      "v0.0.0-20250424202944-7e1f9d3a1c2b4e5f6a7b8c9d",
			Binary:       bin,
			Location:     "var/lib/rancher/k3s/agent/containerd/state/bin/" + bin,
			FixedVersion: "0.0.0-20260608145523-cf437db9e1a2b3c4d5e6f7a8",
			Status:       analyze.StatusLinked, Severity: "CRITICAL",
			Method: "elf-needed-closure",
		}
	}
	// Two binaries so LOCATION earns its place; FIXED IN comes with the fix.
	out := report(t, false, wide("CVE-1", "docker-machine-driver-harvester"), wide("CVE-2", "docker-machine-driver-linode"))

	header := sectionOf(t, out, "AFFECTED")[0]
	for _, col := range []string{"LOCATION", "FIXED IN"} {
		if !strings.Contains(header, col) {
			t.Fatalf("%s column missing, so this is not the widest shape:\n%s", col, header)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		// Runes, not bytes: the truncation ellipsis is three bytes wide and one
		// column, and counting bytes would fail a row that fits perfectly well.
		if w := len([]rune(line)); w > maxTableWidth {
			t.Errorf("row is %d columns, over the %d budget -- it will wrap in a pager:\n%s",
				w, maxTableWidth, line)
		}
	}
}

// An advisory that patched three maintained branches offers three upgrades,
// and only one of them is the small one. The table still names a single target
// -- a cell holding three versions is not scannable -- so --details is where
// the alternatives have to be said, or the pick reads as the only option.
func TestDetailsDiscloseTheFixesNotChosen(t *testing.T) {
	f := analyze.Finding{
		CVE: "CVE-1", ID: "CVE-1", Package: "github.com/hashicorp/vault",
		Version: "1.5.4", Status: analyze.StatusLinked, Severity: "HIGH", Method: "m",
		FixedVersion:  "1.5.9",
		FixedVersions: []string{"1.5.9", "1.6.5", "1.7.2"},
	}
	out := report(t, true, f)
	line := lineWith(t, out, "fixed in:")
	if !strings.Contains(line, "1.5.9 (also fixed in 1.6.5, 1.7.2)") {
		t.Errorf("the branches not chosen were not disclosed:\n%s", line)
	}
	// The table is unchanged: one target per row.
	if row := lineWith(t, out, "CVE-1  "); strings.Contains(row, "1.6.5") {
		t.Errorf("the alternatives leaked into the table:\n%s", row)
	}

	// The ordinary single-fix row says nothing extra.
	f.FixedVersions = nil
	if line := lineWith(t, report(t, true, f), "fixed in:"); strings.Contains(line, "also fixed in") {
		t.Errorf("a lone fix was presented as a choice:\n%s", line)
	}
}

// The summary reports how many affected rows are fixable and how many distinct
// advisories they are, which is what the wall of rows hides.
func TestRemediationSummary(t *testing.T) {
	out := report(t, false,
		// One advisory seen on two packages: two rows, one advisory, both fixable.
		analyze.Finding{CVE: "CVE-1", Package: "a", Version: "1.0", Status: analyze.StatusLinked, Severity: "HIGH", FixedVersion: "1.1"},
		analyze.Finding{CVE: "CVE-1", Package: "b", Version: "1.0", Status: analyze.StatusLinked, Severity: "HIGH", FixedVersion: "1.1"},
		// A third row nobody has patched yet.
		analyze.Finding{CVE: "CVE-2", Package: "c", Version: "2.0", Status: analyze.StatusLinked, Severity: "HIGH"},
	)
	line := lineWith(t, out, "affected:")
	for _, want := range []string{"3 affected", "2 unique advisories", "2 fixable", "1 with no fix yet"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary line %q missing %q", line, want)
		}
	}
}

// With no fix data anywhere the clause is still printed, because "nothing here
// is fixable" is the measurement a reader most wants confirmed and a silent
// summary reads as a missing one. It just never phrases it as "0 fixable".
func TestRemediationSummaryStatesTheZeroWithoutSayingZeroFixable(t *testing.T) {
	out := report(t, false,
		analyze.Finding{CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "HIGH"},
		analyze.Finding{CVE: "CVE-2", Package: "b", Status: analyze.StatusLinked, Severity: "HIGH"},
	)
	line := lineWith(t, out, "affected:")
	if !strings.Contains(line, "2 with no fix yet") {
		t.Errorf("the measured zero went unsaid: %q", line)
	}
	if strings.Contains(line, "fixable") {
		t.Errorf("phrased as a count of fixables: %q", line)
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
	}, renderOpts{})

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
	}, renderOpts{})
	if strings.Contains(out, "npm      npm") {
		t.Errorf("the ecosystem name is repeated:\n%s", out)
	}
	if !strings.Contains(out, "186 components") {
		t.Errorf("the summary line is missing:\n%s", out)
	}
}

// --vexhub

// vexed is the gcc trio's libgcc-s1 row with a vendor statement attached: a
// linked finding somebody has already published an answer to.
func vexedFinding(status string) analyze.Finding {
	f := gccTrio[1]
	f.VEX = &ecosystem.VEXStatement{
		Status:          status,
		Justification:   "vulnerable_code_not_in_execute_path",
		ImpactStatement: "The image authenticates via certificates, so the PAM path is never entered.",
		Author:          "Rancher Security team",
		Timestamp:       "2026-06-19T00:00:00Z",
		Product:         "pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes",
		Hub:             "https://github.com/rancher/vexhub",
	}
	return f
}

func vexReport(t *testing.T, details bool, hubs []ecosystem.VEXHubResult, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "rancher/hardened-kubernetes:v1.30.1", Mode: "image",
		Findings: findings, VEXHubs: hubs,
	}, renderOpts{details: details})
}

// An exculpatory statement moves the row; the finding's own verdict does not
// change, so the same scan rendered without a hub says exactly the same thing
// about it.
func TestAnExculpatoryStatementMovesTheRowOutOfAffected(t *testing.T) {
	for _, status := range []string{"not_affected", "fixed"} {
		out := vexReport(t, false, nil, vexedFinding(status))
		vexed := strings.Join(sectionOf(t, out, "ALREADY VEXED"), "\n")
		if !strings.Contains(vexed, "libgcc-s1") {
			t.Errorf("%s: the row is not under ALREADY VEXED:\n%s", status, out)
		}
		if !strings.Contains(vexed, status) {
			t.Errorf("%s: the vendor status is not shown:\n%s", status, out)
		}
		if strings.Contains(out, "AFFECTED (") {
			t.Errorf("%s: an AFFECTED section was printed with nothing in it:\n%s", status, out)
		}
	}
}

// The one mistake this must not make: a vendor confirming a finding, or saying
// they are still looking, cannot make it quieter.
func TestANonExculpatoryStatementLeavesTheRowAffected(t *testing.T) {
	for _, status := range []string{"affected", "under_investigation", ""} {
		out := vexReport(t, false, nil, vexedFinding(status))
		affected := strings.Join(sectionOf(t, out, "AFFECTED"), "\n")
		if !strings.Contains(affected, "libgcc-s1") {
			t.Errorf("%s: the row left AFFECTED:\n%s", status, out)
		}
		if strings.Contains(out, "ALREADY VEXED (") {
			t.Errorf("%s: an ALREADY VEXED section was printed:\n%s", status, out)
		}
	}
}

// Nothing changes for a reader who did not pass --vexhub.
func TestTheVexedSectionIsAbsentWithoutAHub(t *testing.T) {
	out := report(t, false, gccTrio...)
	if strings.Contains(out, "ALREADY VEXED") || strings.Contains(out, "already vexed") {
		t.Errorf("a plain scan mentions VEX:\n%s", out)
	}
}

// The affected count is what is still open, and the reader is told whose word
// the rest moved on.
func TestSummaryExcludesVexedRowsAndNamesTheAuthor(t *testing.T) {
	hubs := []ecosystem.VEXHubResult{{
		URL: "https://github.com/rancher/vexhub", Author: "Rancher Security team",
		Products: 1082, Matched: 1,
	}}
	out := vexReport(t, false, hubs, vexedFinding("not_affected"), gccTrio[2])

	sev := lineWith(t, out, "affected by severity:")
	if !strings.Contains(sev, "1 medium") {
		t.Errorf("the vexed row is still counted as affected: %q", sev)
	}
	line := lineWith(t, out, "already vexed:")
	if !strings.Contains(line, "1 by Rancher Security team") {
		t.Errorf("the summary does not say who vexed it: %q", line)
	}
}

// A hub that could not be read is not silent, and is not an INCOMPLETE banner
// either: the scan is complete, the grouping is what was lost.
func TestAnUnreachableHubWarnsWithoutClaimingTheScanIsIncomplete(t *testing.T) {
	hubs := []ecosystem.VEXHubResult{{
		URL:   "https://invalid.example/nope",
		Error: "vex: read index: no such host",
	}}
	out := vexReport(t, false, hubs, gccTrio...)

	note := lineWith(t, out, "https://invalid.example/nope")
	if !strings.HasPrefix(note, "NOTE:") {
		t.Errorf("the hub warning is not a NOTE: %q", note)
	}
	if strings.Contains(out, "INCOMPLETE") {
		t.Errorf("an unreachable hub was reported as an incomplete scan:\n%s", out)
	}
	// Nothing moved, so every linked row is still where a reader will look.
	affected := strings.Join(sectionOf(t, out, "AFFECTED"), "\n")
	if !strings.Contains(affected, "libgcc-s1") {
		t.Errorf("a row moved despite the hub failing:\n%s", out)
	}
}

// The vendor's own sentence is the most useful thing in the document, and the
// table has no room for it.
func TestDetailsPrintsTheVendorStatement(t *testing.T) {
	out := vexReport(t, true, nil, vexedFinding("not_affected"))
	for _, want := range []string{
		"Rancher Security team says not_affected",
		"vulnerable_code_not_in_execute_path",
		"The image authenticates via certificates",
		"pkg:oci/hardened-kubernetes",
		"2026-06-19T00:00:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--details is missing %q:\n%s", want, out)
		}
	}
}

// A match that tolerated a different purl spelling says so, because that
// tolerance is the part a reader might disagree with.
func TestDetailsRecordsALooseComponentMatch(t *testing.T) {
	f := vexedFinding("not_affected")
	f.VEX.Match = "statement names pkg:rpm/suse/libgcrypt20; component is pkg:rpm/sles/libgcrypt20@1.9.4?arch=x86_64"
	out := vexReport(t, true, nil, f)
	if !strings.Contains(out, "matched loosely: statement names pkg:rpm/suse/libgcrypt20") {
		t.Errorf("the tolerated disagreement is not shown:\n%s", out)
	}
}

// The section swaps BASIS -- how vexscan decided, which is not what these rows
// are here for -- for what the vendor said.
func TestTheVexedSectionShowsTheVendorColumnsInsteadOfBasis(t *testing.T) {
	out := vexReport(t, false, nil, vexedFinding("not_affected"))
	header := sectionOf(t, out, "ALREADY VEXED")[0]
	if !strings.Contains(header, "VEX STATUS") || !strings.Contains(header, "JUSTIFICATION") {
		t.Errorf("the vendor columns are missing: %q", header)
	}
	if strings.Contains(header, "BASIS") {
		t.Errorf("BASIS is still in the vexed section: %q", header)
	}
}

// A "fixed" statement needs no justification, so the column falls back to the
// vendor's sentence rather than rendering an empty cell.
func TestTheJustificationColumnFallsBackToTheImpactStatement(t *testing.T) {
	f := vexedFinding("fixed")
	f.VEX.Justification = ""
	out := vexReport(t, false, nil, f)
	if !strings.Contains(out, "The image authenticates via certificates") {
		t.Errorf("the justification cell is empty:\n%s", out)
	}
}

// A vexed row that is only vexed because a hub matched must not survive a
// status it never had: only linked and reachable findings can move at all.
func TestOnlyAffectedFindingsCanBeVexed(t *testing.T) {
	f := gccTrio[0] // not_present
	f.VEX = &ecosystem.VEXStatement{Status: "not_affected", Author: "Someone"}
	out := vexReport(t, false, nil, f)
	if strings.Contains(out, "ALREADY VEXED") {
		t.Errorf("a ruled-out finding was moved into ALREADY VEXED:\n%s", out)
	}
	if !strings.Contains(strings.Join(sectionOf(t, out, "RULED OUT"), "\n"), "gcc-12-base") {
		t.Errorf("the ruled-out row left its section:\n%s", out)
	}
}

// --severity: the renderer's whole job here is to make sure a filtered report
// can never be mistaken for a clean one.

func filteredReport(t *testing.T, w *analyze.Withheld, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Findings: findings, Withheld: w,
	}, renderOpts{})
}

func TestTheBannerSaysWhatTheFilterHid(t *testing.T) {
	out := filteredReport(t, &analyze.Withheld{
		Severities: []string{"CRITICAL", "HIGH"},
		Count:      118,
		BySeverity: map[string]int{"MEDIUM": 73, "LOW": 9, "UNKNOWN": 36},
	}, gccTrio[1])

	note := lineWith(t, out, "withheld")
	for _, want := range []string{"NOTE:", "--severity CRITICAL,HIGH", "118 of 119"} {
		if !strings.Contains(note, want) {
			t.Errorf("banner %q is missing %q", note, want)
		}
	}
	// Rank order, not map order, so the line reads the same way the summary does.
	spread := lineWith(t, out, "no rating was published")
	if got := strings.TrimSpace(spread); got != "36 unknown (no rating was published), 73 medium, 9 low" {
		t.Errorf("spread = %q", got)
	}
}

// The gloss is the sentence that keeps this honest: 36 unrated findings must
// not disappear behind a number that reads like low-priority noise.
func TestTheUnratedGlossOnlyAppearsWhenUnratedRowsWereHidden(t *testing.T) {
	out := filteredReport(t, &analyze.Withheld{
		Severities: []string{"CRITICAL", "HIGH", "UNKNOWN"},
		Count:      82,
		BySeverity: map[string]int{"MEDIUM": 73, "LOW": 9},
	}, gccTrio[1])
	if strings.Contains(out, "no rating was published") {
		t.Errorf("glossed a spread with no unrated rows in it:\n%s", out)
	}
	if !strings.Contains(out, "73 medium, 9 low") {
		t.Errorf("want the plain spread, got:\n%s", out)
	}
}

func TestNoBannerWithoutTheFlag(t *testing.T) {
	out := report(t, false, gccTrio...)
	for _, unwanted := range []string{"--severity", "withheld"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("an unfiltered report mentions %q:\n%s", unwanted, out)
		}
	}
}

// The --repo case, and the one this feature could most easily have got wrong:
// govulncheck publishes no severity, so --severity HIGH hides every Go finding
// there is. Printing the ordinary "no findings" line would be a clean bill of
// health for a scan that found twelve things.
func TestFilteringEverythingIsNotACleanResult(t *testing.T) {
	out := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "github.com/cwayne18/vexscan", Mode: "repo",
		Withheld: &analyze.Withheld{
			Severities: []string{"HIGH", "CRITICAL"},
			Count:      12,
			BySeverity: map[string]int{"UNKNOWN": 12},
		},
	}, renderOpts{})

	for _, want := range []string{
		"No findings at these severities.",
		"--severity HIGH,CRITICAL withheld all 12 finding(s)",
		"12 unknown (no rating was published)",
		"This is a filtered view, not a clean result.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The wording for an incomplete scan is a different and stronger claim, and
	// must not be borrowed for a filter the reader asked for.
	if strings.Contains(out, "the scan was incomplete") {
		t.Errorf("a filtered report claims the scan was incomplete:\n%s", out)
	}
}

// A genuinely clean scan still reads as clean. The filter's wording only
// applies when the filter is what emptied the report.
func TestAnEmptyUnfilteredReportIsUnchanged(t *testing.T) {
	out := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
	}, renderOpts{})
	if !strings.Contains(out, "No findings: nothing selected was found") {
		t.Errorf("want the plain empty wording, got:\n%s", out)
	}
	if strings.Contains(out, "filtered view") {
		t.Errorf("an unfiltered empty report claims to be filtered:\n%s", out)
	}
}

// An incomplete scan outranks a filter: the reader needs to know the tool could
// not read something before they are told what they chose to hide.
func TestIncompletenessOutranksTheFilterWhenBothEmptyTheReport(t *testing.T) {
	out := renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{{ID: "os", Error: "dpkg status unreadable"}},
		Withheld:   &analyze.Withheld{Severities: []string{"HIGH"}, Count: 3, BySeverity: map[string]int{"LOW": 3}},
	}, renderOpts{})
	if !strings.Contains(out, "This is not a clean result.") {
		t.Errorf("want the incomplete-scan wording, got:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE: ecosystem os") {
		t.Errorf("want the INCOMPLETE banner, got:\n%s", out)
	}
}

// The summary counts rows that are in the report, and the banner accounts for
// the rest -- the two lines have to add up.
func TestTheSummaryCountsOnlyWhatSurvivedTheFilter(t *testing.T) {
	out := filteredReport(t, &analyze.Withheld{
		Severities: []string{"MEDIUM"}, Count: 4, BySeverity: map[string]int{"LOW": 4},
	}, gccTrio...)
	if got := lineWith(t, out, "affected by severity"); !strings.Contains(got, "2 medium") {
		t.Errorf("summary = %q, want only the two linked rows", got)
	}
	if !strings.Contains(lineWith(t, out, "withheld"), "4 of 7") {
		t.Errorf("banner does not account for the difference:\n%s", out)
	}
}

// The footer: what a reader has scrolled past by the time they reach the
// bottom of 172 lines.

// longReport renders n affected findings, which is the only way to get a report
// past footerThreshold.
func longReport(t *testing.T, n int, mutate func(*analyze.Result)) string {
	t.Helper()
	findings := make([]analyze.Finding, 0, n)
	for i := range n {
		findings = append(findings, analyze.Finding{
			Ecosystem: "os",
			CVE:       fmt.Sprintf("CVE-2024-%04d", i),
			ID:        fmt.Sprintf("CVE-2024-%04d", i),
			Package:   "libc6", Module: "libc6", Version: "2.36-9",
			PURL:     "pkg:deb/debian/libc6@2.36-9?arch=amd64",
			Status:   analyze.StatusLinked,
			Method:   "elf-needed-closure",
			Severity: "HIGH",
		})
	}
	res := &analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "os", Ecosystems: []string{"Debian:12"}, Components: 88},
		},
		Findings: findings,
	}
	if mutate != nil {
		mutate(res)
	}
	return renderText(res, renderOpts{})
}

func TestAShortReportHasNoFooter(t *testing.T) {
	out := longReport(t, 5, nil)
	if n := strings.Count(out, "\n"); n > footerThreshold {
		t.Fatalf("this test needs a report under the threshold; it is %d lines", n)
	}
	if got := strings.Count(out, "affected by severity"); got != 1 {
		t.Errorf("summary appears %d times in a short report, want 1:\n%s", got, out)
	}
}

func TestALongReportRepeatsTheSummaryAtTheBottom(t *testing.T) {
	out := longReport(t, 60, nil)
	if n := strings.Count(out, "\n"); n <= footerThreshold {
		t.Fatalf("this test needs a report over the threshold; it is %d lines", n)
	}

	// Twice, and identically: the reader who scrolled to the bottom is owed the
	// same numbers as the one who caught the top.
	var spreads []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "affected by severity") {
			spreads = append(spreads, l)
		}
	}
	if len(spreads) != 2 {
		t.Fatalf("want the severity spread at both ends, got %d:\n%s", len(spreads), out)
	}
	if spreads[0] != spreads[1] {
		t.Errorf("header says %q but footer says %q", spreads[0], spreads[1])
	}
	if !strings.Contains(spreads[0], "60 high") {
		t.Errorf("spread = %q, want 60 high", spreads[0])
	}
}

// The footer is the last thing in the report. A summary with rows under it
// would be a heading, not a footer.
func TestTheFooterIsLast(t *testing.T) {
	out := longReport(t, 60, nil)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// The section index is the footer's final line: nothing prints beneath it.
	if last := lines[len(lines)-1]; !strings.Contains(last, "findings in") {
		t.Errorf("last line is %q, want the section index", last)
	}
	// The whole summary repeats in the footer above that line -- the ecosystem
	// header, the severity spread and the index. The block is sized from the
	// summary rather than a fixed count so an added summary line (the
	// remediation line, say) does not read as rows escaping below the footer.
	footer := strings.Join(lines[len(lines)-5:], "\n")
	for _, want := range []string{"88 components", "affected by severity", "findings in"} {
		if !strings.Contains(footer, want) {
			t.Errorf("footer is missing %q:\n%s", want, footer)
		}
	}
}

func TestTheSectionIndexAgreesWithTheHeadings(t *testing.T) {
	out := longReport(t, 60, func(res *analyze.Result) {
		res.Findings = append(res.Findings, gccTrio[0]) // one not_present row
	})
	index := lineWith(t, out, "findings in")
	for _, want := range []string{"61 findings in 2 section(s)", "AFFECTED (60)", "RULED OUT (1)"} {
		if !strings.Contains(index, want) {
			t.Errorf("index %q is missing %q", index, want)
		}
	}
	// Every heading it names has to exist, with the count it claims.
	for _, heading := range []string{"AFFECTED (60)", "RULED OUT (1)"} {
		if !strings.Contains(out, heading+" -") {
			t.Errorf("index names %q but the report has no such heading", heading)
		}
	}
}

// The reason the footer repeats the caveats and not just the counts: an
// INCOMPLETE banner 154 rows above the reader's eyes is one they never saw.
func TestALongReportRepeatsTheIncompleteBanner(t *testing.T) {
	out := longReport(t, 60, func(res *analyze.Result) {
		res.Ecosystems = append(res.Ecosystems,
			ecosystem.EcosystemResult{ID: "golang", Error: "no go binaries could be read"})
	})
	if got := strings.Count(out, "INCOMPLETE: ecosystem golang"); got != 2 {
		t.Errorf("INCOMPLETE banner appears %d times, want 2 (both ends):\n%s", got, out)
	}
}

func TestALongReportRepeatsTheWithheldNote(t *testing.T) {
	out := longReport(t, 60, func(res *analyze.Result) {
		res.Withheld = &analyze.Withheld{
			Severities: []string{"HIGH"}, Count: 40,
			BySeverity: map[string]int{"MEDIUM": 40},
		}
	})
	if got := strings.Count(out, "--severity HIGH withheld 40 of 100"); got != 2 {
		t.Errorf("withheld note appears %d times, want 2 (both ends):\n%s", got, out)
	}
}

// An unreachable hub is the third caveat, and it must not be the one that gets
// forgotten -- a hub that contributed nothing looks exactly like one with
// nothing to say.
func TestALongReportRepeatsTheVexHubNote(t *testing.T) {
	out := longReport(t, 60, func(res *analyze.Result) {
		res.VEXHubs = []ecosystem.VEXHubResult{
			{URL: "https://github.com/rancher/vexhub", Error: "dial tcp: lookup failed"},
		}
	})
	if got := strings.Count(out, "NOTE: VEX hub"); got != 2 {
		t.Errorf("hub note appears %d times, want 2 (both ends):\n%s", got, out)
	}
}

// A correction is the one caveat about something this tool removed rather than
// something it lost, so it is the one that must never be quiet.

func correctedReport(t *testing.T, c *analyze.Corrections, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "rancher/rancher:v2.15.0", Mode: "image",
		Findings: findings, Corrections: c,
	}, renderOpts{})
}

func TestCorrectionsAreNamedNotJustCounted(t *testing.T) {
	out := correctedReport(t, &analyze.Corrections{
		Count:      2,
		Advisories: []string{"GO-2025-3625", "GO-2025-3711"},
		Details: []string{
			"GO-2025-3625 does not apply to github.com/rancher/rancher@v2.15.0 (the record's own ranges are 2.10.0-2.10.11)",
			"GO-2025-3711 does not apply to github.com/rancher/rancher@v2.15.0 (the record's own ranges are 2.11.0-2.11.13)",
		},
	}, gccTrio[1])

	if !strings.Contains(out, "NOTE: 2 advisory match(es) were not reported") {
		t.Errorf("no correction banner in:\n%s", out)
	}
	// The ids are the point: the drop is a claim, and a reader who doubts it has
	// to be able to go and check the record.
	for _, want := range []string{"GO-2025-3625", "GO-2025-3711", "2.10.0-2.10.11"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// The case the caveat exists for. Every advisory was corrected away, so the
// report is empty -- and an empty report that does not say this is the tool
// claiming a clean image it never established.
func TestCorrectionsAreStatedEvenWithNoFindings(t *testing.T) {
	out := correctedReport(t, &analyze.Corrections{
		Count:      1,
		Advisories: []string{"GO-2025-3625"},
		Details:    []string{"GO-2025-3625 does not apply to github.com/rancher/rancher@v2.15.0 (the record's own ranges are 2.10.0-2.10.11)"},
	})
	if !strings.Contains(out, "GO-2025-3625") {
		t.Errorf("an empty report dropped its correction note:\n%s", out)
	}
}

func TestNoCorrectionNoteWithoutCorrections(t *testing.T) {
	out := report(t, false, gccTrio...)
	if strings.Contains(out, "were not reported") {
		t.Errorf("an uncorrected report mentions corrections:\n%s", out)
	}
}

// Enough of them to bury the findings, so the list is capped -- but the number
// hidden is still stated, because a truncated caveat that reads as complete is
// the failure this whole feature is guarding against.
func TestALongCorrectionListIsCappedButCounted(t *testing.T) {
	c := &analyze.Corrections{Count: 26}
	for i := range 26 {
		id := fmt.Sprintf("GO-2025-%04d", i)
		c.Advisories = append(c.Advisories, id)
		c.Details = append(c.Details, id+" does not apply to github.com/rancher/rancher@v2.15.0 (the record's own ranges are 2.10.0-2.10.11)")
	}
	out := correctedReport(t, c, gccTrio[1])

	if !strings.Contains(out, "... and 6 more") {
		t.Errorf("no truncation count in:\n%s", out)
	}
	if strings.Contains(out, "GO-2025-0020") {
		t.Errorf("the list was not capped:\n%s", out)
	}
	if !strings.Contains(out, "NOTE: 26 advisory match(es) were not reported") {
		t.Errorf("the full count must still be stated:\n%s", out)
	}
}

func TestALongReportRepeatsTheCorrectionNote(t *testing.T) {
	out := longReport(t, 60, func(res *analyze.Result) {
		res.Corrections = &analyze.Corrections{
			Count:      1,
			Advisories: []string{"GO-2025-3625"},
			Details:    []string{"GO-2025-3625 does not apply to github.com/rancher/rancher@v2.15.0 (the record's own ranges are 2.10.0-2.10.11)"},
		}
	})
	if got := strings.Count(out, "advisory match(es) were not reported"); got != 2 {
		t.Errorf("correction note appears %d times, want 2 (both ends):\n%s", got, out)
	}
}

// Paging must never be able to change a byte, so the renderer cannot know
// whether it is talking to a terminal. This is the regression test for that:
// the same result renders identically however it is consumed.
func TestRenderingDoesNotDependOnTheEnvironment(t *testing.T) {
	first := longReport(t, 60, nil)
	t.Setenv("VEXSCAN_PAGER", "less -S")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("COLUMNS", "40")
	if second := longReport(t, 60, nil); first != second {
		t.Error("the report changed with the environment; it must not")
	}
}

// triaged renders a result with --triage evidence attached.
func triaged(t *testing.T, tr *analyze.TriageResult, details bool, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion, Target: "debian:12", Mode: "image",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "os", Ecosystems: []string{"Debian:12"}, Components: 88},
		},
		Findings: findings, Triage: tr,
	}, renderOpts{details: details})
}

// scored is a linked finding carrying an EPSS percentile.
func scored(cve, severity string, pct float64) analyze.Finding {
	f := analyze.Finding{
		Ecosystem: "os", CVE: cve, ID: cve,
		Package: "libc6", Module: "libc6", Version: "2.36-9",
		PURL:     "pkg:deb/debian/libc6@2.36-9?arch=amd64",
		Status:   analyze.StatusLinked,
		Method:   "elf-needed-closure",
		Severity: severity,
	}
	f.Priority = &triage.Priority{CVE: cve, Scored: true, EPSS: pct / 10, Percentile: pct}
	return f
}

// unscored is a finding --triage looked up and could not score.
func unscored(id, severity string) analyze.Finding {
	f := scored(id, severity, 0)
	f.Priority = &triage.Priority{}
	return f
}

func kevFinding(cve string, ransomware bool) analyze.Finding {
	f := scored(cve, "MEDIUM", 0.10)
	f.Priority.KEV = &triage.KEVEntry{DateAdded: "2021-11-03", DueDate: "2022-05-03", Ransomware: ransomware}
	return f
}

// The finding this whole feature exists for: on debian:12 the likeliest to be
// exploited is one nobody ever rated, and it must not be at the bottom.
func TestAnUnratedFindingWithAHighPercentileSortsToTheTop(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 3, EPSSDate: "2026-08-04"}, false,
		scored("CVE-2026-5450", "CRITICAL", 0.402),
		scored("CVE-2018-20796", "HIGH", 0.924),
		scored("CVE-2011-3389", "", 0.994),
	)
	rows := sectionOf(t, out, "AFFECTED")
	if len(rows) < 4 {
		t.Fatalf("expected a header and three rows:\n%s", out)
	}
	if !strings.Contains(rows[1], "CVE-2011-3389") {
		t.Errorf("the 99.4th-percentile unrated finding is not first:\n%s", strings.Join(rows, "\n"))
	}
	if !strings.Contains(rows[3], "CVE-2026-5450") {
		t.Errorf("the low-percentile CRITICAL is not last:\n%s", strings.Join(rows, "\n"))
	}
}

// Known exploitation is not a probability, so it outranks every probability.
func TestKEVOutranksAHigherPercentile(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 2, KnownExploited: 1}, false,
		scored("CVE-2011-3389", "LOW", 0.994),
		kevFinding("CVE-2017-5638", false),
	)
	rows := sectionOf(t, out, "AFFECTED")
	if !strings.Contains(rows[1], "CVE-2017-5638") {
		t.Errorf("the known-exploited row is not first:\n%s", strings.Join(rows, "\n"))
	}
}

func TestTheEPSSColumnShowsThePercentileNotTheRawScore(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 1}, false, scored("CVE-2011-3389", "HIGH", 0.994))
	row := lineWith(t, out, "CVE-2011-3389")
	if !strings.Contains(row, "99.4%") {
		t.Errorf("no percentile in the row: %q", row)
	}
	if !strings.Contains(lineWith(t, out, "SEVERITY"), "EPSS") {
		t.Error("no EPSS column heading")
	}
}

// A column of blanks on every image that has never shipped a known-exploited
// package is a daily reminder of a rare event.
func TestTheKEVColumnOnlyAppearsWhenSomethingIsListed(t *testing.T) {
	without := triaged(t, &analyze.TriageResult{Scored: 1}, false, scored("CVE-2011-3389", "HIGH", 0.994))
	if strings.Contains(lineWith(t, without, "SEVERITY"), "KEV") {
		t.Error("a KEV column was printed with nothing in it")
	}
	with := triaged(t, &analyze.TriageResult{Scored: 1, KnownExploited: 1}, false, kevFinding("CVE-2017-5638", true))
	if !strings.Contains(lineWith(t, with, "SEVERITY"), "KEV") {
		t.Error("no KEV column when a row is listed")
	}
	if !strings.Contains(lineWith(t, with, "CVE-2017-5638"), "ransomware") {
		t.Error("a ransomware campaign was not called one")
	}
}

// An unscored row sorts last, which in a list ordered by likelihood reads as
// "least likely". It means "nobody knows", and the report has to say so.
func TestUnscoredRowsSortLastAndAreExplained(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 1, NoCVE: 1, NotInFeed: 1}, false,
		unscored("GHSA-gcjh-h69q-9w9g", "CRITICAL"),
		scored("CVE-2011-3389", "LOW", 0.994),
		unscored("CVE-2026-53613", "HIGH"),
	)
	rows := sectionOf(t, out, "AFFECTED")
	if !strings.Contains(rows[1], "CVE-2011-3389") {
		t.Errorf("the scored row is not first:\n%s", strings.Join(rows, "\n"))
	}
	note := lineWith(t, out, "could not score")
	if !strings.Contains(note, "2 of 3") {
		t.Errorf("the note does not say how many: %q", note)
	}
	if !strings.Contains(out, "lack of risk") {
		t.Errorf("nothing warns that last does not mean safe:\n%s", out)
	}
	if !strings.Contains(out, "no CVE id") || !strings.Contains(out, "not scored yet") {
		t.Errorf("the two reasons are not distinguished:\n%s", out)
	}
	if !strings.Contains(lineWith(t, out, "GHSA-gcjh"), " - ") {
		t.Errorf("an unscored row shows a number rather than a dash:\n%s", out)
	}
}

// A percentile is a claim about a day, and a report read next month has to be
// able to see which day.
func TestTheSummaryNamesTheFeedDates(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{
		Scored: 1, EPSSDate: "2026-08-04", KEVDate: "2026.08.03",
	}, false, scored("CVE-2011-3389", "HIGH", 0.994))

	line := lineWith(t, out, "priority data:")
	if !strings.Contains(line, "EPSS 2026-08-04") || !strings.Contains(line, "KEV catalog 2026.08.03") {
		t.Errorf("priority data line = %q", line)
	}
	p := lineWith(t, out, "  priority: ")
	if !strings.Contains(p, "1 at or above the 90th EPSS percentile") {
		t.Errorf("priority line = %q", p)
	}
	if !strings.Contains(p, "none in CISA's known-exploited catalog") {
		t.Errorf("the catalog was checked and the line does not say so: %q", p)
	}
}

func TestACachedFeedIsMarkedAsCached(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{
		Scored: 1, EPSSDate: "2026-08-03", EPSSStale: true,
	}, false, scored("CVE-2011-3389", "HIGH", 0.994))

	if !strings.Contains(lineWith(t, out, "priority data:"), "EPSS 2026-08-03 (cached)") {
		t.Errorf("a stale feed is not marked:\n%s", out)
	}
	if !strings.Contains(out, "the percentiles below are that day's") {
		t.Errorf("nothing explains that the scores are old:\n%s", out)
	}
}

// A feed that could not be read leaves the rows in their old order. That must
// never look like a report where nothing is being exploited.
func TestAFailedFeedIsSaidOutLoud(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{
		NotInFeed: 1,
		EPSSError: "dial tcp: connection refused",
		KEVError:  "403 Forbidden",
	}, false, unscored("CVE-2011-3389", "HIGH"))

	if !strings.Contains(out, "could not read the EPSS feed") {
		t.Errorf("the EPSS failure is not reported:\n%s", out)
	}
	if !strings.Contains(out, "no row below is marked as exploited") {
		t.Errorf("the KEV failure is not reported:\n%s", out)
	}
	if strings.Contains(out, "none in CISA's known-exploited catalog") {
		t.Error("a catalog that could not be read was reported as having nothing in it")
	}
	// The unscored note would be noise here: nothing was scored at all, and the
	// line above already says why.
	if strings.Contains(out, "could not score") {
		t.Errorf("the per-finding note repeats the feed failure:\n%s", out)
	}
}

// The v0.4.1 property: anything a reader needs is at both ends of a long
// report, because a caveat only above 154 rows is one nobody sees.
func TestALongTriagedReportRepeatsThePriorityLines(t *testing.T) {
	out := longReport(t, 60, func(res *analyze.Result) {
		res.Triage = &analyze.TriageResult{Scored: 60, EPSSDate: "2026-08-04", EPSSStale: true}
		for i := range res.Findings {
			res.Findings[i].Priority = &triage.Priority{
				CVE: res.Findings[i].CVE, Scored: true, Percentile: 0.5,
			}
		}
	})
	for _, want := range []string{"priority data:", "(cached)", "  priority: ", "used the cached scores"} {
		if n := strings.Count(out, want); n != 2 {
			t.Errorf("%q appears %d times, want 2 (once at each end):\n%s", want, n, out)
		}
	}
}

// Without the flag nothing changes -- not a column, not a line, not the order.
// This is the guarantee that makes the feature safe to add.
func TestAnUntriagedReportIsUnchanged(t *testing.T) {
	before := report(t, true, gccTrio...)
	for i := range gccTrio {
		if gccTrio[i].Priority != nil {
			t.Fatal("the fixture was mutated by another test")
		}
	}
	if strings.Contains(before, "EPSS") || strings.Contains(before, "priority") {
		t.Errorf("an untriaged report mentions triage:\n%s", before)
	}
	// Same findings, same order, with the overlay having run and found nothing.
	rows := make([]analyze.Finding, len(gccTrio))
	copy(rows, gccTrio)
	sortForDisplay(rows)
	for i, f := range rows {
		if f.CVE != gccTrio[i].CVE {
			t.Error("the triage-aware sort reordered an untriaged report")
		}
	}
}

func TestTheDetailBlockShowsWhichCVEWasScored(t *testing.T) {
	f := scored("GO-2025-3547", "HIGH", 0.31)
	f.Priority.CVE = "CVE-2024-7598"
	out := triaged(t, &analyze.TriageResult{Scored: 1}, true, f)

	line := lineWith(t, out, "epss:")
	if !strings.Contains(line, "CVE-2024-7598") {
		t.Errorf("the detail does not name the id the score was looked up under: %q", line)
	}
	if !strings.Contains(line, "31.0%") || !strings.Contains(line, "0.031") {
		t.Errorf("the detail should carry both the percentile and the raw score: %q", line)
	}
	// A single-CVE advisory must not grow a set size, or every Debian row does.
	if strings.Contains(line, "highest of") {
		t.Errorf("a one-CVE advisory reported a set size: %q", line)
	}
}

// suseBundle is a distro advisory that fixes several CVEs and names none of
// them in its own id, scored at its worst member.
func suseBundle(pct float64, upstream ...string) analyze.Finding {
	f := scored("SUSE-SU-2026:0312-1", "UNKNOWN", pct)
	f.Package, f.Module, f.Version = "openssl-3", "libopenssl3", "3.1.4-150600.2.19"
	f.PURL = "pkg:rpm/suse/libopenssl3@3.1.4-150600.2.19?arch=x86_64"
	f.Upstream = upstream
	f.Priority.CVE = upstream[0]
	f.Priority.OfSet = len(upstream)
	return f
}

func TestABundledAdvisorySaysWhatItFixesAndHowManyItStandsFor(t *testing.T) {
	f := suseBundle(0.972, "CVE-2024-5535", "CVE-2024-2511", "CVE-2024-4603")
	out := triaged(t, &analyze.TriageResult{Scored: 1}, true, f)

	fixes := lineWith(t, out, "fixes:")
	for _, cve := range f.Upstream {
		if !strings.Contains(fixes, cve) {
			t.Errorf("the fixes line omits %s: %q", cve, fixes)
		}
	}
	epss := lineWith(t, out, "epss:")
	if !strings.Contains(epss, "highest of 3") {
		t.Errorf("the score is one CVE's out of three and does not say so: %q", epss)
	}
	if !strings.Contains(epss, "CVE-2024-5535") {
		t.Errorf("the score does not name the member it came from: %q", epss)
	}
}

// Stopping at five with no remainder would read as the whole list, which is the
// same failure as a truncated report reading as a clean one.
func TestALongBundleCountsTheCVEsItDoesNotName(t *testing.T) {
	f := suseBundle(0.5, "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003",
		"CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0006", "CVE-2024-0007")
	out := triaged(t, &analyze.TriageResult{Scored: 1}, true, f)

	line := lineWith(t, out, "fixes:")
	if !strings.Contains(line, "(+2 more)") {
		t.Errorf("a seven-CVE bundle showing five did not count the rest: %q", line)
	}
	if strings.Contains(line, "CVE-2024-0006") {
		t.Errorf("more than five CVEs were named: %q", line)
	}
}

// "CVE-2026-0001 is not in the feed yet" is a true statement about one of three
// and a misleading one about the row.
func TestAnUnscoredBundleSaysNoneOfThemRatherThanNamingOne(t *testing.T) {
	f := suseBundle(0, "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")
	f.Priority = &triage.Priority{CVE: "CVE-2026-0001", OfSet: 3}
	out := triaged(t, &analyze.TriageResult{NotInFeed: 1}, true, f)

	line := lineWith(t, out, "epss:")
	if !strings.Contains(line, "none of this advisory's 3 CVEs") {
		t.Errorf("an unscored bundle blamed a single CVE: %q", line)
	}
}

// What an advisory fixes is a property of the advisory, not of the flag, so it
// shows up with no --triage at all.
func TestTheFixesLineDoesNotNeedTriage(t *testing.T) {
	f := suseBundle(0, "CVE-2024-5535", "CVE-2024-2511")
	f.Priority = nil
	out := triaged(t, nil, true, f)

	if !strings.Contains(lineWith(t, out, "fixes:"), "CVE-2024-2511") {
		t.Error("an untriaged report does not say what the advisory fixes")
	}
	if strings.Contains(out, "epss:") {
		t.Error("an untriaged report rendered a priority line")
	}
}

// rpmReport renders a metadata-only result, the shape --rpm produces.
func rpmReport(t *testing.T, tr *analyze.TriageResult, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "/tmp/libopenssl3-3.1.4-150600.2.19.x86_64.rpm",
		Mode:          "rpm",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "os", Ecosystems: []string{"SUSE"}, Components: 1},
		},
		Findings: findings, Triage: tr,
	}, renderOpts{})
}

// undecided is what a metadata-only scan produces for a package that ships an
// ELF object: no test could run, so no claim is made.
func undecided(cve string) analyze.Finding {
	return analyze.Finding{
		Ecosystem: "os", CVE: cve, ID: cve,
		Package: "libopenssl3", Module: "libopenssl3", Version: "0:3.1.4-150600.2.19",
		PURL:   "pkg:rpm/sles/libopenssl3@0:3.1.4-150600.2.19?arch=x86_64",
		Status: analyze.StatusUndetermined,
		Reason: ospkg.ReasonNoReachabilityTest,
	}
}

// TestTheMetadataCaveatIsPrintedTwice is the v0.4.1 footer rule applied to the
// caveat that changes the most: without it an undetermined row reads as one the
// tool gave up on, rather than one the input cannot answer.
func TestTheMetadataCaveatIsPrintedTwice(t *testing.T) {
	// Long enough to earn a footer, which is the same 32 the real SLE package
	// produces -- the case the repetition exists for.
	var findings []analyze.Finding
	for i := 0; i < 32; i++ {
		findings = append(findings, undecided(fmt.Sprintf("SUSE-SU-2026:%04d-1", i)))
	}
	out := rpmReport(t, nil, findings...)

	if n := strings.Count(out, "this read package metadata, not an installed system"); n != 2 {
		t.Errorf("the caveat appears %d times, want it at both ends of the report", n)
	}
	if !strings.Contains(out, "32 finding(s) below are undetermined") {
		t.Errorf("the caveat does not count the rows it explains:\n%s", out)
	}
}

// An image scan must not grow the caveat, whatever its findings look like: it
// has the filesystem the caveat exists to say is missing.
func TestTheMetadataCaveatIsForDescribedPackagesOnly(t *testing.T) {
	if out := report(t, false, gccTrio...); strings.Contains(out, "not an installed system") {
		t.Errorf("an image report carried the metadata caveat:\n%s", out)
	}
}

// A linked Go finding carrying the govulncheck-unavailable evidence must make
// the report say the reachability test was skipped, and count how many findings
// it could not narrow. Without this a report from a box with no govulncheck is
// byte-identical to one where govulncheck ran and ruled nothing out.
func TestTheGovulncheckCaveatCountsSkippedFindings(t *testing.T) {
	skipped := func(cve string) analyze.Finding {
		return analyze.Finding{
			Ecosystem: "golang", CVE: cve, ID: cve,
			Module: "golang.org/x/net", Version: "v0.17.0",
			Status: analyze.StatusLinked,
			Evidence: []ecosystem.Evidence{{
				Origin: ecosystem.OriginGovulncheckUnavailable,
				Detail: "govulncheck is not on PATH",
			}},
		}
	}
	out := report(t, false, skipped("CVE-2023-39325"), skipped("CVE-2023-44487"))

	if !strings.Contains(out, "govulncheck was not found") {
		t.Errorf("the report does not warn that govulncheck was missing:\n%s", out)
	}
	if !strings.Contains(out, "2 linked Go finding(s) could not be") {
		t.Errorf("the caveat does not count the findings it explains:\n%s", out)
	}
	if !strings.Contains(out, "go install golang.org/x/vuln/cmd/govulncheck@latest") {
		t.Errorf("the caveat does not say how to fix it:\n%s", out)
	}
}

// A scan where govulncheck ran must not carry the caveat: the absence of the
// evidence is the whole signal, and a false warning would tell a user to
// install a tool they already have.
func TestTheGovulncheckCaveatIsAbsentWhenGovulncheckRan(t *testing.T) {
	if out := report(t, false, gccTrio...); strings.Contains(out, "govulncheck was not found") {
		t.Errorf("a report with no skipped findings carried the govulncheck caveat:\n%s", out)
	}
}

// sbomReport renders the shape --sbom produces.
func sbomReport(t *testing.T, findings ...analyze.Finding) string {
	t.Helper()
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "bom.json",
		Mode:          "sbom",
		Ecosystems: []ecosystem.EcosystemResult{
			{ID: "os", Ecosystems: []string{"Debian:12"}, Components: 1},
		},
		Findings: findings,
	}, renderOpts{})
}

// --sbom loses more than --rpm does, and the note has to say the extra part.
// An rpm header still lists the files the package installs, so a reader who
// knows the --rpm wording would otherwise carry over a rule-out this input
// cannot support.
func TestTheSBOMCaveatSaysWhatItCannotRuleOut(t *testing.T) {
	out := sbomReport(t, undecided("CVE-2024-0001"))

	if !strings.Contains(out, "bill of materials, not an installed system") {
		t.Errorf("the sbom report does not say what it read:\n%s", out)
	}
	if !strings.Contains(out, "does not list the files it installs") {
		t.Errorf("the sbom caveat does not say it cannot rule anything out:\n%s", out)
	}
	// The rpm reference measurement is about the one test rpm mode is missing.
	// Here every test is missing, so quoting it would understate the loss.
	if strings.Contains(out, "SUSE 15.6") {
		t.Errorf("the sbom caveat borrowed the --rpm scale note:\n%s", out)
	}
	if strings.Contains(out, "read package metadata") {
		t.Errorf("the sbom report carried the --rpm wording:\n%s", out)
	}
}

// The footer rule, applied to the caveat that changes the most.
func TestTheSBOMCaveatIsPrintedTwice(t *testing.T) {
	var findings []analyze.Finding
	for i := 0; i < 32; i++ {
		findings = append(findings, undecided(fmt.Sprintf("CVE-2026-%04d", i)))
	}
	out := sbomReport(t, findings...)

	if n := strings.Count(out, "bill of materials, not an installed system"); n != 2 {
		t.Errorf("the caveat appears %d times, want it at both ends of the report", n)
	}
	if !strings.Contains(out, "32 finding(s) below are undetermined") {
		t.Errorf("the caveat does not count the rows it explains:\n%s", out)
	}
}

// "No findings" out of a bill of materials is the weakest clean report this
// tool can produce, and it has to say so.
func TestTheSBOMCaveatSurvivesAnEmptyReport(t *testing.T) {
	out := sbomReport(t)
	if !strings.Contains(out, "No ELF") {
		t.Errorf("a clean sbom report did not say what it could not test:\n%s", out)
	}
	if strings.Contains(out, "finding(s) below") {
		t.Errorf("a report with no rows counted some:\n%s", out)
	}
}

// The caveat still prints with nothing to explain. "No findings" out of a
// package file is a weaker statement than the same words out of an image, and
// this is the whole of the difference.
func TestTheMetadataCaveatSurvivesAnEmptyReport(t *testing.T) {
	out := rpmReport(t, nil)
	if !strings.Contains(out, "No ELF") {
		t.Errorf("a clean metadata-only report did not say what it could not test:\n%s", out)
	}
	if strings.Contains(out, "finding(s) below") {
		t.Errorf("a report with no rows counted some:\n%s", out)
	}
}

// A package that ships no ELF object is ruled out on the header alone, and the
// caveat has to distinguish that from the rows it could not decide -- otherwise
// "RULED OUT (2)" sits under a note saying nothing could be ruled out.
func TestTheCaveatSeparatesRuledOutFromUndecided(t *testing.T) {
	noCode := undecided("RLSA-2026:25239")
	noCode.Status = analyze.StatusNotPresent
	noCode.Reason = ""
	noCode.Method = ospkg.MethodNoCode
	noCode.Justification = "vulnerable_code_not_present"

	out := rpmReport(t, nil, noCode, undecided("RLSA-2026:22312"))
	for _, want := range []string{
		"1 finding(s) below are undetermined",
		"1 finding(s) below are ruled out on the header alone",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("caveat is missing %q:\n%s", want, out)
		}
	}
}

// TestThePriorityLineIsNotPrintedOverAnEmptyPopulation is the metadata-only
// case making a latent contradiction visible: it counts affected rows, a
// metadata-only scan has none by construction, and "0 scored" printed above a
// table of EPSS percentages is a summary the report itself refutes.
func TestThePriorityLineIsNotPrintedOverAnEmptyPopulation(t *testing.T) {
	f := undecided("SUSE-SU-2024:3106-1")
	f.Priority = &triage.Priority{CVE: "CVE-2024-5535", Scored: true, Percentile: 0.992, OfSet: 1}

	out := rpmReport(t, &analyze.TriageResult{EPSSDate: "2026-08-04"}, f)
	if strings.Contains(out, "0 scored") {
		t.Errorf("the summary said nothing was scored over a row showing 99.2%%:\n%s", out)
	}
	// The date survives: a percentile is a claim about a day either way.
	if !strings.Contains(out, "priority data: EPSS 2026-08-04") {
		t.Errorf("the feed date went with it:\n%s", out)
	}
}

// ruledOutKEV is a known-exploited finding this scan ruled out: the package is
// installed, it is in the catalog, and no object it ships is reachable. It is
// the shape that made the summary and the log line disagree.
func ruledOutKEV(cve string) analyze.Finding {
	f := kevFinding(cve, false)
	f.Status = analyze.StatusNotInPath
	f.Justification = "vulnerable_code_not_in_execute_path"
	return f
}

// The defect this pair of tests exists for: --triage logs "3 finding(s) are in
// CISA's known-exploited catalog" and writes known_exploited:3 to the JSON,
// counting every finding, while the summary counted only the affected ones --
// so a report could print "none in CISA's known-exploited catalog" over a run
// whose own log said three. Whichever number a reader believes, one of them was
// lying to them.
func TestTheSummaryDoesNotSayNoneWhenTheCatalogFired(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 2, KnownExploited: 1, KEVDate: "2026.08.03"}, false,
		scored("CVE-2011-3389", "HIGH", 0.994),
		ruledOutKEV("CVE-2017-5638"),
	)
	p := lineWith(t, out, "  priority: ")
	if strings.Contains(p, "none in CISA's known-exploited catalog") {
		t.Errorf("the summary denied a catalog hit the log and the JSON both report: %q", p)
	}
	if !strings.Contains(p, "1 other row is") {
		t.Errorf("the hit is not mentioned at all: %q", p)
	}
	// It is outside the population on purpose, so it must not be counted into
	// the numbers that mean work to do.
	if !strings.Contains(p, "1 scored") {
		t.Errorf("the ruled-out row leaked into the affected counts: %q", p)
	}
}

// A hit inside the population and a hit outside it are different claims, and
// the line has to carry both rather than picking one.
func TestTheSummarySeparatesExploitedRowsFromRuledOutOnes(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 3, KnownExploited: 3}, false,
		kevFinding("CVE-2021-44228", false),
		ruledOutKEV("CVE-2017-5638"),
		ruledOutKEV("CVE-2014-0160"),
	)
	p := lineWith(t, out, "  priority: ")
	if !strings.Contains(p, "1 known exploited (CISA KEV), 2 more outside the affected rows") {
		t.Errorf("priority line = %q", p)
	}
	// 1 + 2 is the number the log line and the JSON print. A reader adding the
	// summary up has to arrive there.
	if !strings.Contains(p, "1 scored") {
		t.Errorf("the two ruled-out rows leaked into the affected counts: %q", p)
	}
}

// A vendor's not_affected is somebody else's conclusion, not this scan's, and
// it does not remove the row from the catalog.
func TestAVexedRowStillCountsAsACatalogHit(t *testing.T) {
	f := kevFinding("CVE-2017-5638", false)
	f.VEX = &ecosystem.VEXStatement{Status: "not_affected", Author: "SUSE"}

	out := triaged(t, &analyze.TriageResult{Scored: 1, KnownExploited: 1}, false, f)
	p := lineWith(t, out, "  priority: ")
	if !strings.Contains(p, "1 other row is") {
		t.Errorf("a vexed catalog hit went unmentioned: %q", p)
	}
}

// The empty-population suppression must not swallow the one clause that is not
// about the population. A metadata-only scan decides nothing, so every row is
// outside the affected set -- which is exactly when a catalog hit is easiest to
// lose and worst to lose.
func TestACatalogHitSurvivesAnEmptyPopulation(t *testing.T) {
	f := undecided("SUSE-SU-2024:3106-1")
	f.Priority = &triage.Priority{CVE: "CVE-2017-5638", Scored: true, Percentile: 0.992, OfSet: 1}
	f.Priority.KEV = &triage.KEVEntry{DateAdded: "2021-11-03", DueDate: "2022-05-03"}

	out := rpmReport(t, &analyze.TriageResult{EPSSDate: "2026-08-04", KnownExploited: 1}, f)
	p := lineWith(t, out, "  priority: ")
	if !strings.Contains(p, "1 other row is") {
		t.Errorf("the catalog hit was suppressed with the empty population: %q", p)
	}
	if strings.Contains(p, "0 scored") {
		t.Errorf("the population counts came back with it: %q", p)
	}
}

// Nothing anywhere in the catalog is still worth printing, and the wording for
// that case must not have been disturbed by the wording for the others.
func TestTheQuietCaseIsUnchanged(t *testing.T) {
	out := triaged(t, &analyze.TriageResult{Scored: 1}, false, scored("CVE-2011-3389", "HIGH", 0.994))
	p := lineWith(t, out, "  priority: ")
	if !strings.Contains(p, "none in CISA's known-exploited catalog") {
		t.Errorf("priority line = %q", p)
	}
	if strings.Contains(p, "outside the affected rows") || strings.Contains(p, "other row") {
		t.Errorf("a remainder clause was printed with no remainder: %q", p)
	}
}

// withDescriptor renders a report of n copies of the gcc trio, stamped with d.
func withDescriptor(t *testing.T, d *analyze.Descriptor, n int) string {
	t.Helper()
	var findings []analyze.Finding
	for i := 0; i < n; i++ {
		for _, f := range gccTrio {
			f.CVE = fmt.Sprintf("%s-%d", f.CVE, i)
			f.ID = f.CVE
			findings = append(findings, f)
		}
	}
	return renderText(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "debian:12",
		Mode:          "image",
		Findings:      findings,
		Descriptor:    d,
	}, renderOpts{})
}

var fullDescriptor = &analyze.Descriptor{
	Tool:           "vexscan",
	Version:        "v0.6.2",
	Started:        time.Date(2026, 8, 5, 14, 2, 0, 0, time.UTC),
	Duration:       "12.4s",
	AdvisorySource: "https://api.osv.dev/v1",
	AdvisoriesAsOf: time.Date(2026, 8, 5, 14, 2, 9, 0, time.UTC),
}

// The provenance line names the build, the clock and the advisory source, so a
// report read six months from now can still be dated.
func TestProvenanceNamesWhatProducedTheReport(t *testing.T) {
	out := withDescriptor(t, fullDescriptor, 1)
	line := lineWith(t, out, "scanned by:")
	for _, want := range []string{"vexscan v0.6.2", "2026-08-05 14:02 UTC", "12.4s", "https://api.osv.dev/v1"} {
		if !strings.Contains(line, want) {
			t.Errorf("provenance line is missing %q: %q", want, line)
		}
	}
	// The header, above every section -- it is provenance, not a finding.
	if i, j := strings.Index(out, "scanned by:"), strings.Index(out, "AFFECTED ("); i > j {
		t.Errorf("the provenance line is below the first section:\n%s", out)
	}
}

// Caveats are repeated in the footer of a long report because they change what
// the reader should conclude. Provenance does not, so it stays in the header --
// printing it beside the INCOMPLETE banners would dilute exactly those.
func TestProvenanceIsNotRepeatedInTheFooter(t *testing.T) {
	out := withDescriptor(t, fullDescriptor, 20)
	if n := strings.Count(out, "\n"); n <= footerThreshold {
		t.Fatalf("the report is %d lines, too short to have grown a footer", n)
	}
	if n := strings.Count(out, "affected by severity:"); n != 2 {
		t.Fatalf("the summary appears %d time(s), so the footer did not run:\n%s", n, out)
	}
	lineWith(t, out, "scanned by:") // exactly one, footer or no footer
}

// A report with nothing to say about itself says nothing, rather than printing
// an empty label.
func TestProvenanceIsSilentWithoutADescriptor(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    *analyze.Descriptor
	}{
		{"nil", nil},
		{"zero", &analyze.Descriptor{}},
		// Stamped by the resolver but never by the command: not a state main
		// produces, but the renderer must not print a bare "vexscan" for it.
		{"tool only", &analyze.Descriptor{Tool: "vexscan"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out := withDescriptor(t, tc.d, 1); strings.Contains(out, "scanned by:") {
				t.Errorf("a %s descriptor still printed provenance:\n%s", tc.name, out)
			}
		})
	}
}

// Each half of the line is optional, and a missing half must not leave the
// separator behind.
func TestProvenanceOmitsWhatItDoesNotKnow(t *testing.T) {
	out := withDescriptor(t, &analyze.Descriptor{Tool: "vexscan", Version: "v0.6.2"}, 1)
	line := lineWith(t, out, "scanned by:")
	if line != "scanned by: vexscan v0.6.2" {
		t.Errorf("provenance line = %q, want no separator and no empty fields", line)
	}

	// An offline run resolves no advisories, so there is no as-of date to give.
	out = withDescriptor(t, &analyze.Descriptor{
		Version: "v0.6.2", Started: fullDescriptor.Started, Duration: "0.2s",
		AdvisorySource: "https://api.osv.dev/v1",
	}, 1)
	if line := lineWith(t, out, "scanned by:"); strings.Contains(line, "advisories from") {
		t.Errorf("an unanswered advisory source was still dated: %q", line)
	}
}
