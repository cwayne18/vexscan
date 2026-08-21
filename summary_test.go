package main

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// summaryOf renders a summary from an explicit set of ecosystems and findings.
func summaryOf(t *testing.T, ecos []ecosystem.EcosystemResult, findings ...analyze.Finding) string {
	t.Helper()
	return renderSummary(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "debian:12",
		Mode:          "image",
		Ecosystems:    ecos,
		Findings:      findings,
	}, renderOpts{})
}

func TestSummaryCountsBucketsPerEcosystem(t *testing.T) {
	out := summaryOf(t,
		[]ecosystem.EcosystemResult{
			{ID: "os", Ecosystems: []string{"Debian:12"}, Components: 117},
			{ID: "golang", Components: 42},
		},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "HIGH"},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-2", Package: "b", Status: analyze.StatusNotPresent},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-3", Package: "c", Status: analyze.StatusNotInPath},
		analyze.Finding{Ecosystem: "golang", CVE: "CVE-4", Package: "d", Status: analyze.StatusReachable, Severity: "CRITICAL"},
		analyze.Finding{Ecosystem: "golang", CVE: "CVE-5", Package: "e", Status: analyze.StatusUndetermined},
	)

	// os row: the label carries the concrete OSV ecosystem, 117 components,
	// 1 affected, 2 ruled out.
	os := lineWith(t, out, "os (Debian:12)")
	if !strings.Contains(os, "117") {
		t.Errorf("os row missing component count:\n%s", out)
	}

	// The total row sums both ecosystems: 159 components, 2 affected, 1
	// undetermined, 2 ruled out. VEXED is absent (nothing vexed).
	total := lineWith(t, out, "TOTAL")
	if got := strings.Fields(total); !equalStrings(got, []string{"TOTAL", "159", "2", "1", "2"}) {
		t.Errorf("total row = %v, want [TOTAL 159 2 1 2]\n%s", got, out)
	}
}

// equalStrings reports whether two string slices are identical.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSummaryDropsEmptyEcosystemAndTotalRow(t *testing.T) {
	// golang ran but found no inventory and no findings; os found everything.
	out := summaryOf(t,
		[]ecosystem.EcosystemResult{
			{ID: "golang", Components: 0},
			{ID: "os", Ecosystems: []string{"Debian:12"}, Components: 10},
		},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "HIGH"},
	)
	if strings.Contains(out, "golang") {
		t.Errorf("empty golang ecosystem should be dropped from the summary:\n%s", out)
	}
	// With a single remaining ecosystem row, TOTAL would only repeat it.
	if strings.Contains(out, "TOTAL") {
		t.Errorf("TOTAL row should be omitted for a single ecosystem:\n%s", out)
	}
}

func TestSummaryDropsStatusColumnsThatAreZeroEverywhere(t *testing.T) {
	// Nothing vexed, nothing undetermined: those columns earn no place.
	out := summaryOf(t,
		[]ecosystem.EcosystemResult{{ID: "os", Components: 10}},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "HIGH"},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-2", Package: "b", Status: analyze.StatusNotPresent},
	)
	header := lineWith(t, out, "ECOSYSTEM")
	if strings.Contains(header, "VEXED") {
		t.Errorf("VEXED column should be absent when nothing is vexed:\n%s", out)
	}
	if strings.Contains(header, "UNDETERMINED") {
		t.Errorf("UNDETERMINED column should be absent when nothing is undetermined:\n%s", out)
	}
	for _, want := range []string{"AFFECTED", "RULED OUT", "COMPONENTS"} {
		if !strings.Contains(header, want) {
			t.Errorf("header missing %q column:\n%s", want, out)
		}
	}
}

func TestSummaryShowsAffectedSeverity(t *testing.T) {
	out := summaryOf(t,
		[]ecosystem.EcosystemResult{{ID: "os", Components: 10}},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "CRITICAL"},
		analyze.Finding{Ecosystem: "os", CVE: "CVE-2", Package: "b", Status: analyze.StatusLinked, Severity: "HIGH"},
	)
	line := lineWith(t, out, "affected by severity:")
	if !strings.Contains(line, "1 critical") || !strings.Contains(line, "1 high") {
		t.Errorf("severity line wrong:\n%s", line)
	}
}

// The invariant that makes the summary trustworthy: its counts are exactly the
// section sizes of the full text report, because both route through bucketOf.
func TestSummaryTotalsMatchSectionSizes(t *testing.T) {
	findings := []analyze.Finding{
		{Ecosystem: "os", CVE: "CVE-1", Package: "a", Status: analyze.StatusLinked, Severity: "HIGH"},
		{Ecosystem: "os", CVE: "CVE-2", Package: "b", Status: analyze.StatusNotPresent},
		{Ecosystem: "os", CVE: "CVE-3", Package: "c", Status: analyze.StatusUndetermined},
		{Ecosystem: "golang", CVE: "CVE-4", Package: "d", Status: analyze.StatusReachable, Severity: "LOW"},
	}
	res := &analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "debian:12",
		Mode:          "image",
		Ecosystems:    []ecosystem.EcosystemResult{{ID: "os", Components: 5}, {ID: "golang", Components: 3}},
		Findings:      findings,
	}

	var affected, ruledOut, undetermined int
	for _, s := range sections(res) {
		switch s.title {
		case "AFFECTED":
			affected = len(s.findings)
		case "RULED OUT":
			ruledOut = len(s.findings)
		case "UNDETERMINED":
			undetermined = len(s.findings)
		}
	}
	if affected != 2 || ruledOut != 1 || undetermined != 1 {
		t.Fatalf("unexpected section sizes: affected=%d ruledOut=%d undetermined=%d", affected, ruledOut, undetermined)
	}

	total := lineWith(t, renderSummary(res, renderOpts{}), "TOTAL")
	// affected 2, undetermined 1, ruled out 1 must all appear in the total row.
	for _, want := range []string{"2", "1"} {
		if !strings.Contains(total, want) {
			t.Errorf("total row missing %q:\n%s", want, total)
		}
	}
}

func TestSummaryEmptyIsNotClean(t *testing.T) {
	// A scan that lost an ecosystem and found nothing must not read as clean.
	out := summaryOf(t, []ecosystem.EcosystemResult{{ID: "os", Error: "no package database"}})
	if !strings.Contains(out, "incomplete") {
		t.Errorf("empty incomplete summary should say so:\n%s", out)
	}
}

func TestSummaryEcosystemLabel(t *testing.T) {
	cases := []struct {
		e    ecosystem.EcosystemResult
		want string
	}{
		{ecosystem.EcosystemResult{ID: "os", Ecosystems: []string{"Debian:12"}}, "os (Debian:12)"},
		{ecosystem.EcosystemResult{ID: "golang", Ecosystems: []string{"Go"}}, "golang (Go)"},
		{ecosystem.EcosystemResult{ID: "npm"}, "npm"},
		{ecosystem.EcosystemResult{ID: "pypi", Ecosystems: []string{"pypi"}}, "pypi"},
	}
	for _, tc := range cases {
		if got := ecosystemLabel(tc.e); got != tc.want {
			t.Errorf("ecosystemLabel(%+v) = %q, want %q", tc.e, got, tc.want)
		}
	}
}
