package main

import (
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

func finding(status analyze.Status, severity string, vex bool) analyze.Finding {
	f := analyze.Finding{Status: status, Severity: severity}
	if vex {
		f.VEX = &ecosystem.VEXStatement{Status: "not_affected"}
	}
	return f
}

// The default gate is the whole point: linked code, not a version string.
func TestGateDefaultsToAffectedOnly(t *testing.T) {
	g, err := parseFailOn("high", "")
	if err != nil {
		t.Fatalf("parseFailOn: %v", err)
	}
	res := &analyze.Result{Findings: []analyze.Finding{
		finding(analyze.StatusLinked, "CRITICAL", false),       // counts, trips
		finding(analyze.StatusReachable, "HIGH", false),        // counts, trips
		finding(analyze.StatusLinked, "MEDIUM", false),         // counts, below
		finding(analyze.StatusNotPresent, "CRITICAL", false),   // ruled out
		finding(analyze.StatusUndetermined, "CRITICAL", false), // no conclusion
		finding(analyze.StatusLinked, "CRITICAL", true),        // a vendor answered
	}}
	got := g.evaluate(res)
	if got.tripped != 2 {
		t.Errorf("tripped = %d, want 2", got.tripped)
	}
	if got.counted != 3 {
		t.Errorf("counted = %d, want 3 (the linked and reachable rows a vendor has not answered)", got.counted)
	}
}

// A VEX statement that rules a finding out must not trip a gate set to
// affected -- quieting exactly those rows is what the document is for.
func TestGateExcludesVexedFindingsUnlessAsked(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		finding(analyze.StatusLinked, "CRITICAL", true),
	}}
	strict, _ := parseFailOn("any", "")
	if got := strict.evaluate(res); got.tripped != 0 {
		t.Errorf("tripped = %d with the default classes, want 0", got.tripped)
	}
	wide, _ := parseFailOn("any", "affected,vexed")
	if got := wide.evaluate(res); got.tripped != 1 {
		t.Errorf("tripped = %d with vexed named, want 1", got.tripped)
	}
}

// Severity ordering is cvss.Rank's, not a second table: an unrated finding
// sits above MEDIUM and below HIGH, exactly where the report sorts it.
func TestGateOrdersSeveritiesLikeTheTable(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		finding(analyze.StatusLinked, "", false),
	}}
	cases := []struct {
		threshold string
		tripped   int
	}{
		{"CRITICAL", 0},
		{"HIGH", 0},
		{"UNKNOWN", 1},
		{"MEDIUM", 1},
		{"LOW", 1},
		{"any", 1},
	}
	for _, tc := range cases {
		g, err := parseFailOn(tc.threshold, "")
		if err != nil {
			t.Fatalf("parseFailOn(%q): %v", tc.threshold, err)
		}
		if got := g.evaluate(res).tripped; got != tc.tripped {
			t.Errorf("--fail-on %s over an unrated finding: tripped = %d, want %d", tc.threshold, got, tc.tripped)
		}
	}
}

// The gate passing because it could not read a number is the one silence this
// must not have, so it is counted and reported.
func TestGateCountsWhatItCouldNotWeigh(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		finding(analyze.StatusLinked, "", false),
		finding(analyze.StatusLinked, "UNKNOWN", false),
		finding(analyze.StatusLinked, "LOW", false),
	}}
	high, _ := parseFailOn("high", "")
	got := high.evaluate(res)
	if got.tripped != 0 {
		t.Errorf("tripped = %d, want 0", got.tripped)
	}
	if got.unweighable != 2 {
		t.Errorf("unweighable = %d, want 2 (an empty severity and an explicit UNKNOWN)", got.unweighable)
	}
	// Below UNKNOWN the unrated findings already count, so there is nothing
	// left unweighed and nothing to warn about.
	low, _ := parseFailOn("low", "")
	if got := low.evaluate(res); got.unweighable != 0 {
		t.Errorf("unweighable = %d at --fail-on low, want 0", got.unweighable)
	}
}

func TestParseFailOn(t *testing.T) {
	cases := []struct {
		name      string
		severity  string
		statuses  string
		wantErr   bool
		wantOn    bool
		wantLabel string
	}{
		{name: "off by default"},
		{name: "a severity", severity: "critical", wantOn: true, wantLabel: "CRITICAL"},
		{name: "moderate is medium", severity: "moderate", wantOn: true, wantLabel: "MEDIUM"},
		{name: "any", severity: "ANY", wantOn: true, wantLabel: "ANY"},
		{name: "all statuses", severity: "high", statuses: "all", wantOn: true, wantLabel: "HIGH"},
		{name: "a list", severity: "high", statuses: "affected, undetermined", wantOn: true, wantLabel: "HIGH"},

		// Strict, for the reason --severity is strict: a threshold that never
		// matches is a gate that silently passes everything.
		{name: "a typo in the severity", severity: "critcal", wantErr: true},
		{name: "a typo in the status", severity: "high", statuses: "affcted", wantErr: true},
		{name: "a status with no gate to widen", statuses: "all", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := parseFailOn(tc.severity, tc.statuses)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFailOn(%q, %q) = nil error, want one", tc.severity, tc.statuses)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFailOn(%q, %q): %v", tc.severity, tc.statuses, err)
			}
			if g.on != tc.wantOn {
				t.Errorf("on = %v, want %v", g.on, tc.wantOn)
			}
			if g.label != tc.wantLabel {
				t.Errorf("label = %q, want %q", g.label, tc.wantLabel)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		f    analyze.Finding
		want findingClass
	}{
		{"linked", finding(analyze.StatusLinked, "HIGH", false), classAffected},
		{"reachable", finding(analyze.StatusReachable, "HIGH", false), classAffected},
		{"undetermined", finding(analyze.StatusUndetermined, "HIGH", false), classUndetermined},
		{"not present", finding(analyze.StatusNotPresent, "HIGH", false), classCleared},
		{"not in execute path", finding(analyze.StatusNotInPath, "HIGH", false), classCleared},
		// Vexed wins over linked, or the default gate would fire on exactly
		// the rows the VEX document exists to quiet.
		{"linked but vexed", finding(analyze.StatusLinked, "HIGH", true), classVexed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.f); got != tc.want {
				t.Errorf("classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGateDescribeNamesTheFlagThatFired(t *testing.T) {
	g, _ := parseFailOn("high", "affected,undetermined")
	got := g.describe(gateResult{tripped: 3})
	want := "gate: 3 affected/undetermined finding(s) at or above HIGH (--fail-on high)"
	if got != want {
		t.Errorf("describe() = %q, want %q", got, want)
	}
	any, _ := parseFailOn("any", "")
	if got := any.describe(gateResult{tripped: 1}); got != "gate: 1 affected finding(s) at any severity (--fail-on any)" {
		t.Errorf("describe() for any = %q", got)
	}
}
