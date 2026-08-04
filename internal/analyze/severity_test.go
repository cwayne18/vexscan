package analyze

import (
	"testing"

	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/osv"
)

const criticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8

func resolverWith(cache map[string]map[string]*osv.Advisory) *advisoryResolver {
	r := newResolver()
	r.cache = cache
	return r
}

// TestSeveritiesReadsWhatWasAlreadyFetched covers the central claim: the
// severity comes out of the advisories the resolver cached to decide the
// findings existed, so it costs no extra request.
func TestSeveritiesReadsWhatWasAlreadyFetched(t *testing.T) {
	r := resolverWith(map[string]map[string]*osv.Advisory{
		"Debian:12/zlib1g@1:1.2.13.dfsg-1": {
			"DEBIAN-CVE-2023-45853": {
				ID:         "DEBIAN-CVE-2023-45853",
				Aliases:    []string{"CVE-2023-45853"},
				CVSSVector: criticalVector,
			},
		},
	})

	sev := r.severities()
	// Indexed under its own id and under the alias, because a finding names
	// the advisory by whichever id its plugin was working from.
	for _, key := range []string{"DEBIAN-CVE-2023-45853", "CVE-2023-45853"} {
		got, ok := sev[key]
		if !ok {
			t.Fatalf("%s missing from the severity map", key)
		}
		if got.label != cvss.Critical {
			t.Errorf("%s: label = %s, want %s", key, got.label, cvss.Critical)
		}
		if got.vector != criticalVector {
			t.Errorf("%s: vector = %q", key, got.vector)
		}
	}
}

// An advisory reachable from two components must not report a different
// severity depending on map iteration order.
func TestSeveritiesIsDeterministicAcrossComponents(t *testing.T) {
	r := resolverWith(map[string]map[string]*osv.Advisory{
		"Debian:12/a@1": {"CVE-1": {ID: "CVE-1", PublisherSeverity: "LOW"}},
		"Debian:12/b@1": {"CVE-1": {ID: "CVE-1", PublisherSeverity: "CRITICAL"}},
	})
	for i := 0; i < 50; i++ {
		if got := r.severities()["CVE-1"].label; got != cvss.Critical {
			t.Fatalf("iteration %d: label = %s, want the more severe %s", i, got, cvss.Critical)
		}
	}
}

func TestSeveritiesToleratesNilAdvisories(t *testing.T) {
	r := resolverWith(map[string]map[string]*osv.Advisory{
		"Debian:12/a@1": {"CVE-1": nil},
	})
	if got := len(r.severities()); got != 0 {
		t.Errorf("severities() = %d entries, want 0", got)
	}
}

func TestSeverityOverlay(t *testing.T) {
	sev := map[string]severity{
		"DEBIAN-CVE-2023-45853": {label: cvss.Critical, vector: criticalVector},
		"CVE-2023-45853":        {label: cvss.Critical, vector: criticalVector},
		"GO-2023-2102":          {label: cvss.High},
	}

	findings := []Finding{
		// Matched on CVE, which is what ospkg fills in.
		{CVE: "DEBIAN-CVE-2023-45853", ID: "DEBIAN-CVE-2023-45853"},
		// Matched on the neutral ID when CVE is spelled differently.
		{CVE: "", ID: "CVE-2023-45853"},
		// Matched on GoID, the Go plugin's own identifier.
		{CVE: "CVE-2023-39325", ID: "CVE-2023-39325", GoID: "GO-2023-2102"},
		// Nothing was resolved for this one.
		{CVE: "CVE-9999-0000", ID: "CVE-9999-0000"},
	}
	severityOverlay(findings, sev)

	if findings[0].Severity != cvss.Critical || findings[0].CVSS != criticalVector {
		t.Errorf("matched on CVE: %+v", findings[0])
	}
	if findings[1].Severity != cvss.Critical {
		t.Errorf("matched on ID: %+v", findings[1])
	}
	if findings[2].Severity != cvss.High {
		t.Errorf("matched on GoID: %+v", findings[2])
	}
	if findings[2].CVSS != "" {
		t.Errorf("CVSS = %q, the advisory published no vector", findings[2].CVSS)
	}
	// An unresolved advisory leaves Severity empty rather than claiming
	// UNKNOWN. The two are different facts: nothing was read, versus a record
	// was read and published no rating.
	if findings[3].Severity != "" {
		t.Errorf("Severity = %q, want empty for an advisory nothing resolved", findings[3].Severity)
	}
}

func TestSeverityOverlayWithAnEmptyMapChangesNothing(t *testing.T) {
	findings := []Finding{{CVE: "CVE-1", Severity: ""}}
	severityOverlay(findings, nil)
	if findings[0].Severity != "" {
		t.Errorf("Severity = %q", findings[0].Severity)
	}
}

// The Go repo-mode path resolves advisories inside govulncheck rather than
// through the resolver, so its findings arrive with no severity. That gap is
// documented in the README; this pins that it degrades to "unrated" rather
// than to a wrong rating.
func TestSeverityOverlayLeavesUnresolvableFindingsAlone(t *testing.T) {
	findings := []Finding{{CVE: "CVE-2023-39325", GoID: "GO-2023-2102"}}
	severityOverlay(findings, map[string]severity{"CVE-OTHER": {label: cvss.Critical}})
	if findings[0].Severity != "" || findings[0].CVSS != "" {
		t.Errorf("unresolved finding was labelled: %+v", findings[0])
	}
}

// rated is a linked finding at one severity, which is all severityFilter looks
// at. An empty label is the real and common case: no advisory was resolved.
func rated(id, label string) Finding {
	return Finding{
		Ecosystem: "os", ID: id, CVE: id,
		Severity: label, Status: StatusLinked,
	}
}

func labels(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func TestNoSeverityFilterIsANoOp(t *testing.T) {
	in := []Finding{rated("a", cvss.Critical), rated("b", cvss.Low)}
	got, w := severityFilter(in, nil)
	if len(got) != 2 {
		t.Errorf("kept %v, want both", labels(got))
	}
	if w != nil {
		t.Errorf("Withheld = %+v, want nil so no banner prints", w)
	}
}

func TestSeverityFilterKeepsOnlyWhatWasNamed(t *testing.T) {
	in := []Finding{
		rated("crit", cvss.Critical),
		rated("high", cvss.High),
		rated("med", cvss.Medium),
		rated("low", cvss.Low),
	}
	got, w := severityFilter(in, []string{cvss.Critical, cvss.High})
	if len(got) != 2 || got[0].ID != "crit" || got[1].ID != "high" {
		t.Errorf("kept %v, want [crit high]", labels(got))
	}
	if w == nil || w.Count != 2 {
		t.Fatalf("Withheld = %+v, want 2 dropped", w)
	}
	if w.BySeverity[cvss.Medium] != 1 || w.BySeverity[cvss.Low] != 1 {
		t.Errorf("BySeverity = %v, want one medium and one low", w.BySeverity)
	}
}

// The decision that most surprises a Trivy user, pinned: an unrated finding is
// dropped by --severity CRITICAL,HIGH, and counted as UNKNOWN so the banner can
// say the drop happened.
func TestAnUnratedFindingIsWithheldAsUnknown(t *testing.T) {
	in := []Finding{rated("crit", cvss.Critical), rated("unrated", "")}
	got, w := severityFilter(in, []string{cvss.Critical, cvss.High})
	if len(got) != 1 || got[0].ID != "crit" {
		t.Errorf("kept %v, want [crit]", labels(got))
	}
	if w == nil || w.BySeverity[cvss.Unknown] != 1 {
		t.Fatalf("Withheld = %+v, want the unrated finding counted as UNKNOWN", w)
	}
}

// An empty Severity and an explicit UNKNOWN are the same fact to a reader, so
// naming UNKNOWN has to reach both.
func TestNamingUnknownKeepsBothSpellingsOfUnrated(t *testing.T) {
	in := []Finding{
		rated("empty", ""),
		rated("explicit", cvss.Unknown),
		rated("high", cvss.High),
	}
	got, w := severityFilter(in, []string{cvss.Unknown})
	if len(got) != 2 || got[0].ID != "empty" || got[1].ID != "explicit" {
		t.Errorf("kept %v, want both unrated spellings", labels(got))
	}
	if w == nil || w.Count != 1 || w.BySeverity[cvss.High] != 1 {
		t.Errorf("Withheld = %+v, want only the high one dropped", w)
	}
}

// The exemption. unmapped emits this row so an id the user typed cannot vanish;
// a severity filter deleting it would recreate exactly the silence that row
// exists to prevent, and would do it to the id they asked about most directly.
func TestARequestedIdThatMatchedNothingSurvivesTheFilter(t *testing.T) {
	in := append(unmapped([]string{"CVE-2024-9999"}, nil), rated("med", cvss.Medium))
	got, w := severityFilter(in, []string{cvss.Critical})
	if len(got) != 1 || got[0].CVE != "CVE-2024-9999" {
		t.Fatalf("kept %v, want the unmatched id to survive", labels(got))
	}
	if got[0].Reason != "no_component_matched" {
		t.Errorf("Reason = %q, want it unchanged", got[0].Reason)
	}
	// It survived, so it is not counted as withheld -- the banner would be
	// claiming to have hidden a row that is printed right below it.
	if w == nil || w.Count != 1 || w.BySeverity[cvss.Medium] != 1 {
		t.Errorf("Withheld = %+v, want only the medium finding counted", w)
	}
}

// An undetermined finding with no severity is not exempt: only the
// no_component_matched receipt is.
func TestTheExemptionIsNarrow(t *testing.T) {
	f := Finding{ID: "x", CVE: "x", Status: StatusUndetermined, Reason: "dlopen_reachable"}
	got, w := severityFilter([]Finding{f}, []string{cvss.Critical})
	if len(got) != 0 {
		t.Errorf("kept %v, want an ordinary undetermined finding to be filtered", labels(got))
	}
	if w == nil || w.Count != 1 {
		t.Errorf("Withheld = %+v, want it counted", w)
	}
}

// A filter that hid nothing produces no banner, so the line that will one day
// matter is not one a reader has been trained to skip.
func TestAFilterThatHidNothingReportsNothing(t *testing.T) {
	in := []Finding{rated("crit", cvss.Critical)}
	got, w := severityFilter(in, []string{cvss.Critical, cvss.High})
	if len(got) != 1 {
		t.Errorf("kept %v, want the critical finding", labels(got))
	}
	if w != nil {
		t.Errorf("Withheld = %+v, want nil when nothing was dropped", w)
	}
}

func TestWithheldQuotesTheFlagBack(t *testing.T) {
	_, w := severityFilter([]Finding{rated("low", cvss.Low)}, []string{cvss.Critical, cvss.High})
	if w == nil {
		t.Fatal("want a Withheld")
	}
	if len(w.Severities) != 2 || w.Severities[0] != cvss.Critical || w.Severities[1] != cvss.High {
		t.Errorf("Severities = %v, want what --severity asked for", w.Severities)
	}
}

// Filtering everything is legal and is the --repo case: every Go finding there
// is UNKNOWN. What must not happen is it going unrecorded.
func TestFilteringEverythingIsStillRecorded(t *testing.T) {
	in := []Finding{rated("a", ""), rated("b", "")}
	got, w := severityFilter(in, []string{cvss.High, cvss.Critical})
	if len(got) != 0 {
		t.Errorf("kept %v, want nothing", labels(got))
	}
	if w == nil || w.Count != 2 || w.BySeverity[cvss.Unknown] != 2 {
		t.Fatalf("Withheld = %+v, want both counted as unrated", w)
	}
}
