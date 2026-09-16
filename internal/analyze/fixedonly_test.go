package analyze

import (
	"testing"

	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// fixable is a linked finding with an upgrade target, and unfixed is the same
// finding before anyone published one. The severity is carried because it is
// what the banner reports.
func fixable(id, label, fix string) Finding {
	f := rated(id, label)
	f.FixedVersion = fix
	return f
}

func TestNoFixedOnlyFilterIsANoOp(t *testing.T) {
	in := []Finding{fixable("a", cvss.Critical, "1.2.3"), rated("b", cvss.Low)}
	got, w := fixedOnlyFilter(in, false)
	if len(got) != 2 {
		t.Errorf("kept %v, want both", labels(got))
	}
	if w != nil {
		t.Errorf("WithheldUnfixed = %+v, want nil so no banner prints", w)
	}
}

func TestFixedOnlyKeepsOnlyWhatHasAFix(t *testing.T) {
	in := []Finding{
		fixable("fixed", cvss.Critical, "1.2.3"),
		rated("open-high", cvss.High),
		rated("open-med", cvss.Medium),
	}
	got, w := fixedOnlyFilter(in, true)
	if len(got) != 1 || got[0].ID != "fixed" {
		t.Errorf("kept %v, want [fixed]", labels(got))
	}
	if w == nil || w.Count != 2 {
		t.Fatalf("WithheldUnfixed = %+v, want 2 dropped", w)
	}
	if w.BySeverity[cvss.High] != 1 || w.BySeverity[cvss.Medium] != 1 {
		t.Errorf("BySeverity = %v, want one high and one medium", w.BySeverity)
	}
}

// Nothing hidden means no banner: the filter ran and had nothing to say, which
// is not the same as having something to say about zero rows.
func TestFixedOnlyReportsNothingWhenEverythingHasAFix(t *testing.T) {
	in := []Finding{fixable("a", cvss.High, "1.1"), fixable("b", cvss.Low, "2.2")}
	got, w := fixedOnlyFilter(in, true)
	if len(got) != 2 {
		t.Errorf("kept %v, want both", labels(got))
	}
	if w != nil {
		t.Errorf("WithheldUnfixed = %+v, want nil: a 'withheld 0' banner is noise", w)
	}
}

// The count this flag is dangerous without. These are not rows that failed to
// clear a bar -- they are open, they apply, and the only thing wrong with them
// is that there is nowhere to upgrade to.
func TestFixedOnlyCountsTheAffectedRowsItHid(t *testing.T) {
	linked := rated("linked", cvss.Critical)
	reachable := rated("reachable", cvss.High)
	reachable.Status = ecosystem.StatusReachable
	ruledOut := rated("not-present", cvss.High)
	ruledOut.Status = ecosystem.StatusNotPresent

	_, w := fixedOnlyFilter([]Finding{linked, reachable, ruledOut}, true)
	if w == nil || w.Count != 3 {
		t.Fatalf("WithheldUnfixed = %+v, want all 3 dropped", w)
	}
	if w.Affected != 2 {
		t.Errorf("Affected = %d, want 2: linked and reachable, not the ruled-out row", w.Affected)
	}
}

// The same exemption severityFilter makes, for the same reason: an id the user
// named by hand that matched nothing has no fix to publish, and dropping it
// here would silently answer "no" to a question that was never resolved.
func TestFixedOnlyStillReportsAnIDThatMatchedNothing(t *testing.T) {
	unmatched := Finding{
		Ecosystem: "os", ID: "CVE-2024-9999", CVE: "CVE-2024-9999",
		Status: ecosystem.StatusUndetermined, Reason: "no_component_matched",
	}
	got, w := fixedOnlyFilter([]Finding{unmatched}, true)
	if len(got) != 1 {
		t.Fatalf("kept %v, want the unmatched id reported", labels(got))
	}
	if w != nil {
		t.Errorf("WithheldUnfixed = %+v, want nil: nothing was hidden", w)
	}
}

// FixedVersions without FixedVersion cannot happen today, and if it ever does
// the row has to survive: over-reporting is the direction this tool errs in.
func TestFixedOnlyKeepsAFindingWithOnlyTheFixList(t *testing.T) {
	f := rated("multi", cvss.High)
	f.FixedVersions = []string{"1.5.9", "1.6.5"}
	got, w := fixedOnlyFilter([]Finding{f}, true)
	if len(got) != 1 {
		t.Errorf("kept %v, want the finding: a fix was published for it", labels(got))
	}
	if w != nil {
		t.Errorf("WithheldUnfixed = %+v, want nil", w)
	}
}

// The two filters compose, and each reports its own stage. --severity runs
// first on the full set; --fixed-only runs on what survived it.
func TestSeverityAndFixedOnlyEachReportTheirOwnStage(t *testing.T) {
	in := []Finding{
		fixable("crit-fixed", cvss.Critical, "1.2.3"),
		rated("crit-open", cvss.Critical),
		rated("low-open", cvss.Low),
	}
	kept, sev := severityFilter(in, []string{cvss.Critical})
	kept, unfixed := fixedOnlyFilter(kept, true)

	if len(kept) != 1 || kept[0].ID != "crit-fixed" {
		t.Errorf("kept %v, want [crit-fixed]", labels(kept))
	}
	if sev == nil || sev.Count != 1 {
		t.Errorf("Withheld = %+v, want the one low finding", sev)
	}
	if unfixed == nil || unfixed.Count != 1 {
		t.Fatalf("WithheldUnfixed = %+v, want the one open critical", unfixed)
	}
	if unfixed.BySeverity[cvss.Critical] != 1 {
		t.Errorf("BySeverity = %v, want one critical", unfixed.BySeverity)
	}
}
