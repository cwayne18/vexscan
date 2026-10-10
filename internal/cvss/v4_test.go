package cvss

import "testing"

// The vectors below are not invented, same as the v3 reference table: each is
// the exact vectorString and baseScore NVD itself publishes for the CVE, so
// this pins the implementation against the reference rather than against its
// own arithmetic. They were chosen because NVD had, at the time, scored each
// one with CVSS:4.0 in addition to (and disagreeing with) a v3.1 score from
// the reporting CNA -- which is what makes them good regression fixtures:
// real vectors, covering a spread of the rating scale, with a known-correct
// answer from the authority that minted the score.
var v4Reference = []struct {
	name   string
	vector string
	score  float64
	label  string
}{
	{"CVE-2024-7450 low exposure", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 5.3, Medium},
	{"CVE-2024-7450 full compromise", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 8.7, High},
	{"CVE-2024-7451 low exposure", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 5.3, Medium},
	{"CVE-2024-7452 full compromise", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 8.7, High},
	{"CVE-2024-7871 full compromise", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 8.7, High},
	{"CVE-2025-3067 requires user interaction", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 8.6, High},
}

func TestV4ScoreMatchesPublishedValues(t *testing.T) {
	for _, tc := range v4Reference {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Score(tc.vector)
			if !ok {
				t.Fatalf("Score(%q) declined to score a v4.0 vector", tc.vector)
			}
			if got != tc.score {
				t.Errorf("Score(%q) = %.1f, published value is %.1f", tc.vector, got, tc.score)
			}
			if label := Label(got); label != tc.label {
				t.Errorf("Label(%.1f) = %s, published rating is %s", got, label, tc.label)
			}
		})
	}
}

// TestV4NoImpactScoresExactlyZero covers the shortcut the specification
// defines separately from the lookup table: when every impact metric is None,
// the score is exactly 0.0, not a number the MacroVector table happens to
// produce for the lowest row.
func TestV4NoImpactScoresExactlyZero(t *testing.T) {
	got, ok := Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	if !ok || got != 0.0 {
		t.Errorf("Score(no impact) = %.1f, %v; want 0.0, true", got, ok)
	}
	if label := Label(got); label != None {
		t.Errorf("Label(0.0) = %s, want %s", label, None)
	}
}

// TestV4WorstCaseScoresTen pins the opposite corner: every base metric at its
// most severe value is the one vector guaranteed to be in the lookup table
// with no interpolation at all.
func TestV4WorstCaseScoresTen(t *testing.T) {
	got, ok := Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if !ok || got != 10.0 {
		t.Errorf("Score(worst case) = %.1f, %v; want 10.0, true", got, ok)
	}
}

// TestV4ModifiedMetricsOverrideBase covers the one mechanism unique to v4.0's
// environmental metrics: an MVC/MVI/... value, when present and not X, is
// used in place of the base VC/VI/... value for scoring, even though the base
// value is still what a reader sees printed in the vector.
func TestV4ModifiedMetricsOverrideBase(t *testing.T) {
	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
	got, ok := Score(base)
	if !ok || got != 0.0 {
		t.Fatalf("Score(%q) = %.1f, %v; want 0.0, true", base, got, ok)
	}
	modified := base + "/MVC:H/MVI:H/MVA:H"
	got, ok = Score(modified)
	if !ok {
		t.Fatalf("Score(%q) declined to score", modified)
	}
	if got == 0.0 {
		t.Errorf("Score(%q) = 0.0; MVC/MVI/MVA:H should have raised the score above the unmodified base's", modified)
	}
}

// TestV4SafetyModifierSelectsEQ4Zero covers MSI:S/MSA:S, the one base-metric
// override that does not have a corresponding plain value on SI/SA -- Safety
// is reachable only through the modified metric, and the MacroVector's EQ4
// digit reads it directly rather than through the usual effective-value
// fallback.
func TestV4SafetyModifierSelectsEQ4Zero(t *testing.T) {
	without, ok := Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if !ok {
		t.Fatal("Score declined without MSI")
	}
	withSafety, ok := Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S")
	if !ok {
		t.Fatal("Score declined with MSI:S")
	}
	if withSafety < without {
		t.Errorf("Score with MSI:S = %.1f, want it at least as severe as without (%.1f)", withSafety, without)
	}
}

// TestV4DeclinesWhatItCannotScore mirrors the v3 test of the same shape: these
// must produce no severity rather than a wrong one.
func TestV4DeclinesWhatItCannotScore(t *testing.T) {
	unscorable := []struct {
		name   string
		vector string
	}{
		{"missing a base metric", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H"},
		{"unrecognized base metric value", "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
		{"unrecognized optional metric value", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:Z"},
		{"malformed component", "CVSS:4.0/AV:N/AC/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
	}
	for _, tc := range unscorable {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := Score(tc.vector); ok {
				t.Errorf("Score(%q) = %.1f, true; want no score", tc.vector, got)
			}
		})
	}
}

// TestV4RoundingMatchesToFixedTieBreak guards the specific reason
// roundHalfUp1 goes through math/big instead of strconv.FormatFloat or a
// x*10+0.5 truncation. 4.25 is exactly representable in binary, so it is a
// genuine tie between 4.2 and 4.3; the specification's reference calculator
// gets "4.3" from JavaScript's toFixed(1), which breaks a tie toward the
// larger magnitude, not the even digit Go's own float-to-decimal formatting
// would pick.
func TestV4RoundingMatchesToFixedTieBreak(t *testing.T) {
	cases := []struct{ in, want float64 }{
		{4.25, 4.3},
		{0.25, 0.3},
		{8.65, 8.7},
		{0.0, 0.0},
		{10.0, 10.0},
		{4.24, 4.2},
		{4.26, 4.3},
	}
	for _, c := range cases {
		if got := roundHalfUp1(c.in); got != c.want {
			t.Errorf("roundHalfUp1(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
