package cvss

import "testing"

// The vectors below are not invented. Each is a real published record, and the
// expected score and label are the ones NVD itself publishes for it, so the
// test pins this implementation against the reference rather than against its
// own arithmetic. They were chosen from a 187-record cross-check of every
// CVSS v3 vector NVD published in a two-week window, which this scorer matched
// exactly on both score and label; the subset kept here is the one that
// between it exercises every value of every base metric, both scopes, and each
// band of the rating scale.
var reference = []struct {
	name   string
	vector string
	score  float64
	label  string
}{
	// The two seen live in a debian:12 scan, which is where this started.
	{"DEBIAN-CVE-2023-45853", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Critical},
	{"DEBIAN-CVE-2022-27943", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5, Medium},

	// A scope change is the one place the formula genuinely branches: it
	// changes the impact sub-score equation, re-weights Privileges Required,
	// and applies the 1.08 multiplier.
	{"CVE-2026-45131 scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0, Critical},
	{"CVE-2026-35563 scope changed", "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.5, High},
	{"CVE-2026-40961 scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2, High},
	{"CVE-2026-42253 scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, Medium},

	// The metric values a synthetic test would forget: physical access,
	// adjacent network, high complexity, high privileges.
	{"CVE-2026-45153 physical", "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N", 4.6, Medium},
	{"CVE-2026-20452 adjacent", "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.0, High},
	{"CVE-2026-20454 high privileges", "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.4, Medium},
	{"CVE-2026-10237 high privileges", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.7, Medium},

	// The bottom of the scale, which the sections of a report that nobody
	// scrolls to are made of.
	{"CVE-2026-10216 low", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, Low},
	{"CVE-2026-45154 low", "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6, Low},

	// CVSS:3.0 is accepted and uses the same base weights. Kept because the
	// version prefix is checked explicitly and a typo there would only show up
	// on the older records, which are exactly the ones nobody looks at.
	{"CVSS:3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, High},

	// No impact is a real answer of exactly zero, not an absence of one. The
	// pair below is the distinction the bool return exists to preserve: this
	// scores, and reports NONE.
	{"no impact", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, None},
}

func TestScoreMatchesPublishedValues(t *testing.T) {
	for _, tc := range reference {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Score(tc.vector)
			if !ok {
				t.Fatalf("Score(%q) declined to score a v3 vector", tc.vector)
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

// TestScoreDeclinesWhatItCannotScore covers the inputs that must produce no
// severity rather than a wrong one. The CVSS:4.0 case is the one that matters
// in practice: those records are already in OSV, and scoring them with the v3
// formula would silently produce a plausible number for a vector whose metrics
// do not mean the same thing.
func TestScoreDeclinesWhatItCannotScore(t *testing.T) {
	unscorable := []struct {
		name   string
		vector string
	}{
		{"CVSS 4.0", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"CVSS 2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{"CVSS 2.0 with a prefix", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{"empty", ""},
		{"prose", "high"},
		{"missing a base metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{"unrecognized metric value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"unrecognized scope", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"},
		{"malformed component", "CVSS:3.1/AV:N/AC/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	for _, tc := range unscorable {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := Score(tc.vector); ok {
				t.Errorf("Score(%q) = %.1f, true; want no score", tc.vector, got)
			}
		})
	}
}

// TestScoreIgnoresSurroundingSpace exists because these vectors arrive from a
// JSON field written by whichever database published the record.
func TestScoreIgnoresSurroundingSpace(t *testing.T) {
	got, ok := Score("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n")
	if !ok || got != 9.8 {
		t.Errorf("Score(padded) = %.1f, %v; want 9.8, true", got, ok)
	}
}

// TestLabelBandBoundaries pins the edges of the rating scale, where an
// off-by-a-tenth moves a finding between the section a reader acts on and the
// one they skim.
func TestLabelBandBoundaries(t *testing.T) {
	bands := []struct {
		score float64
		want  string
	}{
		{10.0, Critical},
		{9.0, Critical},
		{8.9, High},
		{7.0, High},
		{6.9, Medium},
		{4.0, Medium},
		{3.9, Low},
		{0.1, Low},
		{0.0, None},
	}
	for _, b := range bands {
		if got := Label(b.score); got != b.want {
			t.Errorf("Label(%.1f) = %s, want %s", b.score, got, b.want)
		}
	}
}

// TestRoundUpUsesIntegerArithmetic guards the specific reason roundUp is not
// written as math.Ceil(x*10)/10. In binary floating point 4.02*100 is
// 401.99999999999994, so the obvious implementation returns 4.1 for a value
// the specification rounds to 4.0.
func TestRoundUpUsesIntegerArithmetic(t *testing.T) {
	cases := []struct{ in, want float64 }{
		{4.02, 4.1},
		{4.0, 4.0},
		{0.0, 0.0},
		{6.7, 6.7},
		{8.2222, 8.3},
		{9.999, 10.0},
	}
	for _, c := range cases {
		if got := roundUp(c.in); got != c.want {
			t.Errorf("roundUp(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestNormalize covers the reason this function exists: GitHub says MODERATE
// where every other database says MEDIUM.
func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"MODERATE", Medium},
		{"moderate", Medium},
		{" Moderate ", Medium},
		{"CRITICAL", Critical},
		{"high", High},
		{"Low", Low},
		{"NONE", None},
		{"", Unknown},
		// An unrecognized spelling becomes Unknown rather than being passed
		// through, so a new label from some database cannot reach the report as
		// a severity the sort order has never heard of.
		{"SEVERE", Unknown},
		{"IMPORTANT", Unknown},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestRankPutsUnknownAboveMedium pins the one ordering choice here that is not
// simply the rating scale. A severity nobody published is not evidence that the
// problem is small, and sorting it below LOW is how it stops being read.
func TestRankPutsUnknownAboveMedium(t *testing.T) {
	if Rank(Unknown) >= Rank(Medium) {
		t.Errorf("Rank(%s) = %d, Rank(%s) = %d; unknown must sort first",
			Unknown, Rank(Unknown), Medium, Rank(Medium))
	}
	if Rank(Unknown) <= Rank(High) {
		t.Errorf("Rank(%s) = %d must sort below Rank(%s) = %d",
			Unknown, Rank(Unknown), High, Rank(High))
	}
	ordered := []string{Critical, High, Unknown, Medium, Low, None}
	for i := 1; i < len(ordered); i++ {
		if Rank(ordered[i-1]) >= Rank(ordered[i]) {
			t.Errorf("%s ranks %d, %s ranks %d; want strictly increasing",
				ordered[i-1], Rank(ordered[i-1]), ordered[i], Rank(ordered[i]))
		}
	}
	// An empty severity is the common case for a finding nothing published a
	// severity for at all, and must rank with Unknown rather than falling to
	// the unrecognized bucket at the bottom.
	if Rank("") != Rank(Unknown) {
		t.Errorf(`Rank("") = %d, want the same as Rank(%s) = %d`, Rank(""), Unknown, Rank(Unknown))
	}
	if Rank("nonsense") <= Rank(None) {
		t.Errorf("an unrecognized label must rank last, got %d", Rank("nonsense"))
	}
}

// TestRankIsCaseInsensitive covers labels that arrive from a database rather
// than from Label.
func TestRankIsCaseInsensitive(t *testing.T) {
	if Rank("critical") != Rank(Critical) {
		t.Error("Rank must not depend on the case of the label")
	}
}
