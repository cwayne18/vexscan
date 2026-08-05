package debver

import "testing"

// TestCompareMatchesDpkg checks orderings dpkg --compare-versions produces, so
// the fix plan's "newest" is the version apt would actually install.
func TestCompareMatchesDpkg(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// The case the fix plan exists for: point releases of one package.
		{"2.36-9+deb12u7", "2.36-9+deb12u14", -1},
		{"2.36-9+deb12u14", "2.36-9+deb12u7", 1},
		{"2.36-9+deb12u3", "2.36-9+deb12u10", -1}, // numeric, not lexical
		{"2.36-9+deb12u1", "2.36-9+deb12u1", 0},
		// Tilde sorts before everything, including the plain version.
		{"252.12-1~deb12u1", "252.12-1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~~a", -1},
		{"1.0~~a", "1.0~", -1},
		// Epochs dominate the rest of the version.
		{"1:1.0", "2.0", 1},
		{"1:2.66-4", "1:2.66-4+deb12u3", -1},
		// Plain numeric and dotted upstream ordering.
		{"1.21.22", "1.21.23", -1},
		{"5.4.1-0.2", "5.4.1-1", -1},
		{"1.2.3", "1.2.3", 0},
		{"1.10.1-3", "1.10.1-3+deb12u1", -1},
		// A missing revision compares as empty and so sorts below any revision.
		{"1.34", "1.34-1", -1},
		{"1:4.13+dfsg1-1+b1", "1:4.13+dfsg1-1+deb12u1", -1}, // b < d
		// Digit-vs-non-digit alignment: dpkg weights a digit as 0, so it sorts
		// before any letter and after '~'. These are the cases the first cut of
		// order() got backwards by letting a digit fall through to c+256.
		{"1.0", "1.a", -1}, // digit 0 sorts before letter a
		{"a1", "aa", -1},   // digit 1 sorts before letter a
		{"1.0", "1.~", 1},  // digit 0 sorts after '~'
		// Decided by the numeric length rule before the 'w' matters: the run
		// "1" is less than "10", so 1.1.1w < 1.1.10 (validated against dpkg).
		{"1.1.1w", "1.1.10", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry: swapping the arguments must negate the result.
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareIsReflexive(t *testing.T) {
	for _, v := range []string{"", "1.0", "2.36-9+deb12u7", "1:2.66-4+deb12u3", "252.12-1~deb12u1"} {
		if got := Compare(v, v); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", v, v, got)
		}
	}
}
