package apkver

import "testing"

// The cases below were written against apk-tools' documented grammar and
// checked against its own test corpus (test/unit/version.data, 767 orderings
// and its full validity list) during development. What is kept here is a
// property-per-case table: one case for each rule the port has to get right, so
// a regression names the rule it broke instead of a line number in someone
// else's data file.

func TestCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
	}{
		// Plain numeric components, compared as numbers and not as text.
		{"equal", "1.2.3", "1.2.3", 0},
		{"patch", "1.2.3", "1.2.4", -1},
		{"ten beats nine", "1.10", "1.9", 1},
		{"initial digit is numeric", "10", "9", 1},
		{"longer continues higher", "1.0", "1.0.1", -1},

		// A leading zero anywhere in a component turns that comparison into a
		// string sort, because the component reads as a fraction. This is the
		// rule apk took from Gentoo and the one a naive port gets wrong.
		{"leading zero sorts as text", "1.01", "1.1", -1},
		{"leading zero both sides", "1.010", "1.09", -1},
		{"no leading zero stays numeric", "1.10", "1.9", 1},

		// A trailing letter is a release of its own, above the bare version.
		{"letter beats bare", "2.3.0b", "2.3.0", 1},
		{"letters order", "1.0a", "1.0b", -1},

		// Pre-release suffixes sort below the version they lead to, in the
		// order alpha, beta, pre, rc.
		{"alpha below bare", "1.0_alpha", "1.0", -1},
		{"alpha below beta", "1.0_alpha", "1.0_beta", -1},
		{"beta below pre", "1.0_beta", "1.0_pre", -1},
		{"pre below rc", "1.0_pre", "1.0_rc", -1},
		{"rc below bare", "1.0_rc", "1.0", -1},
		{"suffix number", "1.0_alpha1", "1.0_alpha2", -1},
		{"bare suffix below numbered", "1.0_alpha", "1.0_alpha1", -1},

		// Post-release suffixes sort above it, in the order cvs, svn, git, hg, p.
		{"cvs above bare", "1.0_cvs", "1.0", 1},
		{"cvs below svn", "1.0_cvs", "1.0_svn", -1},
		{"svn below git", "1.0_svn", "1.0_git", -1},
		{"git below hg", "1.0_git", "1.0_hg", -1},
		{"hg below p", "1.0_hg", "1.0_p", -1},

		// The -rN revision, which neither dpkg nor rpm spells this way.
		{"revision orders", "1.0-r1", "1.0-r2", -1},
		{"revision beats none", "1.0", "1.0-r0", -1},
		{"revision is numeric", "1.0-r10", "1.0-r9", 1},

		// A ~hash commit marker.
		{"commit hash orders", "1.0~1234", "1.0~2345", -1},
		{"revision after hash", "1.0~1234-r0", "1.0~1234-r1", -1},

		// Versions Alpine actually ships, which is what this is for.
		{"busybox rebuild", "1.36.1-r15", "1.36.1-r16", -1},
		{"openssl point release", "3.0.12-r0", "3.1.4-r5", -1},
		{"openssl rebuild", "3.1.4-r5", "3.1.4-r6", -1},
		{"musl", "1.2.4_git20230717-r4", "1.2.5-r0", -1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Compare(c.a, c.b); got != c.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
			}
			// Antisymmetry is not decoration here: sortEvents in package osv
			// sorts range boundaries with this, and a comparator that is not
			// antisymmetric produces an order that depends on input order.
			if got := Compare(c.b, c.a); got != -c.want {
				t.Errorf("Compare(%q, %q) = %d, want %d (not antisymmetric)", c.b, c.a, got, -c.want)
			}
		})
	}
}

func TestValid(t *testing.T) {
	valid := []string{
		"1", "1.2", "1.2.3", "1.0a", "1.0_alpha", "1.0_alpha1", "1.0_p1",
		"1.0-r0", "1.36.1-r15", "1.2.4_git20230717-r4", "0.1_pre2~1234abcd",
		"0.1_p1_pre2", "3.1.4-r5",
	}
	for _, v := range valid {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false, want true", v)
		}
	}

	// Every one of these would otherwise be compared against something, and a
	// comparison of nonsense is worse than declining to make one: package osv
	// keeps the advisory and says it could not check the version.
	invalid := []string{
		"",                  // nothing at all
		"a",                 // must start with a digit
		".1",                // must start with a digit
		"0.1bc",             // only one trailing letter is allowed
		"0.1a1",             // no digits after a letter
		"0.1_foobar",        // not a suffix apk knows
		"0.1_",              // suffix with no name
		"0.1__alpha",        // empty suffix name
		"0.1-r",             // revision with no number
		"0.1-r2-r3",         // one revision only
		"0.1-r2.1",          // nothing follows a revision
		"0.1-r2_pre1",       // a suffix cannot follow a revision
		"0.1_pre2~",         // hash marker with no hash
		"0.1_pre2~1234xbcd", // not hex
		"-r1",               // no version
		"1.0 ",              // trailing space is not part of the grammar
	}
	for _, v := range invalid {
		if Valid(v) {
			t.Errorf("Valid(%q) = true, want false", v)
		}
	}
}
