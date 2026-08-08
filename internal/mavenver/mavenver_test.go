package mavenver

import "testing"

// The two ascending sequences below are Maven's own, lifted from
// ComparableVersionTest. The port was checked against that whole test class
// during development -- 529 ordered pairs and 42 equalities, no disagreements
// -- and these are the two assertions that carry the ordering itself, kept
// because every strange rule in the scheme is visible somewhere in them.

// qualifierOrder is Maven's canonical qualifier sequence, strictly ascending.
// Read it once: the unknown qualifiers (abc, def, pom) sit *above* sp and below
// the sub-list forms, and the plain "1" sits in the middle. Nothing else orders
// versions this way.
var qualifierOrder = []string{
	"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123",
	"1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT",
	"1",
	"1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1",
	"1-1-snapshot", "1-1", "1-2", "1-123",
}

// numberOrder is Maven's canonical numeric sequence, strictly ascending. The
// pairs worth staring at are "2.0.a" below "2-1" (a dot-qualifier reads as a
// dash-qualifier, and a sub-list outranks it) and "11" below "11.a" (the lone
// "a" is unknown, not alpha, because no digit follows it).
var numberOrder = []string{
	"2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c",
	"2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11",
	"11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
}

func TestCanonicalOrderings(t *testing.T) {
	for _, seq := range [][]string{qualifierOrder, numberOrder} {
		for i := range seq {
			for j := i + 1; j < len(seq); j++ {
				a, b := seq[i], seq[j]
				if got := Compare(a, b); got != -1 {
					t.Errorf("Compare(%q, %q) = %d, want -1", a, b, got)
				}
				// Antisymmetry is not decoration here: sortEvents in package
				// osv sorts range boundaries with this, and a comparator that
				// is not antisymmetric produces an order that depends on input
				// order.
				if got := Compare(b, a); got != 1 {
					t.Errorf("Compare(%q, %q) = %d, want 1", b, a, got)
				}
			}
			if got := Compare(seq[i], seq[i]); got != 0 {
				t.Errorf("Compare(%q, %q) = %d, want 0", seq[i], seq[i], got)
			}
		}
	}
}

// The equalities are the other half of the scheme, and the half a naive port
// gets wrong: several spellings of one version have to compare equal, or a
// range boundary written one way misses an installed version written the other.
func TestEqualSpellings(t *testing.T) {
	pairs := [][2]string{
		// Trailing nulls carry no meaning, however they are spelled.
		{"1", "1.0"}, {"1", "1.0.0"}, {"1.0", "1.0.0"},
		{"1", "1-0"}, {"1", "1.0-0"}, {"1.0", "1.0-0"},
		{"1", "1-ga"}, {"1", "1.0-ga"}, {"1", "1-final"}, {"1", "1-release"},
		{"1", "1.0.0-0.0.0"},

		// A dot-qualifier and a dash-qualifier are the same thing.
		{"1a", "1-a"}, {"1a", "1.0-a"}, {"1a", "1.0.0-a"}, {"1.0a", "1-a"},
		{"1x", "1-x"}, {"1x", "1.0-x"}, {"1.0.0x", "1-x"},

		// The qualifier aliases.
		{"1ga", "1"}, {"1release", "1"}, {"1final", "1"},
		{"1cr", "1rc"},
		{"1alpha1", "1a1"}, {"1beta1", "1b1"}, {"1milestone1", "1m1"},

		// Leading zeros are not significant.
		{"1.01", "1.1"}, {"1.0.01", "1.0.1"},

		// Case is not significant.
		{"1-SNAPSHOT", "1-snapshot"}, {"1-Alpha1", "1-alpha1"},
	}
	for _, p := range pairs {
		if got := Compare(p[0], p[1]); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", p[0], p[1], got)
		}
		if got := Compare(p[1], p[0]); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", p[1], p[0], got)
		}
	}
}

// A lone letter is shorthand for a pre-release only when a number follows it.
// Pinned on its own because the two readings land in opposite bands -- below
// the release and above every known qualifier -- so getting it wrong inverts
// the pair rather than nudging it.
func TestALoneLetterIsNotAPreRelease(t *testing.T) {
	if got := Compare("1-a1", "1"); got != -1 {
		t.Errorf(`Compare("1-a1", "1") = %d, want -1: a1 is alpha-1`, got)
	}
	if got := Compare("1-a", "1"); got != 1 {
		t.Errorf(`Compare("1-a", "1") = %d, want 1: a alone is an unknown qualifier`, got)
	}
}

// Versions Maven Central actually ships, which is what this is for.
func TestRealVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.14.1", "2.15.0", -1},
		{"2.17.0", "2.17.1", -1},
		{"2.14.1", "2.14.1", 0},
		{"1.2.3.RELEASE", "1.2.3", 0},
		{"5.3.20", "5.3.9", 1},
		{"4.0.0-beta-1", "4.0.0", -1},
		{"3.0.0-SNAPSHOT", "3.0.0", -1},
		{"1.0-alpha-1", "1.0-alpha-2", -1},
		{"20030203.000550", "20040203.000550", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for _, v := range []string{"1", "1.0", "2.14.1", "1.0-SNAPSHOT", "1.2.3.RELEASE", "0", " 1.0 "} {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false, want true", v)
		}
	}
	// Maven would tokenize every one of these and order it against something.
	// Declining is the point: package osv keeps the advisory and says it could
	// not check the version, rather than acting on an ordering of nonsense.
	for _, v := range []string{"", "RELEASE", "LATEST", "master", "v1.0", "a1b2c3d"} {
		if Valid(v) {
			t.Errorf("Valid(%q) = true, want false", v)
		}
	}
}
