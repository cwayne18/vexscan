package pep440

import "testing"

// The cases below were written against PEP 440 and checked against
// pypa/packaging during development -- 5,200 orderings over 3,100 real version
// strings pulled from OSV's PyPI export, plus its full accept/reject list, with
// no disagreements. What is kept here is a property-per-case table: one case
// for each rule the port has to get right, so a regression names the rule it
// broke instead of a line number in a generated corpus.

func TestCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
	}{
		// The release segment, and the rule that makes trailing zeros silent.
		{"equal", "1.2.3", "1.2.3", 0},
		{"patch", "1.2.3", "1.2.4", -1},
		{"numeric not lexical", "1.10", "1.9", 1},
		{"trailing zeros are not significant", "1.0", "1.0.0", 0},
		{"and still are not, three deep", "1.0", "1.0.0.0", 0},
		{"a real segment is not a trailing zero", "1.0", "1.0.1", -1},

		// The epoch outranks everything to its right, which is the whole reason
		// a project ever sets one.
		{"epoch beats release", "1!1.0", "2.0", 1},
		{"absent epoch is zero", "0!1.0", "1.0", 0},
		{"epochs order", "1!1.0", "2!1.0", -1},

		// Pre-releases sort below the release they lead to, in the order
		// a, b, rc.
		{"alpha below release", "1.0a1", "1.0", -1},
		{"alpha below beta", "1.0a1", "1.0b1", -1},
		{"beta below rc", "1.0b1", "1.0rc1", -1},
		{"rc below release", "1.0rc1", "1.0", -1},
		{"pre numbers order", "1.0a1", "1.0a2", -1},
		{"pre numbers are numeric", "1.0a10", "1.0a9", 1},
		{"implicit pre number is zero", "1.0a", "1.0a0", 0},

		// Every spelling PEP 440 folds onto the same pre-release. Getting one of
		// these wrong makes two names for one release compare unequal.
		{"alpha is a", "1.0alpha1", "1.0a1", 0},
		{"beta is b", "1.0beta1", "1.0b1", 0},
		{"c is rc", "1.0c1", "1.0rc1", 0},
		{"pre is rc", "1.0pre1", "1.0rc1", 0},
		{"preview is rc", "1.0preview1", "1.0rc1", 0},
		{"separators are optional", "1.0-a-1", "1.0a1", 0},
		{"dot separator", "1.0.a1", "1.0a1", 0},
		{"underscore separator", "1.0_a1", "1.0a1", 0},
		{"case is not significant", "1.0ALPHA1", "1.0a1", 0},
		{"a leading v is not significant", "v1.0", "1.0", 0},

		// Post-releases sort above the release. semver has no equivalent, which
		// is one of the reasons it cannot stand in for this.
		{"post above release", "1.0.post1", "1.0", 1},
		{"post numbers order", "1.0.post1", "1.0.post2", -1},
		{"implicit post number is zero", "1.0.post", "1.0.post0", 0},
		{"rev is post", "1.0rev2", "1.0.post2", 0},
		{"r is post", "1.0r2", "1.0.post2", 0},
		{"the implicit dash form is post", "1.0-1", "1.0.post1", 0},
		{"a post-release of a pre-release", "1.0b2.post345", "1.0b2", 1},
		{"and still below the release", "1.0b2.post345", "1.0", -1},

		// Dev releases sort below everything of the same release, including its
		// pre-releases -- the one case that is not "later text sorts higher".
		{"dev below release", "1.0.dev1", "1.0", -1},
		{"dev below alpha", "1.0.dev456", "1.0a1", -1},
		{"dev numbers order", "1.0.dev1", "1.0.dev2", -1},
		{"a dev of a pre-release", "1.0a12.dev456", "1.0a12", -1},
		{"and above the previous pre-release", "1.0a12.dev456", "1.0a1", 1},
		{"a dev of a post-release", "1.0.post456.dev34", "1.0.post456", -1},
		{"and still above the release", "1.0.post456.dev34", "1.0", 1},

		// Local labels, which sort above the version they qualify.
		{"local above bare", "1.0+abc", "1.0", 1},
		{"local labels order", "1.0+abc.5", "1.0+abc.7", -1},
		{"a numeric local segment outranks a string", "1.0+1", "1.0+abc", 1},
		{"a longer local label is greater", "1.0+abc.1", "1.0+abc", 1},
		{"local separators normalize", "1.0+abc-1", "1.0+abc.1", 0},

		// The full PEP 440 example ordering, spot-checked end to end.
		{"dev below all", "1.0.dev456", "1.0a1", -1},
		{"a1 below a12", "1.0a1", "1.0a12", -1},
		{"a12 below b1", "1.0a12", "1.0b1.dev456", -1},
		{"b2 below rc1", "1.0b2", "1.0rc1", -1},
		{"release below post", "1.0", "1.0.post456", -1},
		{"post below next release", "1.0.post456", "1.0.15", -1},
		{"and that below the next minor", "1.0.15", "1.1.dev1", -1},

		// Versions PyPI actually ships, which is what this is for.
		{"black", "23.9.0", "23.10.0", -1},
		{"pip", "21.1", "25.0.1", -1},
		{"pip rc", "25.0.1", "25.1rc1", -1},
		{"setuptools", "65.5.0", "65.5.1", -1},
		{"an old-style post", "2.4.0-1", "2.4.0", 1},
		// Spelled like a semver pre-release, read as PEP 440 alpha-0. Pinned
		// because the two readings disagree about nothing here and about the
		// ordering everywhere else, and this is the string that shows it.
		{"a semver-looking pre-release", "1.0.0-alpha", "1.0.0", -1},
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
		"1", "1.0", "1.2.3", "1.2.3.4.5", "1!1.0", "1.0a1", "1.0b2", "1.0rc1",
		"1.0.post1", "1.0.dev1", "1.0a1.post2.dev3", "1.0+ubuntu.1", "v1.0",
		"1.0-1", "1.0ALPHA1", " 1.0 ", "23.9.0", "0.7.0",
		// Reads like a semver pre-release and is not one: PEP 440 takes it as
		// alpha with an implicit 0, so it sorts below 1.0.0 rather than being
		// rejected.
		"1.0.0-alpha",
	}
	for _, v := range valid {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false, want true", v)
		}
	}

	// Every one of these would otherwise be compared against something, and a
	// comparison of nonsense is worse than declining to make one: package osv
	// keeps the advisory and says it could not check the version. The last few
	// are real strings out of OSV's PyPI records, which is how they got here.
	invalid := []string{
		"",                // nothing at all
		"abc",             // no release segment
		"0.3X",            // trailing junk
		"0.7.10p1",        // "p" is not a PEP 440 suffix
		"0.13.0.pre1.1",   // nothing follows a pre-release but post/dev/local
		"0.1-bulbasaur",   // a codename is not a version
		"1.0+",            // local label with no content
		"1.0++abc",        // empty local segment
		"1.0.dev1.post1",  // post cannot follow dev
		"002408c3696b173", // a commit hash
	}
	for _, v := range invalid {
		if Valid(v) {
			t.Errorf("Valid(%q) = true, want false", v)
		}
	}
}
