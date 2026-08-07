package rpmver

import "testing"

// The rpmvercmp cases below are rpm's own regression vectors from
// tests/rpmvercmp.at, the authoritative statement of how rpm orders versions.
// Porting them verbatim is the only way to be sure the port did not drift, since
// a drift here clears a CVE the vendor never cleared.
func TestRPMVerCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1a", 0},
		{"2.0.1a", "2.0.1", 1},
		{"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0},
		{"5.5p1", "5.5p2", -1},
		{"5.5p2", "5.5p1", 1},
		{"5.5p10", "5.5p10", 0},
		{"5.5p1", "5.5p10", -1},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"10.1xyz", "10xyz", 1},
		{"xyz10", "xyz10", 0},
		{"xyz10", "xyz10.1", -1},
		{"xyz10.1", "xyz10", 1},
		{"xyz.4", "xyz.4", 0},
		{"xyz.4", "8", -1},
		{"8", "xyz.4", 1},
		{"xyz.4", "2", -1},
		{"2", "xyz.4", 1},
		{"5.5p2", "5.6p1", -1},
		{"5.6p1", "5.5p2", 1},
		{"5.6p1", "6.5p1", -1},
		{"6.5p1", "5.6p1", 1},
		{"6.0.rc1", "6.0", 1},
		{"6.0", "6.0.rc1", -1},
		{"10b2", "10a1", 1},
		{"10a2", "10b2", -1},
		{"1.0aa", "1.0aa", 0},
		{"1.0a", "1.0aa", -1},
		{"1.0aa", "1.0a", 1},
		{"10.0001", "10.0001", 0},
		{"10.0001", "10.1", 0},
		{"10.1", "10.0001", 0},
		{"10.0001", "10.0039", -1},
		{"10.0039", "10.0001", 1},
		{"4.999.9", "5.0", -1},
		{"5.0", "4.999.9", 1},
		{"20101121", "20101121", 0},
		{"20101121", "20101122", -1},
		{"20101122", "20101121", 1},
		{"2_0", "2_0", 0},
		{"2.0", "2_0", 0},
		{"2_0", "2.0", 0},
		// The separator-run cases: a dot and an underscore are both just a
		// boundary, so "2.0.1" ties "2_0.1".
		{"a", "a", 0},
		{"a+", "a+", 0},
		{"a+", "a_", 0},
		{"a_", "a+", 0},
		{"+a", "+a", 0},
		{"+a", "_a", 0},
		{"_a", "+a", 0},
		{"+_", "+_", 0},
		{"_+", "+_", 0},
		{"_+", "_+", 0},
		{"+", "_", 0},
		{"_", "+", 0},
		// Tilde: sorts before, including before the empty string.
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc2", "1.0~rc1", 1},
		{"1.0~rc1~git123", "1.0~rc1~git123", 0},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0~rc1", "1.0~rc1~git123", 1},
		// Caret: sorts after, but a bare end of string still outranks it.
		{"1.0^", "1.0^", 0},
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^git1", "1.0^git1", 0},
		{"1.0^git1", "1.0", 1},
		{"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git2", "1.0^git1", 1},
		{"1.0^git1", "1.01", -1},
		{"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0^20160101", 0},
		{"1.0^20160101", "1.0.1", -1},
		{"1.0^20160101^git1", "1.0^20160101^git1", 0},
		{"1.0^20160102", "1.0^20160101^git1", 1},
		{"1.0~rc1^git1", "1.0~rc1^git1", 0},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc1^git1", -1},
		{"1.0^git1~pre", "1.0^git1~pre", 0},
		{"1.0^git1", "1.0^git1~pre", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); got != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry is a property rpmvercmp must have, and cheap to assert.
		if got := rpmvercmp(c.b, c.a); got != -c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// Compare adds epoch and release handling on top of rpmvercmp; these check the
// pieces the raw segment compare does not see.
func TestCompareEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Plain version-release, the shape SUSE quotes fixes in.
		{"1.1.1l-150500.15.4", "1.1.1l-150500.15.4", 0},
		{"1.1.1l-150500.15.4", "1.1.1l-150500.15.5", -1},
		{"1.1.1l-150500.15.5", "1.1.1l-150500.15.4", 1},
		{"1.1.1l-150500.15.4", "1.1.1w-150500.17.1", -1},
		{"3.0.8-150500.3.1", "1.1.1l-150500.15.4", 1},
		// Epoch is compared only when both sides carry one; then it dominates.
		{"2:1.0-1", "1:9.9-9", 1},
		{"1:1.0-1", "1:2.0-1", -1},
		{"0:1.0-1", "1.0-1", 0},
		// Mixed epoch fails closed: when one side has an epoch and the other
		// does not, a non-zero epoch cannot be proven to outrank the unknown, so
		// the epoch-bearing side sorts below the bare one. This is what stops an
		// installed "1:1.0" (the database always stamps an epoch) from clearing
		// against a vendor fix "2.0" quoted without one.
		{"1:1.0-1", "2.0-1", -1},
		{"2.0-1", "1:1.0-1", 1},
		// A missing release means "the version line", so it ties any release of
		// the same version rather than being ordered below it.
		{"1.1.1l", "1.1.1l-150500.15.4", 0},
		{"1.1.1l-150500.15.4", "1.1.1l", 0},
		{"1.1.1l", "1.1.1w", -1},
		// A malformed epoch must not read as a number and win.
		{"x:1.0-1", "1.0-1", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The property the SUSE feed leans on: an installed version at or above the fix
// compares >= 0, and one below compares < 0. This is the exact test the provider
// uses to decide whether an already-shipped fix clears a finding.
func TestCompareFixThreshold(t *testing.T) {
	fixed := "1.1.1l-150500.15.4"
	atOrAbove := []string{
		"1.1.1l-150500.15.4",   // exactly the fix
		"1.1.1l-150500.15.5",   // newer release
		"1.1.1w-150500.17.1",   // newer version
		"0:1.1.1l-150500.15.4", // epoch-0 installed against an epoch-less fix
	}
	for _, v := range atOrAbove {
		if Compare(v, fixed) < 0 {
			t.Errorf("installed %q should be >= fix %q", v, fixed)
		}
	}
	below := []string{
		"1.1.1k-150500.15.4", // older version
		"1.1.1l-150500.15.3", // older release
		"1.1.0i-150100.14.45.1",
		// An installed non-zero epoch does not clear an epoch-less fix: the
		// version is plainly below the fix and the epoch cannot rescue it.
		"1:1.0.0-1",
	}
	for _, v := range below {
		if Compare(v, fixed) >= 0 {
			t.Errorf("installed %q should be < fix %q", v, fixed)
		}
	}
}

// CompareInstalledToFix is Compare with the operand order fixed by its name, and
// the point of it is that the epoch rule no longer depends on getting that order
// right. Compare's asymmetry is real -- {"2.0-1", "1:1.0-1", 1} above is the same
// unprovable epoch comparison as {"1:1.0-1", "2.0-1", -1}, answered the opposite
// way -- and in a clearing decision the two directions are not equally wrong. One
// leaves a false positive in the report; the other clears a package that has not
// reached the fix, which is a real CVE waved through.
func TestCompareInstalledToFixClosesBothEpochDirections(t *testing.T) {
	// Every one of these must refuse to clear. The installed version is not
	// provably at or above the fix in any of them.
	unprovable := []struct{ installed, fix string }{
		// The database stamps an epoch, SUSE's CSAF quotes the fix without one.
		{"1:1.0-1", "2.0-1"},
		// The mirror image, which raw Compare answers 1 -- "already fixed".
		{"2.0-1", "1:1.0-1"},
		// And where the version alone would clear it, so only the epoch rule
		// stands between this and a wrongly-cleared finding.
		{"9.9-9", "1:1.0-1"},
	}
	for _, c := range unprovable {
		if got := CompareInstalledToFix(c.installed, c.fix); got >= 0 {
			t.Errorf("CompareInstalledToFix(%q, %q) = %d, want < 0: exactly one side states an epoch, "+
				"so the ordering is unprovable and must not clear", c.installed, c.fix, got)
		}
	}

	// An epoch of 0 on one side proves nothing either way, so it falls through to
	// the version -- the ordinary shape, and it must still clear normally.
	same := []struct{ installed, fix string }{
		{"0:1.1.1l-150500.15.4", "1.1.1l-150500.15.4"}, // equal
		{"0:1.1.1w-150500.17.1", "1.1.1l-150500.15.4"}, // past the fix
		{"1.1.1w-150500.17.1", "0:1.1.1l-150500.15.4"},
	}
	for _, c := range same {
		if got := CompareInstalledToFix(c.installed, c.fix); got < 0 {
			t.Errorf("CompareInstalledToFix(%q, %q) = %d, want >= 0: an epoch of 0 is not a reason to withhold a clear",
				c.installed, c.fix, got)
		}
	}

	// With no epoch in play, or with one on both sides, it is Compare exactly.
	agree := []struct{ installed, fix string }{
		{"1.1.1l-150500.15.4", "1.1.1l-150500.15.4"},
		{"1.1.1k-150500.15.4", "1.1.1l-150500.15.4"},
		{"1.1.1w-150500.17.1", "1.1.1l-150500.15.4"},
		{"2:1.0-1", "1:9.9-9"},
		{"1:1.0-1", "1:2.0-1"},
	}
	for _, c := range agree {
		if got, want := CompareInstalledToFix(c.installed, c.fix), Compare(c.installed, c.fix); got != want {
			t.Errorf("CompareInstalledToFix(%q, %q) = %d, want %d (Compare): with no mixed epoch the two must agree",
				c.installed, c.fix, got, want)
		}
	}
}
