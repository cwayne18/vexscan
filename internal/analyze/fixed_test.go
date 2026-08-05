package analyze

import "testing"

// One advisory, two packages built from the same source, each with its own
// fixed version. The overlay must key on the package name, not just the
// advisory, so libgcc-s1 and libstdc++6 do not borrow each other's version.
func TestFixedOverlayJoinsOnPackage(t *testing.T) {
	fixed := map[string]map[string]string{
		"CVE-2022-27943": {
			"libgcc-s1":  "12.2.0-14+deb12u3",
			"libstdc++6": "12.2.0-14+deb12u3",
		},
		"CVE-2025-8941": {"pam": "1.5.2-6+deb12u2"},
	}
	findings := []Finding{
		{CVE: "CVE-2022-27943", ID: "CVE-2022-27943", Package: "libgcc-s1"},
		{CVE: "CVE-2022-27943", ID: "CVE-2022-27943", Package: "libstdc++6"},
		// Matched on the CVE, but the advisory has no fix for this package.
		{CVE: "CVE-2025-8941", ID: "CVE-2025-8941", Package: "something-else"},
		// Nothing was resolved for this advisory at all.
		{CVE: "CVE-9999-0000", ID: "CVE-9999-0000", Package: "libc6"},
	}
	fixedOverlay(findings, fixed)

	if got := findings[0].FixedVersion; got != "12.2.0-14+deb12u3" {
		t.Errorf("libgcc-s1 FixedVersion = %q", got)
	}
	if got := findings[1].FixedVersion; got != "12.2.0-14+deb12u3" {
		t.Errorf("libstdc++6 FixedVersion = %q", got)
	}
	// A published fix for another package is not a fix for this one. Empty is
	// the honest answer, which the renderer shows as "no fix".
	if got := findings[2].FixedVersion; got != "" {
		t.Errorf("FixedVersion = %q, want empty when no fix covers this package", got)
	}
	if got := findings[3].FixedVersion; got != "" {
		t.Errorf("FixedVersion = %q, want empty for an unresolved advisory", got)
	}
}

// When Package is empty, the join falls back to Component(), which for an OS
// finding is the binary name derived from the purl.
func TestFixedOverlayFallsBackToComponent(t *testing.T) {
	fixed := map[string]map[string]string{
		"CVE-1": {"libc6": "2.36-9+deb12u15"},
	}
	findings := []Finding{{CVE: "CVE-1", ID: "CVE-1", PURL: "pkg:deb/debian/libc6@2.36-9+deb12u14"}}
	fixedOverlay(findings, fixed)
	if got := findings[0].FixedVersion; got != "2.36-9+deb12u15" {
		t.Errorf("FixedVersion = %q, want the version keyed by Component()", got)
	}
}

func TestFixedOverlayWithAnEmptyMapChangesNothing(t *testing.T) {
	findings := []Finding{{CVE: "CVE-1", Package: "libc6"}}
	fixedOverlay(findings, nil)
	if findings[0].FixedVersion != "" {
		t.Errorf("FixedVersion = %q", findings[0].FixedVersion)
	}
}
