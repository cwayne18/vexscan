package analyze

import (
	"strings"
	"testing"
)

// deb is a Debian package's published fixes, the single-fix shape that covers
// nearly every distro record.
func deb(versions ...string) fixCandidates {
	return fixCandidates{ecosystem: "Debian:12", versions: versions}
}

// One advisory, two packages built from the same source, each with its own
// fixed version. The overlay must key on the package name, not just the
// advisory, so libgcc-s1 and libstdc++6 do not borrow each other's version.
func TestFixedOverlayJoinsOnPackage(t *testing.T) {
	fixed := map[string]map[string]fixCandidates{
		"CVE-2022-27943": {
			"libgcc-s1":  deb("12.2.0-14+deb12u3"),
			"libstdc++6": deb("12.2.0-14+deb12u3"),
		},
		"CVE-2025-8941": {"pam": deb("1.5.2-6+deb12u2")},
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
	// One fix is not a choice, so nothing is disclosed as an alternative.
	for i, f := range findings {
		if len(f.FixedVersions) != 0 {
			t.Errorf("findings[%d].FixedVersions = %q, want none for a single fix", i, f.FixedVersions)
		}
	}
}

// When Package is empty, the join falls back to Component(), which for an OS
// finding is the binary name derived from the purl.
func TestFixedOverlayFallsBackToComponent(t *testing.T) {
	fixed := map[string]map[string]fixCandidates{
		"CVE-1": {"libc6": deb("2.36-9+deb12u15")},
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

// The case the list exists for. GO-2022-0623 fixed Vault in three maintained
// branches; a 1.5.4 install upgrades to 1.5.9, not to 1.7.2, and the report
// still has to be able to say the other two exist.
func TestFixedOverlayPicksTheNearestBranchAndKeepsTheRest(t *testing.T) {
	fixed := map[string]map[string]fixCandidates{
		"GO-2022-0623": {"github.com/hashicorp/vault": {
			ecosystem: "Go",
			versions:  []string{"1.5.9", "1.6.5", "1.7.2"},
		}},
	}
	findings := []Finding{{
		GoID: "GO-2022-0623", ID: "GO-2022-0623",
		Package: "github.com/hashicorp/vault", Version: "1.5.4",
	}}
	fixedOverlay(findings, fixed)

	if got := findings[0].FixedVersion; got != "1.5.9" {
		t.Errorf("FixedVersion = %q, want the lowest fix above 1.5.4", got)
	}
	if got := strings.Join(findings[0].FixedVersions, ","); got != "1.5.9,1.6.5,1.7.2" {
		t.Errorf("FixedVersions = %q, want every branch kept for disclosure", got)
	}
}

func TestPickFix(t *testing.T) {
	cases := []struct {
		name       string
		ecosystem  string
		installed  string
		candidates []string
		want       string
	}{
		{"nothing published", "Debian:12", "1.0", nil, ""},
		{"the ordinary single fix", "Debian:12", "1.0", []string{"1.1"}, "1.1"},

		// Ordered ecosystems pick the nearest branch above what is installed.
		{"go picks the nearest branch", "Go", "1.5.4", []string{"1.5.9", "1.6.5", "1.7.2"}, "1.5.9"},
		{"go on a later branch", "Go", "1.6.1", []string{"1.5.9", "1.6.5", "1.7.2"}, "1.6.5"},
		{"go past every branch", "Go", "1.8.0", []string{"1.5.9", "1.6.5", "1.7.2"}, "1.7.2"},
		{"npm", "npm", "4.17.15", []string{"4.17.19", "4.17.21"}, "4.17.19"},
		{"dpkg epochs and tildes", "Debian:12", "1:1.2.13~rc1-1", []string{"1:1.2.13-1", "1:1.3-1"}, "1:1.2.13-1"},
		{"ubuntu", "Ubuntu:22.04:LTS", "3.0.2-0ubuntu1.1", []string{"3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15"}, "3.0.2-0ubuntu1.10"},

		// Published out of order: the list is publication order, not sorted, so
		// the pick has to compare rather than take the first that qualifies.
		{"descending list", "Go", "1.5.4", []string{"1.7.2", "1.6.5", "1.5.9"}, "1.5.9"},

		// Unordered ecosystems keep the last published version, which overshoots
		// rather than naming a version that may not contain the fix.
		{"pypi is not semver", "PyPI", "1.0rc1", []string{"1.0", "2.0"}, "2.0"},
		{"rpm is not dpkg", "Rocky Linux:9", "1.0", []string{"1.1", "2.0"}, "2.0"},
		{"maven", "Maven", "1.0", []string{"1.1", "2.0"}, "2.0"},

		// Nothing to compare against, so there is no nearest: take the highest.
		{"no installed version", "Go", "", []string{"1.5.9", "1.7.2"}, "1.7.2"},
		{"installed is not orderable", "Go", "(devel)", []string{"1.5.9", "1.7.2"}, "1.7.2"},
		{"no candidate is orderable", "Go", "1.0.0", []string{"latest", "next"}, "next"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickFix(tc.ecosystem, tc.installed, tc.candidates); got != tc.want {
				t.Errorf("pickFix(%q, %q, %q) = %q, want %q",
					tc.ecosystem, tc.installed, tc.candidates, got, tc.want)
			}
		})
	}
}
