package analyze

import "testing"

// A Go finding reported under its GO id is renamed to the CVE the alias set
// resolves it to, while the GO id is kept on GoID for --details.
func TestCVEOverlayPromotesGoID(t *testing.T) {
	f := Finding{Ecosystem: "golang", ID: "GO-2026-1234", GoID: "GO-2026-1234", CVE: "GO-2026-1234"}
	findings := []Finding{f}
	all := map[string][]string{"GO-2026-1234": {"GO-2026-1234", "CVE-2026-9999", "GHSA-aaaa-bbbb-cccc"}}

	cveOverlay(findings, all)

	if findings[0].CVE != "CVE-2026-9999" {
		t.Errorf("CVE = %q, want CVE-2026-9999 promoted from the alias set", findings[0].CVE)
	}
	if findings[0].GoID != "GO-2026-1234" {
		t.Errorf("GoID = %q, want the GO id kept for --details", findings[0].GoID)
	}
}

// A finding whose CVE field already holds a real CVE is untouched -- the common
// case for OS packages and for a --cves scan that named the CVE itself.
func TestCVEOverlayLeavesRealCVE(t *testing.T) {
	findings := []Finding{{Ecosystem: "os", ID: "CVE-2023-0464", CVE: "CVE-2023-0464"}}
	cveOverlay(findings, map[string][]string{"CVE-2023-0464": {"CVE-2023-0464", "GHSA-x"}})

	if findings[0].CVE != "CVE-2023-0464" {
		t.Errorf("CVE = %q, want it left unchanged", findings[0].CVE)
	}
}

// A bundle that fixes several CVEs has no single CVE to stand in for its id, so
// it keeps its own -- upstreamOverlay lists the rest under "addresses:".
func TestCVEOverlayLeavesBundle(t *testing.T) {
	findings := []Finding{{Ecosystem: "os", ID: "SUSE-SU-2026:0312-1", CVE: "SUSE-SU-2026:0312-1"}}
	all := map[string][]string{"SUSE-SU-2026:0312-1": {"SUSE-SU-2026:0312-1", "CVE-2026-1", "CVE-2026-2"}}

	cveOverlay(findings, all)

	if findings[0].CVE != "SUSE-SU-2026:0312-1" {
		t.Errorf("CVE = %q, want the bundle id kept when it fixes several CVEs", findings[0].CVE)
	}
}

// A non-CVE id with no CVE anywhere in its alias set -- a DSA that names none --
// is left exactly as it is rather than blanked.
func TestCVEOverlayLeavesNonCVEWithoutAlias(t *testing.T) {
	findings := []Finding{{Ecosystem: "os", ID: "DSA-5678-1", CVE: "DSA-5678-1"}}
	cveOverlay(findings, map[string][]string{"DSA-5678-1": {"DSA-5678-1"}})

	if findings[0].CVE != "DSA-5678-1" {
		t.Errorf("CVE = %q, want the DSA id left as-is", findings[0].CVE)
	}
}
