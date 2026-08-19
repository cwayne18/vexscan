package analyze

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/distrofeed/suse"
)

// vectorHigh scores 7.5 (HIGH); vectorCritical scores 9.8 (CRITICAL). They let a
// test set a vendor's rating deliberately below or above the OSV one.
const (
	vectorHigh     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
	vectorCritical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

// suseScoreStmt is an affected SUSE statement carrying a CVSS vector, the shape
// distroScores hands preferVendorOverlay.
func suseScoreStmt(refID, vector string) distrofeed.Statement {
	return distrofeed.Statement{
		RefID: refID, Distro: "suse", Package: "bash", CVE: "CVE-2023-0464",
		Status: distrofeed.StatusAffected, Author: "SUSE Security Team", CVSSVector: vector,
	}
}

func sevFinding(cve, severity, cvss string) Finding {
	return Finding{Ecosystem: "os", ID: cve, CVE: cve, Package: "bash", Version: "5.2-1", Severity: severity, CVSS: cvss}
}

// The headline case the flag exists for: a preferred vendor's score is
// authoritative and wins even when it is lower than the OSV-derived rating.
func TestPreferVendorLowerScoreWins(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}
	index := map[string]*Finding{"0": &findings[0]}

	preferVendorOverlay([]distrofeed.Statement{suseScoreStmt("0", vectorHigh)}, index, []string{"suse"}, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH (the preferred vendor's lower score wins)", findings[0].Severity)
	}
	if findings[0].CVSS != vectorHigh {
		t.Errorf("cvss = %q, want the vendor vector", findings[0].CVSS)
	}
	var detail string
	for _, e := range findings[0].Evidence {
		if e.Origin == OriginPreferVendor {
			detail = e.Detail
		}
	}
	if detail == "" {
		t.Fatal("no prefer-vendor evidence recorded")
	}
	if !strings.Contains(detail, "SUSE") || !strings.Contains(detail, "HIGH") || !strings.Contains(detail, "CRITICAL") {
		t.Errorf("evidence detail = %q, want it to name the vendor, the rating, and what it displaced", detail)
	}
}

// A finding with no OSV rating still takes the vendor's score, and the evidence
// does not claim to have displaced a rating that was never there.
func TestPreferVendorFillsUnrated(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "", "")}
	index := map[string]*Finding{"0": &findings[0]}

	preferVendorOverlay([]distrofeed.Statement{suseScoreStmt("0", vectorHigh)}, index, []string{"suse"}, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", findings[0].Severity)
	}
	for _, e := range findings[0].Evidence {
		if e.Origin == OriginPreferVendor && strings.Contains(e.Detail, "instead of") {
			t.Errorf("evidence claims to have displaced a rating that did not exist: %q", e.Detail)
		}
	}
}

// A vendor nobody asked for is ignored: the OSV rating stands untouched.
func TestPreferVendorIgnoresUnnamedVendor(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}
	index := map[string]*Finding{"0": &findings[0]}

	preferVendorOverlay([]distrofeed.Statement{suseScoreStmt("0", vectorHigh)}, index, []string{"debian"}, quiet)

	if findings[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL unchanged (SUSE was not a preferred vendor)", findings[0].Severity)
	}
	for _, e := range findings[0].Evidence {
		if e.Origin == OriginPreferVendor {
			t.Error("evidence was recorded for a vendor that was not preferred")
		}
	}
}

// An empty vector is no score at all: the OSV rating stands rather than being
// blanked.
func TestPreferVendorEmptyVectorFallsBack(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}
	index := map[string]*Finding{"0": &findings[0]}

	preferVendorOverlay([]distrofeed.Statement{suseScoreStmt("0", "")}, index, []string{"suse"}, quiet)

	if findings[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL (an empty vendor vector must not override)", findings[0].Severity)
	}
}

// When two preferred vendors both score a finding, the earlier one in the
// --prefer-vendor list wins, whatever order the statements arrive in.
func TestPreferVendorEarliestListedWins(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "MEDIUM", "")}
	index := map[string]*Finding{"0": &findings[0]}
	debianStmt := distrofeed.Statement{
		RefID: "0", Author: "Debian Security Tracker", Status: distrofeed.StatusAffected, CVSSVector: vectorCritical,
	}
	// Debian's statement is seen first but SUSE is listed first in the preference.
	stmts := []distrofeed.Statement{debianStmt, suseScoreStmt("0", vectorHigh)}

	preferVendorOverlay(stmts, index, []string{"suse", "debian"}, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH (SUSE outranks Debian in the preference order)", findings[0].Severity)
	}
}

func TestVendorRank(t *testing.T) {
	prefer := []string{"suse", "debian"}
	cases := []struct {
		author string
		want   int
	}{
		{"SUSE Security Team", 0},
		{"Debian Security Tracker", 1},
		{"Red Hat Product Security", -1},
		{"", -1},
	}
	for _, c := range cases {
		if got := vendorRank(c.author, prefer); got != c.want {
			t.Errorf("vendorRank(%q) = %d, want %d", c.author, got, c.want)
		}
	}
}

// End to end through the fetch: a served SUSE document's score reaches a finding
// via distroScores + preferVendorOverlay, exercising the RefID/index plumbing
// osFindings builds.
func TestPreferVendorEndToEnd(t *testing.T) {
	const scoredCSAF = `{
  "product_tree": { "branches": [
    { "category": "product_name", "name": "SUSE Linux Enterprise Server 15 SP5",
      "product": { "product_id": "SUSE Linux Enterprise Server 15 SP5",
        "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } } ] },
  "vulnerabilities": [ { "cve": "CVE-2023-0464",
    "scores": [ { "cvss_v3": { "baseScore": 7.5, "vectorString": "` + vectorHigh + `", "version": "3.1" } } ],
    "product_status": { "known_affected": [ "SUSE Linux Enterprise Server 15 SP5:bash" ] } } ] }`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cve-2023-0464.json") {
			w.Write([]byte(scoredCSAF))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	p := &suse.Provider{BaseURL: srv.URL}
	os := &OSInfo{ID: "sles", VersionID: "15.5", CPEName: "cpe:/o:suse:sles:15:sp5"}
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}

	stmts, index := distroScores(context.Background(), []distrofeed.Provider{p}, os, findings, nil, quiet)
	preferVendorOverlay(stmts, index, []string{"suse"}, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH from SUSE's served score", findings[0].Severity)
	}
}
