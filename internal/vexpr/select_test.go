package vexpr

import (
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

const (
	testProduct = "pkg:oci/synthetic?repository_url=index.docker.io/example/synthetic"
	testTime    = "2026-08-06T10:00:00Z"
)

func TestSelectProposalsPicksRuledOutOnly(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		{ID: "CVE-1", CVE: "CVE-1", Product: testProduct, PURL: "pkg:deb/debian/a@1", Status: analyze.StatusNotPresent, Justification: "component_not_present"},
		{ID: "CVE-2", CVE: "CVE-2", Product: testProduct, PURL: "pkg:deb/debian/b@1", Status: analyze.StatusNotInPath, Justification: "vulnerable_code_not_in_execute_path"},
		// Affected -- must not be proposed.
		{ID: "CVE-3", CVE: "CVE-3", Product: testProduct, PURL: "pkg:deb/debian/c@1", Status: analyze.StatusLinked},
		// Undetermined -- must not be proposed.
		{ID: "CVE-4", CVE: "CVE-4", Product: testProduct, PURL: "pkg:deb/debian/d@1", Status: analyze.StatusUndetermined},
	}}
	props, skipped := selectProposals(res, testTime)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if len(props) != 1 {
		t.Fatalf("got %d product proposals, want 1", len(props))
	}
	if got := len(props[0].Statements); got != 2 {
		t.Fatalf("got %d statements, want 2 (the ruled-out ones)", got)
	}
	if s := props[0].Statements[0]; s.Status != StatusNotAffected {
		t.Errorf("status = %q, want not_affected", s.Status)
	}
	if s := props[0].Statements[1]; s.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification = %q, want the finding's own", s.Justification)
	}
}

func TestSelectProposalsSkipsHubCoveredAndUnmatchable(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		// Already answered by the hub -- leave it alone.
		{ID: "CVE-1", CVE: "CVE-1", Product: testProduct, PURL: "pkg:deb/debian/a@1", Status: analyze.StatusNotPresent, VEX: &ecosystem.VEXStatement{Status: "not_affected"}},
		// No id -- cannot be written as a matchable statement.
		{Product: testProduct, PURL: "pkg:deb/debian/b@1", Status: analyze.StatusNotPresent},
		// No component purl -- likewise.
		{ID: "CVE-3", CVE: "CVE-3", Product: testProduct, Status: analyze.StatusNotPresent},
	}}
	props, skipped := selectProposals(res, testTime)
	if len(props) != 0 {
		t.Fatalf("got %d proposals, want 0", len(props))
	}
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2", skipped)
	}
}

func TestSelectProposalsDedupesWithinScan(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		{ID: "CVE-1", CVE: "CVE-1", Product: testProduct, PURL: "pkg:deb/debian/a@1", Status: analyze.StatusNotPresent},
		{ID: "CVE-1", CVE: "CVE-1", Product: testProduct, PURL: "pkg:deb/debian/a@1", Status: analyze.StatusNotPresent},
	}}
	props, _ := selectProposals(res, testTime)
	if len(props) != 1 || len(props[0].Statements) != 1 {
		t.Fatalf("expected one deduped statement, got %+v", props)
	}
}

func TestVulnIDsPrefersCVEAsName(t *testing.T) {
	name, aliases := vulnIDs(analyze.Finding{ID: "GO-2025-1", GoID: "GO-2025-1", CVE: "CVE-2025-9"})
	if name != "CVE-2025-9" {
		t.Errorf("name = %q, want the CVE", name)
	}
	if len(aliases) != 1 || aliases[0] != "GO-2025-1" {
		t.Errorf("aliases = %v, want [GO-2025-1]", aliases)
	}
}
