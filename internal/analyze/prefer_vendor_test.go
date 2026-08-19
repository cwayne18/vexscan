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

// fakeScorer is a distrofeed.Scorer that answers from a fixed CVE->vector map,
// so a test can set a vendor's score without a server. It records the ids it was
// asked about, to prove a finding's CVEs reached it.
type fakeScorer struct {
	name     string
	scores   map[string]string
	err      error
	askedFor []string
}

func (f *fakeScorer) Name() string { return f.name }

func (f *fakeScorer) Scores(_ context.Context, cves []string) (map[string]string, error) {
	f.askedFor = append(f.askedFor, cves...)
	return f.scores, f.err
}

func suseScorer(scores map[string]string) *fakeScorer {
	return &fakeScorer{name: "SUSE Security Team", scores: scores}
}

// sevFinding is an OS-package finding at a given rating, the common case.
func sevFinding(cve, severity, cvss string) Finding {
	return Finding{Ecosystem: "os", ID: cve, CVE: cve, Package: "bash", Version: "5.2-1", Severity: severity, CVSS: cvss}
}

// preferEvidence returns the prefer-vendor evidence detail on a finding, or "".
func preferEvidence(f Finding) string {
	for _, e := range f.Evidence {
		if e.Origin == OriginPreferVendor {
			return e.Detail
		}
	}
	return ""
}

// The headline case the flag exists for: a preferred vendor's score is
// authoritative and wins even when it is lower than the OSV-derived rating.
func TestPreferVendorLowerScoreWins(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}
	scorer := suseScorer(map[string]string{"CVE-2023-0464": vectorHigh})

	preferVendorScores(context.Background(), []distrofeed.Scorer{scorer}, findings, nil, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH (the preferred vendor's lower score wins)", findings[0].Severity)
	}
	if findings[0].CVSS != vectorHigh {
		t.Errorf("cvss = %q, want the vendor vector", findings[0].CVSS)
	}
	detail := preferEvidence(findings[0])
	if detail == "" {
		t.Fatal("no prefer-vendor evidence recorded")
	}
	if !strings.Contains(detail, "SUSE") || !strings.Contains(detail, "HIGH") || !strings.Contains(detail, "CRITICAL") {
		t.Errorf("evidence detail = %q, want it to name the vendor, the rating, and what it displaced", detail)
	}
}

// The point of the redesign: a finding in a non-OS ecosystem, reported under a
// GO id with no CVE of its own, is still rescored -- reached through the advisory
// alias set that resolves the GO id to the CVE the vendor feed is keyed by.
func TestPreferVendorRescoresGoModuleViaAlias(t *testing.T) {
	f := Finding{Ecosystem: "golang", ID: "GO-2026-1234", GoID: "GO-2026-1234", Package: "golang.org/x/net", Version: "0.1.0", Severity: "CRITICAL", CVSS: vectorCritical}
	findings := []Finding{f}
	// The resolver's alias set bridges the GO id to the CVE SUSE scored.
	ids := map[string][]string{"GO-2026-1234": {"GO-2026-1234", "CVE-2026-9999"}}
	scorer := suseScorer(map[string]string{"CVE-2026-9999": vectorHigh})

	preferVendorScores(context.Background(), []distrofeed.Scorer{scorer}, findings, ids, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH: a Go finding must be rescored via its CVE alias", findings[0].Severity)
	}
	// And the scorer was actually asked about the resolved CVE.
	var asked bool
	for _, id := range scorer.askedFor {
		if id == "CVE-2026-9999" {
			asked = true
		}
	}
	if !asked {
		t.Errorf("scorer was asked about %v, want it to include CVE-2026-9999", scorer.askedFor)
	}
}

// A finding with no OSV rating still takes the vendor's score, and the evidence
// does not claim to have displaced a rating that was never there.
func TestPreferVendorFillsUnrated(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "", "")}
	scorer := suseScorer(map[string]string{"CVE-2023-0464": vectorHigh})

	preferVendorScores(context.Background(), []distrofeed.Scorer{scorer}, findings, nil, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", findings[0].Severity)
	}
	if strings.Contains(preferEvidence(findings[0]), "instead of") {
		t.Errorf("evidence claims to have displaced a rating that did not exist: %q", preferEvidence(findings[0]))
	}
}

// A CVE no scorer rated keeps its OSV rating: the flag only ever adds a vendor's
// opinion where they have one.
func TestPreferVendorUnscoredCVEStands(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}
	scorer := suseScorer(map[string]string{"CVE-2099-0001": vectorHigh}) // a different CVE

	preferVendorScores(context.Background(), []distrofeed.Scorer{scorer}, findings, nil, quiet)

	if findings[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL unchanged (SUSE did not score this CVE)", findings[0].Severity)
	}
	if preferEvidence(findings[0]) != "" {
		t.Error("evidence was recorded for a CVE the vendor did not score")
	}
}

// An unscannable vector is no score at all: the OSV rating stands rather than
// being blanked.
func TestPreferVendorBadVectorFallsBack(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}
	scorer := suseScorer(map[string]string{"CVE-2023-0464": "not-a-vector"})

	preferVendorScores(context.Background(), []distrofeed.Scorer{scorer}, findings, nil, quiet)

	if findings[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL (an unscannable vendor vector must not override)", findings[0].Severity)
	}
}

// When two preferred vendors both score a finding, the earlier one in the
// scorer list -- which the caller builds in --prefer-vendor priority order --
// wins.
func TestPreferVendorEarliestListedWins(t *testing.T) {
	findings := []Finding{sevFinding("CVE-2023-0464", "MEDIUM", "")}
	first := &fakeScorer{name: "SUSE Security Team", scores: map[string]string{"CVE-2023-0464": vectorHigh}}
	second := &fakeScorer{name: "Debian Security Tracker", scores: map[string]string{"CVE-2023-0464": vectorCritical}}

	preferVendorScores(context.Background(), []distrofeed.Scorer{first, second}, findings, nil, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH (the first-listed vendor wins)", findings[0].Severity)
	}
}

// A bundle finding relating to several CVEs takes the most severe of the
// vendor's own scores among them -- fail towards severe within one vendor.
func TestPreferVendorBundleTakesHighest(t *testing.T) {
	f := sevFinding("CVE-2023-0001", "", "")
	findings := []Finding{f}
	ids := map[string][]string{"CVE-2023-0001": {"CVE-2023-0001", "CVE-2023-0002"}}
	scorer := suseScorer(map[string]string{
		"CVE-2023-0001": vectorHigh,     // 7.5
		"CVE-2023-0002": vectorCritical, // 9.8
	})

	preferVendorScores(context.Background(), []distrofeed.Scorer{scorer}, findings, ids, quiet)

	if findings[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL (the worst of the vendor's scores for the bundle)", findings[0].Severity)
	}
}

func TestBestVendorVector(t *testing.T) {
	scores := map[string]string{"CVE-2023-0464": vectorHigh, "CVE-2023-9999": vectorCritical}
	cases := []struct {
		name      string
		cves      []string
		wantVec   string
		wantLabel string
		wantOK    bool
	}{
		{"one match", []string{"CVE-2023-0464"}, vectorHigh, "HIGH", true},
		{"highest of several", []string{"CVE-2023-0464", "CVE-2023-9999"}, vectorCritical, "CRITICAL", true},
		{"case-insensitive", []string{"cve-2023-0464"}, vectorHigh, "HIGH", true},
		{"no match", []string{"CVE-2000-0000"}, "", "", false},
	}
	for _, c := range cases {
		vec, label, ok := bestVendorVector(scores, c.cves)
		if ok != c.wantOK || vec != c.wantVec || label != c.wantLabel {
			t.Errorf("%s: bestVendorVector = (%q, %q, %v), want (%q, %q, %v)", c.name, vec, label, ok, c.wantVec, c.wantLabel, c.wantOK)
		}
	}
}

// End to end through the real SUSE provider: a served CSAF document's score
// reaches a finding via Scores + preferVendorScores, over HTTP, with no CPE or
// product join in play -- the standalone path a bare --prefer-vendor takes.
func TestPreferVendorEndToEnd(t *testing.T) {
	const scoredCSAF = `{
  "product_tree": { "branches": [] },
  "vulnerabilities": [ { "cve": "CVE-2023-0464",
    "scores": [ { "cvss_v3": { "baseScore": 7.5, "vectorString": "` + vectorHigh + `", "version": "3.1" } } ] } ] }`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cve-2023-0464.json") {
			w.Write([]byte(scoredCSAF))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	p := &suse.Provider{BaseURL: srv.URL}
	findings := []Finding{sevFinding("CVE-2023-0464", "CRITICAL", vectorCritical)}

	preferVendorScores(context.Background(), []distrofeed.Scorer{p}, findings, nil, quiet)

	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH from SUSE's served score", findings[0].Severity)
	}
}
