package analyze

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cwayne18/vexscan/internal/triage"
)

// The three ids below are real, and so is the alias that joins them:
// GO-2025-3547 is CVE-2024-7598, which is exactly the case vexscan's findings
// hit on a Go image and the one the OSV alias bridge exists for.
const (
	goID      = "GO-2025-3547"
	goCVE     = "CVE-2024-7598"
	debianID  = "DEBIAN-CVE-2026-54369"
	debianCVE = "CVE-2026-54369"
)

func triageServer(t *testing.T) *triage.Loader {
	t.Helper()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	fmt.Fprint(zw, "#model_version:v2026.06.15,score_date:2026-08-04T12:00:14Z\ncve,epss,percentile\n"+
		goCVE+",0.00123,0.31000\n"+
		debianCVE+",0.04000,0.90000\n"+
		"CVE-2017-5638,0.94000,0.99900\n")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	body := gz.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("/epss_scores-current.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "epss_scores-2026-08-04.csv.gz", http.StatusFound)
	})
	mux.HandleFunc("/epss_scores-2026-08-04.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"catalogVersion":"2026.08.03","vulnerabilities":[
			{"cveID":"CVE-2017-5638","dateAdded":"2021-11-03","dueDate":"2021-11-17","knownRansomwareCampaignUse":"Known"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	l := triage.New()
	l.Dir = t.TempDir()
	l.EPSSURL = srv.URL + "/epss_scores-current.csv.gz"
	l.KEVURL = srv.URL + "/kev.json"
	return l
}

// The join that matters: a Go finding names no CVE anywhere in its own fields,
// and is scored anyway through the alias list the resolver already fetched.
func TestAGoFindingIsScoredThroughItsAlias(t *testing.T) {
	findings := []Finding{{ID: goID, CVE: goID, GoID: goID, Module: "golang.org/x/net"}}
	aliases := map[string][]string{
		goID:  {goID, goCVE, "GHSA-r56h-j38w-hrqq"},
		goCVE: {goID, goCVE, "GHSA-r56h-j38w-hrqq"},
	}

	res := triageOverlay(context.Background(), triageServer(t), findings, aliases, quiet)

	p := findings[0].Priority
	if p == nil || !p.Scored {
		t.Fatalf("the finding was not scored: %+v", p)
	}
	if p.CVE != goCVE {
		t.Errorf("scored as %q, want %q -- the alias bridge did not carry", p.CVE, goCVE)
	}
	if p.Percentile != 0.31 {
		t.Errorf("percentile = %v, want 0.31", p.Percentile)
	}
	if res.Scored != 1 || res.Unscored() != 0 {
		t.Errorf("counts: scored=%d unscored=%d, want 1 and 0", res.Scored, res.Unscored())
	}
}

// A distro id is a CVE wearing a database's name.
func TestADistroPrefixIsStrippedBeforeTheLookup(t *testing.T) {
	findings := []Finding{{ID: debianID, CVE: debianID, Module: "acl"}}
	triageOverlay(context.Background(), triageServer(t), findings, nil, quiet)

	p := findings[0].Priority
	if p == nil || !p.Scored {
		t.Fatalf("%s was not scored: %+v", debianID, p)
	}
	if p.CVE != debianCVE {
		t.Errorf("scored as %q, want %q", p.CVE, debianCVE)
	}
}

// An advisory that never got a CVE cannot be scored, and must not be filed as
// a zero. This is the failure mode the whole Scored flag exists to prevent.
func TestAnAdvisoryWithNoCVEIsUnscoredRatherThanZero(t *testing.T) {
	findings := []Finding{{ID: "GHSA-gcjh-h69q-9w9g", CVE: "GHSA-gcjh-h69q-9w9g"}}
	res := triageOverlay(context.Background(), triageServer(t), findings, nil, quiet)

	p := findings[0].Priority
	if p == nil {
		t.Fatal("no Priority at all; the reader cannot tell the flag ran")
	}
	if p.Scored {
		t.Error("an advisory with no CVE was reported as scored")
	}
	if p.CVE != "" {
		t.Errorf("CVE = %q, want empty", p.CVE)
	}
	if res.NoCVE != 1 || res.NotInFeed != 0 {
		t.Errorf("counted NoCVE=%d NotInFeed=%d, want 1 and 0 -- the two reasons are not interchangeable",
			res.NoCVE, res.NotInFeed)
	}
}

// A CVE published yesterday has no score yet. That is a different fact from
// having no CVE, and the report explains them differently.
func TestACVETheFeedHasNotScoredYetIsCountedApart(t *testing.T) {
	findings := []Finding{{ID: "CVE-2026-53613", CVE: "CVE-2026-53613"}}
	res := triageOverlay(context.Background(), triageServer(t), findings, nil, quiet)

	if res.NotInFeed != 1 || res.NoCVE != 0 {
		t.Errorf("counted NoCVE=%d NotInFeed=%d, want 0 and 1", res.NoCVE, res.NotInFeed)
	}
	if p := findings[0].Priority; p.CVE != "CVE-2026-53613" {
		t.Errorf("CVE = %q; the id was resolved but not recorded", p.CVE)
	}
}

func TestKEVIsAttachedAndCounted(t *testing.T) {
	findings := []Finding{
		{ID: "CVE-2017-5638", CVE: "CVE-2017-5638"},
		{ID: debianID, CVE: debianID},
	}
	res := triageOverlay(context.Background(), triageServer(t), findings, nil, quiet)

	k := findings[0].Priority.KEV
	if k == nil {
		t.Fatal("CVE-2017-5638 is in the catalog and was not marked")
	}
	if !k.Ransomware || k.DueDate != "2021-11-17" {
		t.Errorf("KEV entry = %+v", k)
	}
	if findings[1].Priority.KEV != nil {
		t.Error("a CVE not in the catalog was marked as known-exploited")
	}
	if res.KnownExploited != 1 || res.CatalogSize != 1 {
		t.Errorf("KnownExploited=%d CatalogSize=%d, want 1 and 1", res.KnownExploited, res.CatalogSize)
	}
}

// Without the flag the overlay must not touch a thing, which is what keeps an
// untriaged report identical to one from before any of this existed.
func TestTheOverlayIsANoOpWithoutTheFlag(t *testing.T) {
	findings := []Finding{{ID: debianID, CVE: debianID}}
	if res := triageOverlay(context.Background(), nil, findings, nil, quiet); res != nil {
		t.Errorf("a nil loader produced %+v, want nil", res)
	}
	if findings[0].Priority != nil {
		t.Error("a nil loader still annotated the findings")
	}
}

// An unreachable feed leaves the findings in the order they were already in.
// It must be recorded, and it must not look like an empty catalog.
func TestAnUnreachableFeedIsRecordedRatherThanSilent(t *testing.T) {
	l := triage.New()
	l.Dir = t.TempDir()
	l.EPSSURL = "http://127.0.0.1:1/epss_scores-current.csv.gz"
	l.KEVURL = "http://127.0.0.1:1/kev.json"

	findings := []Finding{{ID: debianID, CVE: debianID}}
	res := triageOverlay(context.Background(), l, findings, nil, quiet)

	if res.EPSSError == "" || res.KEVError == "" {
		t.Fatalf("errors not recorded: epss=%q kev=%q", res.EPSSError, res.KEVError)
	}
	if res.Usable() {
		t.Error("a result with both feeds down claimed to be usable")
	}
	if res.Scored != 0 || res.NotInFeed != 1 {
		t.Errorf("scored=%d notInFeed=%d; a dead feed must not score anything", res.Scored, res.NotInFeed)
	}
}

func TestFindingCVEPrefersTheFirstUsableID(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		aliases map[string][]string
		want    string
	}{
		{"a bare CVE", Finding{ID: "CVE-2020-8559", CVE: "CVE-2020-8559"}, nil, "CVE-2020-8559"},
		{"a distro prefix", Finding{ID: debianID, CVE: debianID}, nil, debianCVE},
		{"an Ubuntu prefix", Finding{ID: "UBUNTU-CVE-2023-45853"}, nil, "CVE-2023-45853"},
		{"a GHSA with no CVE anywhere", Finding{ID: "GHSA-gcjh-h69q-9w9g"}, nil, ""},
		{
			"a GHSA whose alias is a CVE",
			Finding{ID: "GHSA-82hx-w2r5-c2wq"},
			map[string][]string{"GHSA-82hx-w2r5-c2wq": {"GHSA-82hx-w2r5-c2wq", "CVE-2020-8552"}},
			"CVE-2020-8552",
		},
		// A GO id is not a CVE and its digits must not be mistaken for one.
		{"a GO id alone", Finding{ID: "GO-2022-0965", GoID: "GO-2022-0965"}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findingCVE(tt.finding, tt.aliases); got != tt.want {
				t.Errorf("findingCVE() = %q, want %q", got, tt.want)
			}
		})
	}
}
