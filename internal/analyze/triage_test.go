package analyze

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
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
	// A real SUSE advisory id: no CVE in it, no aliases on the record, and
	// eight CVEs in its upstream list.
	suseID = "SUSE-SU-2026:0312-1"
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

func TestFindingCVEsCollectsEveryReachableID(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		sets    map[string][]string
		want    []string
	}{
		{"a bare CVE", Finding{ID: "CVE-2020-8559", CVE: "CVE-2020-8559"}, nil, []string{"CVE-2020-8559"}},
		{"a distro prefix", Finding{ID: debianID, CVE: debianID}, nil, []string{debianCVE}},
		{"an Ubuntu prefix", Finding{ID: "UBUNTU-CVE-2023-45853"}, nil, []string{"CVE-2023-45853"}},
		{"a GHSA with no CVE anywhere", Finding{ID: "GHSA-gcjh-h69q-9w9g"}, nil, nil},
		{
			"a GHSA whose alias is a CVE",
			Finding{ID: "GHSA-82hx-w2r5-c2wq"},
			map[string][]string{"GHSA-82hx-w2r5-c2wq": {"GHSA-82hx-w2r5-c2wq", "CVE-2020-8552"}},
			[]string{"CVE-2020-8552"},
		},
		// A GO id is not a CVE and its digits must not be mistaken for one.
		{"a GO id alone", Finding{ID: "GO-2022-0965", GoID: "GO-2022-0965"}, nil, nil},
		// The case the whole change exists for: a SUSE advisory names no CVE in
		// its own id and carries no aliases, only the CVEs its patch fixes.
		{
			"a SUSE bundle",
			Finding{ID: suseID, CVE: suseID},
			map[string][]string{suseID: {suseID, "CVE-2024-2511", "CVE-2024-4603", "CVE-2024-5535"}},
			[]string{"CVE-2024-2511", "CVE-2024-4603", "CVE-2024-5535"},
		},
		// The same CVE reached twice -- once bare, once through the set -- is
		// one CVE, and must not make a one-CVE advisory look like a bundle.
		{
			"a CVE reachable by two routes",
			Finding{ID: debianID, CVE: debianCVE},
			map[string][]string{debianID: {debianID, debianCVE}, debianCVE: {debianID, debianCVE}},
			[]string{debianCVE},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingCVEs(tt.finding, tt.sets)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findingCVEs() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A SUSE-SU advisory addresses several CVEs at once and names none of them.
// Before this it scored nothing at all: SUSE files under "upstream", vexscan
// read only "aliases", and no SUSE id contains a CVE to fall back on.
func TestASUSEBundleIsScoredByItsWorstMember(t *testing.T) {
	findings := []Finding{{ID: suseID, CVE: suseID, Module: "openssl-3"}}
	sets := map[string][]string{suseID: {suseID, goCVE, debianCVE, "CVE-2026-53613"}}

	res := triageOverlay(context.Background(), triageServer(t), findings, sets, quiet)

	p := findings[0].Priority
	if p == nil || !p.Scored {
		t.Fatalf("the bundle was not scored: %+v", p)
	}
	// goCVE is the 31st percentile, debianCVE the 90th, and the third is not in
	// the feed at all. Taking the first would have reported the 31st.
	if p.CVE != debianCVE || p.Percentile != 0.90 {
		t.Errorf("scored as %s at %v, want %s at 0.90 -- the worst member did not win", p.CVE, p.Percentile, debianCVE)
	}
	if p.OfSet != 3 {
		t.Errorf("OfSet = %d, want 3 -- the reader cannot tell this row stands for three CVEs", p.OfSet)
	}
	if res.Scored != 1 || res.Unscored() != 0 {
		t.Errorf("counts: scored=%d unscored=%d, want 1 and 0 -- a bundle is one finding", res.Scored, res.Unscored())
	}
}

// KEV outranks a higher percentile inside a bundle for the same reason it does
// between rows: an observed exploit ends the argument.
func TestAKnownExploitedMemberWinsTheBundle(t *testing.T) {
	findings := []Finding{{ID: suseID, CVE: suseID}}
	sets := map[string][]string{suseID: {suseID, debianCVE, "CVE-2017-5638"}}

	triageOverlay(context.Background(), triageServer(t), findings, sets, quiet)

	p := findings[0].Priority
	if p.KEV == nil {
		t.Fatal("a bundle containing a known-exploited CVE was not marked")
	}
	if p.CVE != "CVE-2017-5638" {
		t.Errorf("reported %s; the row's rank comes from CVE-2017-5638 and must say so", p.CVE)
	}
}

// An ordinary single-CVE advisory must look exactly as it did before bundles
// existed, or every Debian row grows a "highest of 1".
func TestASingleCVEAdvisoryHasNoSetSize(t *testing.T) {
	findings := []Finding{{ID: debianID, CVE: debianID}}
	triageOverlay(context.Background(), triageServer(t), findings, nil, quiet)

	if got := findings[0].Priority.OfSet; got != 0 {
		t.Errorf("OfSet = %d, want 0", got)
	}
}

func TestUpstreamOverlayOnlyMarksRealBundles(t *testing.T) {
	findings := []Finding{
		{ID: suseID, CVE: suseID},
		{ID: debianID, CVE: debianID},
		{ID: "CVE-2020-8559", CVE: "CVE-2020-8559"},
	}
	upstreamOverlay(findings, map[string][]string{
		suseID: {"CVE-2024-2511", "CVE-2024-5535"},
		// Debian's record addresses the one CVE its own id already spells.
		debianID:        {debianCVE},
		"CVE-2020-8559": {"CVE-2020-8559"},
	})

	if len(findings[0].Upstream) != 2 {
		t.Errorf("the SUSE bundle got Upstream = %v, want both CVEs", findings[0].Upstream)
	}
	for _, f := range findings[1:] {
		if len(f.Upstream) != 0 {
			t.Errorf("%s got Upstream = %v; repeating a row's own CVE back at it is noise", f.ID, f.Upstream)
		}
	}
}
