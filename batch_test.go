package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/target"
)

// imageResult is one scanned image for a batch test.
func imageResult(ref string, components int, findings ...analyze.Finding) *analyze.Result {
	return &analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        ref,
		Mode:          "image",
		Ecosystems:    []ecosystem.EcosystemResult{{ID: "os", Ecosystems: []string{"Debian:12"}, Components: components}},
		Findings:      findings,
	}
}

func TestBatchTableCountsPerImage(t *testing.T) {
	br := &batchReport{
		SchemaVersion: batchSchemaVersion,
		Mode:          "batch",
		Targets:       2,
		order:         []string{"a:1", "b:2"},
		Results: []*analyze.Result{
			imageResult("a:1", 100,
				analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "p", Status: analyze.StatusLinked, Severity: "HIGH"},
				analyze.Finding{Ecosystem: "os", CVE: "CVE-2", Package: "q", Status: analyze.StatusNotPresent},
			),
			imageResult("b:2", 20,
				analyze.Finding{Ecosystem: "os", CVE: "CVE-3", Package: "r", Status: analyze.StatusReachable, Severity: "CRITICAL"},
			),
		},
	}

	out := renderBatchSummary(br, renderOpts{})
	if got := strings.Fields(lineWith(t, out, "a:1")); !equalStrings(got, []string{"a:1", "100", "1", "1"}) {
		t.Errorf("a:1 row = %v, want [a:1 100 1 1]\n%s", got, out)
	}
	if got := strings.Fields(lineWith(t, out, "b:2")); !equalStrings(got, []string{"b:2", "20", "1", "0"}) {
		t.Errorf("b:2 row = %v, want [b:2 20 1 0]\n%s", got, out)
	}
	if got := strings.Fields(lineWith(t, out, "TOTAL")); !equalStrings(got, []string{"TOTAL", "120", "2", "1"}) {
		t.Errorf("total row = %v, want [TOTAL 120 2 1]\n%s", got, out)
	}
	// Nothing was vexed and nothing was undetermined, so neither column is
	// printed -- the same rule the per-ecosystem summary follows.
	if strings.Contains(out, "VEXED") || strings.Contains(out, "UNDETERMINED") {
		t.Errorf("empty status columns should not be printed:\n%s", out)
	}
}

// An image that could not be pulled is the case this whole feature has to get
// right: it must be visible in the table, counted in the header, and it must
// stop the run exiting 0.
func TestBatchKeepsUnscannableImageVisible(t *testing.T) {
	br := &batchReport{
		SchemaVersion: batchSchemaVersion,
		Targets:       2,
		order:         []string{"good:1", "bad:1"},
		Results:       []*analyze.Result{imageResult("good:1", 10)},
		Failures:      []batchFailure{{Target: "bad:1", Error: "manifest unknown"}},
	}

	out := renderBatchSummary(br, renderOpts{})
	if !strings.Contains(out, "INCOMPLETE: 1 of 2 image(s) could not be scanned") {
		t.Errorf("missing batch INCOMPLETE banner:\n%s", out)
	}
	if !strings.Contains(out, "bad:1: manifest unknown") {
		t.Errorf("banner does not say why bad:1 failed:\n%s", out)
	}
	row := lineWith(t, out, "bad:1 (NOT SCANNED)")
	if !strings.Contains(row, "-") {
		t.Errorf("unscannable row should carry - not counts, got %q", row)
	}
	if !br.failed() {
		t.Error("a batch with an unscannable image must not report success")
	}
}

// The rows follow the list, so an image that failed stays where it was asked
// for rather than dropping to the bottom.
func TestBatchRowsFollowListOrder(t *testing.T) {
	br := &batchReport{
		Targets: 3,
		order:   []string{"a:1", "bad:1", "c:1"},
		Results: []*analyze.Result{imageResult("a:1", 1), imageResult("c:1", 1)},
		Failures: []batchFailure{
			{Target: "bad:1", Error: "nope"},
		},
	}
	var got []string
	for _, r := range batchRows(br) {
		got = append(got, r.target)
	}
	if !equalStrings(got, []string{"a:1", "bad:1", "c:1"}) {
		t.Errorf("row order = %v, want [a:1 bad:1 c:1]", got)
	}
}

// An image scanned with holes in it keeps its counts -- they are real as far as
// they go -- but the row says they are a floor, and the batch does not pass.
func TestBatchMarksIncompleteResult(t *testing.T) {
	holed := imageResult("holed:1", 5,
		analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "p", Status: analyze.StatusLinked, Severity: "HIGH"})
	holed.Unreadable = &target.Unreadable{Count: 3, Paths: []string{"/var/lib/dpkg/status"}}

	br := &batchReport{
		Targets: 1,
		order:   []string{"holed:1"},
		Results: []*analyze.Result{holed},
	}
	out := renderBatchSummary(br, renderOpts{})
	if !strings.Contains(out, "holed:1 (INCOMPLETE)") {
		t.Errorf("incomplete image not marked in the table:\n%s", out)
	}
	if !br.failed() {
		t.Error("a batch containing an incomplete scan must not report success")
	}
}

// The gate sums over the fleet and trips on any image, because a pipeline that
// ships a fleet ships the worst image in it.
func TestBatchGateSumsAcrossImages(t *testing.T) {
	gate, err := parseFailOn("high", "")
	if err != nil {
		t.Fatal(err)
	}
	br := &batchReport{
		Results: []*analyze.Result{
			imageResult("a:1", 1, analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "p", Status: analyze.StatusLinked, Severity: "LOW"}),
			imageResult("b:1", 1, analyze.Finding{Ecosystem: "os", CVE: "CVE-2", Package: "q", Status: analyze.StatusLinked, Severity: "CRITICAL"}),
		},
	}
	g := batchGate(gate, br)
	if g.counted != 2 {
		t.Errorf("counted = %d, want 2", g.counted)
	}
	if g.tripped != 1 {
		t.Errorf("tripped = %d, want 1 (only the CRITICAL is at or above high)", g.tripped)
	}
}

// Every image gets its own SARIF run, so a dashboard can tell them apart.
func TestBatchSARIFEmitsOneRunPerImage(t *testing.T) {
	br := &batchReport{
		Targets: 2,
		Results: []*analyze.Result{
			imageResult("a:1", 1, analyze.Finding{Ecosystem: "os", CVE: "CVE-1", Package: "p", Status: analyze.StatusLinked, Severity: "HIGH"}),
			imageResult("b:1", 1, analyze.Finding{Ecosystem: "os", CVE: "CVE-2", Package: "q", Status: analyze.StatusNotPresent}),
		},
	}
	out, err := renderBatchSARIF(br)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Props map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("sarif is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(doc.Runs))
	}
	for i, want := range []string{"a:1", "b:1"} {
		if got := doc.Runs[i].Props["target"]; got != want {
			t.Errorf("run %d target = %v, want %s", i, got, want)
		}
	}
}

// The JSON wrapper keeps the per-image results whole and separate: each one
// still carries its own target and its own schema version.
func TestBatchJSONWrapsResults(t *testing.T) {
	br := &batchReport{
		SchemaVersion: batchSchemaVersion,
		Mode:          "batch",
		Targets:       2,
		Results:       []*analyze.Result{imageResult("a:1", 1)},
		Failures:      []batchFailure{{Target: "b:1", Error: "nope"}},
	}
	out, err := renderBatch(br, "json", renderOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion int    `json:"schema_version"`
		Mode          string `json:"mode"`
		Targets       int    `json:"targets"`
		Results       []struct {
			SchemaVersion int    `json:"schema_version"`
			Target        string `json:"target"`
		} `json:"results"`
		Failures []struct {
			Target string `json:"target"`
			Error  string `json:"error"`
		} `json:"failures"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("batch json is not valid: %v", err)
	}
	if doc.SchemaVersion != batchSchemaVersion || doc.Mode != "batch" || doc.Targets != 2 {
		t.Errorf("wrapper = %+v, want schema %d, mode batch, 2 targets", doc, batchSchemaVersion)
	}
	if len(doc.Results) != 1 || doc.Results[0].Target != "a:1" || doc.Results[0].SchemaVersion != analyze.SchemaVersion {
		t.Errorf("results = %+v, want one a:1 at schema %d", doc.Results, analyze.SchemaVersion)
	}
	if len(doc.Failures) != 1 || doc.Failures[0].Target != "b:1" {
		t.Errorf("failures = %+v, want one b:1", doc.Failures)
	}
}

// A clean batch is the only one that says so.
func TestBatchCleanReportsSuccess(t *testing.T) {
	br := &batchReport{Targets: 1, order: []string{"a:1"}, Results: []*analyze.Result{imageResult("a:1", 7)}}
	if br.failed() {
		t.Error("a batch with no failures and no holes should report success")
	}
	out := renderBatchSummary(br, renderOpts{})
	if strings.Contains(out, "INCOMPLETE") {
		t.Errorf("clean batch should carry no INCOMPLETE banner:\n%s", out)
	}
}

// The full text report repeats every image's own header, so the reports below
// the roll-up can never be read as one merged scan.
func TestBatchTextKeepsPerImageReports(t *testing.T) {
	br := &batchReport{
		Targets: 2,
		order:   []string{"a:1", "b:1"},
		Results: []*analyze.Result{imageResult("a:1", 1), imageResult("b:1", 1)},
	}
	out := renderBatchText(br, renderOpts{})
	for _, want := range []string{"BATCH SUMMARY", "vexscan report (image) for a:1", "vexscan report (image) for b:1"} {
		if !strings.Contains(out, want) {
			t.Errorf("batch text missing %q:\n%s", want, out)
		}
	}
}
