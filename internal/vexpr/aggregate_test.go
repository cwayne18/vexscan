package vexpr

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// otherProduct is a second image, so the aggregate has more than one product to
// merge -- which is the whole of what makes it an aggregate.
const otherProduct = "pkg:oci/other?repository_url=index.docker.io/example/other"

// aggregateDoc is a minimal merged report: two products in one file, the shape
// rancher/vexhub's reports/*.openvex.json have at 316,236 statements.
const aggregateDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/merged",
  "author": "Hub Owner",
  "version": 3,
  "timestamp": "2026-01-01T00:00:00Z",
  "statements": [
    {
      "vulnerability": {"name": "CVE-1"},
      "products": [{"@id": "` + testProduct + `", "subcomponents": [{"@id": "pkg:deb/debian/a@1"}]}],
      "status": "not_affected"
    }
  ]
}
`

func aggProps() []ProductProposal {
	return []ProductProposal{
		{Product: testProduct, Claims: []Claim{
			claim("CVE-1", "pkg:deb/debian/a@1"), // already in the aggregate
			claim("CVE-2", "pkg:deb/debian/b@1"), // new
		}},
		{Product: otherProduct, Claims: []Claim{{
			Vuln: "CVE-3", Product: otherProduct,
			Subcomponent: "pkg:deb/debian/c@1", Status: StatusNotAffected,
		}}},
	}
}

// TestMergeAggregateFoldsEveryProduct is the core of the feature: one file,
// every product, dedupe still honoured against what it already carries.
func TestMergeAggregateFoldsEveryProduct(t *testing.T) {
	content, changes, err := openvexEncoder{}.mergeAggregate(
		[]byte(aggregateDoc), aggProps(), testMeta("2026-09-10T00:00:00Z"))
	if err != nil {
		t.Fatalf("mergeAggregate: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %+v, want one per product", changes)
	}
	if got := changes[0].Vulns; len(got) != 1 || got[0] != "CVE-2" {
		t.Errorf("%s gained %v, want [CVE-2] (CVE-1 is already there)", changes[0].Product, got)
	}
	if got := changes[1].Vulns; len(got) != 1 || got[0] != "CVE-3" {
		t.Errorf("%s gained %v, want [CVE-3]", changes[1].Product, got)
	}

	doc, ok := ParseDoc(content)
	if !ok {
		t.Fatal("merged aggregate does not parse")
	}
	if len(doc.Statements) != 3 {
		t.Errorf("aggregate has %d statements, want 3", len(doc.Statements))
	}
	// The hub's own top-level members survive: an aggregate is somebody's
	// published file, and a merge adds to it rather than reissuing it.
	if doc.ID != "https://example.com/merged" {
		t.Errorf("@id = %q, want the hub's own", doc.ID)
	}
	if fmt := doc.Version; fmt != json.Number("3") && fmt != float64(3) {
		t.Errorf("version = %v, want the hub's own 3", fmt)
	}
	if doc.Timestamp != "2026-09-10T00:00:00Z" {
		t.Errorf("timestamp = %q, want the run's", doc.Timestamp)
	}
}

// TestMergeAggregateIsIdempotent pins the property the whole flow rests on: a
// re-run that has nothing new to say produces no write at all, so a scheduled
// job does not open a pull request a day.
func TestMergeAggregateIsIdempotent(t *testing.T) {
	first, _, err := openvexEncoder{}.mergeAggregate([]byte(aggregateDoc), aggProps(), testMeta(testTime))
	if err != nil {
		t.Fatalf("first merge: %v", err)
	}
	content, changes, err := openvexEncoder{}.mergeAggregate(first, aggProps(), testMeta("2026-12-25T00:00:00Z"))
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if len(changes) != 0 || content != nil {
		t.Fatalf("second merge changed something: %+v", changes)
	}
}

// TestMergeAggregateRefusesLFSPointer is the one that matters most.
//
// A clone made without git-lfs holds a 133-byte pointer where the 121 MB report
// should be. Writing a small document over it would produce a pull request that
// silently replaces the hub's merged report with a fraction of its contents,
// and it would look entirely normal in review.
func TestMergeAggregateRefusesLFSPointer(t *testing.T) {
	pointer := []byte("version https://git-lfs.github.com/spec/v1\n" +
		"oid sha256:11ff465b87d7368cae022a236bf2000c2667ff0d04b25fdfdfd42a38b17c2c42\n" +
		"size 126788465\n")
	content, _, err := openvexEncoder{}.mergeAggregate(pointer, aggProps(), testMeta(testTime))
	if content != nil {
		t.Fatal("wrote over an LFS pointer")
	}
	var d *declineError
	if !errors.As(err, &d) {
		t.Fatalf("err = %v, want a decline naming LFS", err)
	}
	// The refusal has to say what to do about it; "could not be parsed" sends
	// someone hunting for malformed JSON.
	if !strings.Contains(d.reason, "git lfs pull") {
		t.Errorf("reason = %q, want it to name the command that fixes it", d.reason)
	}
}

func TestIsLFSPointer(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"pointer", "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1\n", true},
		{"openvex document", aggregateDoc, false},
		{"empty", "", false},
		{"prose that starts the same way", "version https://git-lfs.github.com/spec/v1 is what we use\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLFSPointer([]byte(tc.in)); got != tc.want {
				t.Errorf("isLFSPointer = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMergeAggregateRefusesCSAF(t *testing.T) {
	advisory := `{"document":{"category":"csaf_vex","csaf_version":"2.0",` +
		`"publisher":{"category":"other","name":"x","namespace":"https://x"},` +
		`"title":"t","tracking":{"id":"X","current_release_date":"2026-01-01T00:00:00Z",` +
		`"initial_release_date":"2026-01-01T00:00:00Z","status":"final","version":"1",` +
		`"revision_history":[]}}}`
	content, _, err := openvexEncoder{}.mergeAggregate([]byte(advisory), aggProps(), testMeta(testTime))
	if content != nil {
		t.Fatal("wrote OpenVEX statements into a CSAF advisory")
	}
	var d *declineError
	if !errors.As(err, &d) {
		t.Fatalf("err = %v, want a decline", err)
	}
}

func TestCheckAggregatePath(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{in: "reports/rancher.openvex.json"},
		{in: "merged.json"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "/etc/passwd", wantErr: true},
		{in: "../outside.json", wantErr: true},
		{in: "reports/../../outside.json", wantErr: true},
		{in: "index.json", wantErr: true},
		{in: "./reports/x.json", wantErr: true}, // not clean; the message suggests the fix
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if err := checkAggregatePath(tc.in); (err != nil) != tc.wantErr {
				t.Errorf("checkAggregatePath(%q) = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestPlanAggregatesRejectsMissingHubDocument pins the typo guard: naming a path
// the hub does not publish is an error, not an invitation to create the file.
func TestPlanAggregatesRejectsMissingHubDocument(t *testing.T) {
	plan := &Plan{}
	opts := Options{Hub: emptyHub{}, Aggregates: []string{"reports/typoed.openvex.json"}}
	err := planAggregates(context.Background(), plan, openvexEncoder{}, aggProps(), opts, testMeta(testTime))
	if err == nil || !strings.Contains(err.Error(), "publishes no document") {
		t.Fatalf("err = %v, want a refusal naming the missing document", err)
	}
}

// TestPlanAggregatesRejectsProductPath catches the collision that would
// otherwise lose statements: the second write is built from the hub's original
// bytes and would drop the first one's additions.
func TestPlanAggregatesRejectsProductPath(t *testing.T) {
	const loc = "pkg/oci/index.docker.io/example/synthetic/scan.openvex.json"
	plan := &Plan{Changes: []FileChange{{Path: loc, Content: []byte("{}")}}}
	opts := Options{Hub: emptyHub{}, Aggregates: []string{loc}}
	err := planAggregates(context.Background(), plan, openvexEncoder{}, aggProps(), opts, testMeta(testTime))
	if err == nil || !strings.Contains(err.Error(), "already writes that path") {
		t.Fatalf("err = %v, want a refusal naming the collision", err)
	}
}

// TestPlanAggregatesRejectsCSAF pins that the format check survives even if the
// CLI's up-front one is bypassed.
func TestPlanAggregatesRejectsCSAF(t *testing.T) {
	opts := Options{Format: FormatCSAF, Aggregates: []string{"reports/x.json"}}
	err := planAggregates(context.Background(), &Plan{}, csafEncoder{}, aggProps(), opts, testMeta(testTime))
	if err == nil || !strings.Contains(err.Error(), "merged OpenVEX report") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

// TestPlanAggregatesFailsRatherThanSkips pins that a named aggregate this
// cannot write stops the run.
//
// The alternative -- warn and carry on, which is what a per-product document
// gets -- would produce exactly the pull request --vex-merge-into exists to
// prevent: the tree updated, the merged report everything actually reads left
// behind, and a warning somewhere above the diff. Nothing is on disk at this
// point, so failing leaves the clone untouched rather than half done.
func TestPlanAggregatesFailsRatherThanSkips(t *testing.T) {
	plan := &Plan{Changes: []FileChange{{Path: "pkg/x/scan.openvex.json", Content: []byte("{}")}}}
	opts := Options{Hub: pointerHub{}, Aggregates: []string{"reports/rancher.openvex.json"}}
	err := planAggregates(context.Background(), plan, openvexEncoder{}, aggProps(), opts, testMeta(testTime))
	if err == nil {
		t.Fatal("carried on past an aggregate it could not write")
	}
	if !strings.Contains(err.Error(), "git lfs pull") {
		t.Errorf("err = %v, want it to name the command that fixes it", err)
	}
	if len(plan.Aggregates) != 0 {
		t.Errorf("recorded an aggregate change anyway: %+v", plan.Aggregates)
	}
}

// emptyHub is a hub with an index and no documents at all.
type emptyHub struct{}

func (emptyHub) IndexRaw() []byte { return []byte(`{"version":1,"packages":[]}`) }
func (emptyHub) Raw(context.Context, string) ([]byte, bool, error) {
	return nil, false, nil
}

// pointerHub is a hub cloned without git-lfs: every document is the pointer
// that names it rather than the object itself.
type pointerHub struct{}

func (pointerHub) IndexRaw() []byte { return []byte(`{"version":1,"packages":[]}`) }
func (pointerHub) Raw(context.Context, string) ([]byte, bool, error) {
	return []byte("version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 126788465\n"), true, nil
}
