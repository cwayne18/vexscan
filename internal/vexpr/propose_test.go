package vexpr

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// fakeHub is a hub held in memory: an index and whatever documents it points at.
// It stands in for *vex.Hub, which reads the same two things off a directory or
// over HTTPS.
type fakeHub struct {
	index string
	files map[string]string
}

func (h *fakeHub) IndexRaw() []byte { return []byte(h.index) }

func (h *fakeHub) Raw(_ context.Context, loc string) ([]byte, bool, error) {
	b, ok := h.files[loc]
	if !ok {
		return nil, false, nil
	}
	return []byte(b), true, nil
}

const syntheticLoc = "pkg/oci/index.docker.io/example/synthetic/scan.openvex.json"

// syntheticIndex is a hub index that already knows the product the test
// findings are filed under.
func syntheticIndex(extra ...string) string {
	entries := append([]string{
		`{"id":"pkg:oci/synthetic?repository_url=index.docker.io%2Fexample%2Fsynthetic","location":"` + syntheticLoc + `"}`,
	}, extra...)
	return `{"version":1,"packages":[` + strings.Join(entries, ",") + `]}`
}

// ruledOutResult is a scan that ruled out the named CVEs against testProduct.
func ruledOutResult(cves ...string) *analyze.Result {
	res := &analyze.Result{Target: "example/synthetic:latest"}
	for i, cve := range cves {
		res.Findings = append(res.Findings, analyze.Finding{
			ID: cve, CVE: cve, Product: testProduct,
			PURL:          "pkg:deb/debian/pkg" + string(rune('a'+i)) + "@1",
			Status:        analyze.StatusNotPresent,
			Justification: "component_not_present", Method: "pkgdb",
		})
	}
	return res
}

func proposeInto(t *testing.T, hub HubReader, res *analyze.Result) *Plan {
	t.Helper()
	plan, err := Propose(context.Background(), res, Options{
		Hub: hub, Author: "Acme Security", Timestamp: testTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestProposeMergesIntoExistingDocument(t *testing.T) {
	hub := &fakeHub{index: syntheticIndex(), files: map[string]string{
		syntheticLoc: `{
			"@context":"https://openvex.dev/ns/v0.2.0","author":"Prev","version":1,
			"timestamp":"2026-01-01T00:00:00Z","statements":[
				{"vulnerability":{"name":"CVE-OLD"},
				 "products":[{"@id":"pkg:oci/synthetic?repository_url=index.docker.io/example/synthetic",
				   "subcomponents":[{"@id":"pkg:deb/debian/pkga@1"}]}],
				 "status":"not_affected"}
			]}`,
	}}
	// CVE-OLD is already in the document against the same subcomponent, so only
	// CVE-NEW is new.
	res := ruledOutResult("CVE-OLD", "CVE-NEW")
	res.Findings[1].PURL = "pkg:deb/debian/pkga@1"
	res.Findings[1].Product = testProduct

	plan := proposeInto(t, hub, res)
	if plan.Statements != 1 {
		t.Fatalf("statements = %d, want 1 (CVE-OLD deduped away)", plan.Statements)
	}
	// Only the product document changes; index.json already knows this product.
	if len(plan.Changes) != 1 || plan.Changes[0].Path != syntheticLoc {
		t.Fatalf("changes = %+v, want only %s", pathsOf(plan), syntheticLoc)
	}
	got := string(plan.Changes[0].Content)
	for _, want := range []string{"CVE-NEW", "CVE-OLD", `"Prev"`} {
		if !strings.Contains(got, want) {
			t.Errorf("merged document lost %s:\n%s", want, got)
		}
	}
}

// TestProposeLeavesUnparsableDocumentAlone covers the difference between "the
// hub has no document for this product" and "the hub has one this version
// cannot read".
//
// Those used to take the same branch: an unreadable document fell through to a
// fresh one, and the output then replaced whatever the hub had published --
// other authors' statements, other authors' names. A statement vexscan cannot
// decode is still one its publisher meant and quite possibly one another reader
// acts on, so the file has to be left exactly as it is, and the omission
// reported rather than counted as success.
func TestProposeLeavesUnparsableDocumentAlone(t *testing.T) {
	hub := &fakeHub{index: syntheticIndex(), files: map[string]string{
		syntheticLoc: `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Vendor",` +
			`"statements":[{"vulnerability":{"name":"CVE-VENDOR-1"}}` + "\n\nNOT JSON",
	}}

	plan := proposeInto(t, hub, ruledOutResult("CVE-NEW"))
	if !plan.Empty() {
		t.Fatalf("plan rewrites an unreadable document: %v", pathsOf(plan))
	}
	if len(plan.Unparsable) != 1 || plan.Unparsable[0] != syntheticLoc {
		t.Fatalf("Unparsable = %v, want [%s] -- the omission must be reported, not silent",
			plan.Unparsable, syntheticLoc)
	}
}

// TestProposeVersionAsStringIsStillReadable is the same guard from the other
// side. OpenVEX calls the version a number and some published hubs write it as
// a string; a typed int made that a decode failure, and a decode failure used
// to mean the document was replaced. The document below is valid and must be
// merged into, not overwritten.
func TestProposeVersionAsStringIsStillReadable(t *testing.T) {
	hub := &fakeHub{index: syntheticIndex(), files: map[string]string{
		syntheticLoc: `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Vendor","version":"1",
			"timestamp":"2026-01-01T00:00:00Z","statements":[
				{"vulnerability":{"name":"CVE-VENDOR-1"},
				 "products":[{"@id":"pkg:oci/synthetic?repository_url=index.docker.io/example/synthetic"}],
				 "status":"not_affected"}]}`,
	}}

	plan := proposeInto(t, hub, ruledOutResult("CVE-NEW"))
	if len(plan.Unparsable) != 0 {
		t.Fatalf(`a "version":"1" document was treated as unreadable: %v`, plan.Unparsable)
	}
	if len(plan.Changes) != 1 {
		t.Fatalf("changes = %v, want one document", pathsOf(plan))
	}
	got := string(plan.Changes[0].Content)
	for _, want := range []string{"CVE-VENDOR-1", "CVE-NEW", `"Vendor"`, `"version": "1"`} {
		if !strings.Contains(got, want) {
			t.Errorf("merged document lost %s:\n%s", want, got)
		}
	}
}

// TestProposeNewProductExtendsIndex checks the other half of a merge: a product
// the hub does not carry needs a document and an index entry pointing at it.
func TestProposeNewProductExtendsIndex(t *testing.T) {
	// A hub that indexes something else entirely, with a top-level field this
	// code does not model.
	hub := &fakeHub{index: `{"version":1,"metadata":{"owner":"someone"},"packages":[
		{"id":"pkg:golang/example.com/other","location":"pkg/golang/example.com/other/scan.openvex.json","note":"kept"}
	]}`}

	plan := proposeInto(t, hub, ruledOutResult("CVE-NEW"))
	want := []string{syntheticLoc, "index.json"}
	if got := pathsOf(plan); !equalStrings(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}

	idx := plan.Changes[1].Content
	// The hub's own entry, its unknown per-entry field and its unknown
	// top-level field all survive: an index is the hub's artifact, and a
	// one-product change must not rewrite it.
	for _, keep := range []string{`"owner": "someone"`, `"note": "kept"`, "pkg:golang/example.com/other"} {
		if !strings.Contains(string(idx), keep) {
			t.Errorf("index.json lost %s:\n%s", keep, idx)
		}
	}
	// And the new product is filed under its encoded key.
	if !strings.Contains(string(idx), "index.docker.io%2Fexample%2Fsynthetic") {
		t.Errorf("index.json does not carry the new product:\n%s", idx)
	}
	var check map[string]any
	if err := json.Unmarshal(idx, &check); err != nil {
		t.Fatalf("index.json is not valid JSON: %v\n%s", err, idx)
	}
}

// TestProposeWithNoHubBootstrapsOne is --vex-out without --vexhub: there is
// nothing to merge against, so the output is a hub in its own right and must
// carry the index that makes it one.
func TestProposeWithNoHubBootstrapsOne(t *testing.T) {
	plan := proposeInto(t, nil, ruledOutResult("CVE-NEW"))
	want := []string{syntheticLoc, "index.json"}
	if got := pathsOf(plan); !equalStrings(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}
	if !strings.Contains(string(plan.Changes[0].Content), `"Acme Security"`) {
		t.Errorf("fresh document does not carry the author:\n%s", plan.Changes[0].Content)
	}
}

func TestProposeNeedsAnAuthor(t *testing.T) {
	_, err := Propose(context.Background(), ruledOutResult("CVE-NEW"), Options{Timestamp: testTime})
	if err == nil {
		t.Fatal("Propose with no author = nil error; an OpenVEX statement has to say who is asserting it")
	}
}

func TestProposeEmptyWhenNothingRuledOut(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		{ID: "CVE-1", CVE: "CVE-1", Product: testProduct, PURL: "pkg:deb/debian/a@1", Status: analyze.StatusLinked},
	}}
	plan := proposeInto(t, nil, res)
	if !plan.Empty() {
		t.Fatalf("plan not empty: %v", pathsOf(plan))
	}
}

// TestWriteNeverEscapesTheOutputDirectory drives a hostile product name all the
// way to the filesystem, because the checks in location.go are only worth
// anything if nothing downstream re-derives a path around them.
//
// The product name here is what vexscan would build from a Go main module read
// out of a binary inside a scanned image -- a string the image's author chose.
func TestWriteNeverEscapesTheOutputDirectory(t *testing.T) {
	res := ruledOutResult("CVE-OK")
	res.Findings = append(res.Findings, analyze.Finding{
		ID: "CVE-EVIL", CVE: "CVE-EVIL",
		Product:       "pkg:golang/example.com/m/../../../../.github/workflows/release",
		PURL:          "pkg:golang/golang.org/x/net",
		Status:        analyze.StatusNotPresent,
		Justification: "component_not_present", Method: "pkgdb",
	})

	plan := proposeInto(t, nil, res)
	if plan.Empty() {
		t.Fatal("plan is empty; the well-formed product should still have been written")
	}
	for _, ch := range plan.Changes {
		if ch.Path == "index.json" {
			continue
		}
		if !strings.HasPrefix(ch.Path, "pkg/") || strings.Contains(ch.Path, "..") {
			t.Errorf("plan writes %q, outside the hub's pkg/ tree", ch.Path)
		}
	}

	root := t.TempDir()
	dir := filepath.Join(root, "hub")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(dir); err != nil {
		t.Fatal(err)
	}
	var written []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			written = append(written, filepath.ToSlash(rel))
		}
		return nil
	})
	if len(written) == 0 {
		t.Fatal("nothing was written; the test proves nothing")
	}
	for _, p := range written {
		if !strings.HasPrefix(p, "hub/") {
			t.Errorf("Write put %q outside the output directory", p)
		}
	}
}

// TestWriteRefusesANonLocalPath is the last-line check, exercised directly
// because no path built by this package should ever reach it.
func TestWriteRefusesANonLocalPath(t *testing.T) {
	for _, bad := range []string{"../escape.json", "/etc/passwd"} {
		p := &Plan{Changes: []FileChange{{Path: bad, Content: []byte("{}")}}}
		if err := p.Write(t.TempDir()); err == nil {
			t.Errorf("Write(%q) = nil error, want a refusal", bad)
		}
	}
}

// TestWriteIntoAHubClone is the documented workflow: merge against a clone and
// write back into it, so the result is a git diff.
func TestWriteIntoAHubClone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(syntheticIndex()), 0o644); err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(dir, filepath.FromSlash(syntheticLoc))
	if err := os.MkdirAll(filepath.Dir(docPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Vendor","version":1,
		"timestamp":"2026-01-01T00:00:00Z","statements":[]}`
	if err := os.WriteFile(docPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	hub := &fakeHub{index: syntheticIndex(), files: map[string]string{syntheticLoc: existing}}
	plan := proposeInto(t, hub, ruledOutResult("CVE-NEW"))
	if err := plan.Write(dir); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "CVE-NEW") {
		t.Errorf("the clone's document was not updated:\n%s", after)
	}
	if !strings.Contains(string(after), `"Vendor"`) {
		t.Errorf("writing back into the clone dropped the existing author:\n%s", after)
	}
}

// TestProposeKeepsTheHubsFormatting is the point of the whole design, applied
// to whitespace: the reviewer of the resulting pull request has to be able to
// see what changed.
//
// rancher/vexhub's index.json is 4381 lines and has no trailing newline.
// Re-emitting it with this package's own preferences -- two spaces, newline at
// end -- turns a one-product addition into a diff that touches the last line
// too, and against a hub indenting with four spaces it would touch all 4381.
// So the formatting is read off the file and reproduced, and the only lines in
// the diff are the ones with new content.
func TestProposeKeepsTheHubsFormatting(t *testing.T) {
	// Four-space indent, no trailing newline, on both files.
	index := "{\n" +
		`    "version": 1,` + "\n" +
		`    "packages": [` + "\n" +
		`        {"id":"pkg:golang/example.com/other","location":"pkg/golang/example.com/other/scan.openvex.json"}` + "\n" +
		"    ]\n}"
	doc := "{\n" +
		`    "@context": "https://openvex.dev/ns/v0.2.0",` + "\n" +
		`    "author": "Vendor",` + "\n" +
		`    "version": 1,` + "\n" +
		`    "statements": []` + "\n}"

	hub := &fakeHub{index: index, files: map[string]string{syntheticLoc: doc}}
	// The index does not carry the scanned product, so both files change.
	plan := proposeInto(t, hub, ruledOutResult("CVE-NEW"))
	if got, want := pathsOf(plan), []string{syntheticLoc, "index.json"}; !equalStrings(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}

	for _, ch := range plan.Changes {
		got := string(ch.Content)
		if strings.HasSuffix(got, "\n") {
			t.Errorf("%s gained a trailing newline the hub does not have:\n%s", ch.Path, got)
		}
		if strings.Contains(got, "\n  \"") {
			t.Errorf("%s was reindented from four spaces to two:\n%s", ch.Path, got)
		}
		if !strings.Contains(got, "\n    \"") {
			t.Errorf("%s does not use the hub's four-space indent:\n%s", ch.Path, got)
		}
	}
}

// TestMarshalDefaultsToTwoSpacesAndANewline covers the other side: a file this
// package creates has no formatting to inherit, so it picks the conventional
// one rather than emitting a single line.
func TestMarshalDefaultsToTwoSpacesAndANewline(t *testing.T) {
	plan := proposeInto(t, nil, ruledOutResult("CVE-NEW"))
	for _, ch := range plan.Changes {
		got := string(ch.Content)
		if !strings.HasSuffix(got, "\n") {
			t.Errorf("%s has no trailing newline:\n%s", ch.Path, got)
		}
		if !strings.Contains(got, "\n  \"") {
			t.Errorf("%s is not indented with two spaces:\n%s", ch.Path, got)
		}
	}
}

func pathsOf(p *Plan) []string {
	out := make([]string, 0, len(p.Changes))
	for _, ch := range p.Changes {
		out = append(out, ch.Path)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
