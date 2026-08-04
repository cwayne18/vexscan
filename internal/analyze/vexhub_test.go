package analyze

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// The hub these tests run against is internal/vex's testdata, reached over
// HTTP so the request count is observable: one lookup per product is the
// property that keeps a three-hundred-finding image to a single fetch.
const (
	k8sProduct = "pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes"
	hubDir     = "../vex/testdata/hub"
)

func hubServer(t *testing.T, hits *int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		b, err := os.ReadFile(filepath.Join(hubDir, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/"))))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func quiet(string, ...any) {}

// osFinding is a linked OS finding of the kind a Rancher image produces, with
// the purl spelling vexscan actually emits.
func osFinding(id, name string) Finding {
	return Finding{
		Ecosystem: "os", ID: id, CVE: id,
		Package: name, Module: name, Version: "4.8.1-150600.1.1",
		PURL:    "pkg:rpm/sles/" + name + "@4.8.1-150600.1.1?arch=x86_64",
		Product: k8sProduct,
		Status:  StatusLinked, Method: "elf-needed-closure",
	}
}

func TestVexOverlayAnnotatesWithoutChangingStatus(t *testing.T) {
	var hits int
	findings := []Finding{osFinding("SUSE-RU-2026:1228-1", "shadow")}

	hubs := vexOverlay(context.Background(), []string{hubServer(t, &hits)}, findings, nil, quiet)

	f := findings[0]
	if f.VEX == nil {
		t.Fatalf("no statement attached")
	}
	if f.VEX.Status != "not_affected" {
		t.Errorf("vex status = %q", f.VEX.Status)
	}
	if f.VEX.Author != "Rancher Security team" {
		t.Errorf("author = %q", f.VEX.Author)
	}
	// The whole design rests on this: the local verdict is untouched, so a run
	// with a hub and a run without agree on every status and on the JSON.
	if f.Status != StatusLinked {
		t.Errorf("status = %q, want the local verdict unchanged", f.Status)
	}
	if f.Method != "elf-needed-closure" {
		t.Errorf("method = %q", f.Method)
	}

	// The claim is recorded as evidence, and never as a taint.
	var found bool
	for _, e := range f.Evidence {
		if e.Origin != "vendor-vex" {
			continue
		}
		found = true
		if e.Blocking {
			t.Error("a vendor claim was recorded as a blocking taint")
		}
		if !strings.Contains(e.Detail, "Rancher Security team") || !strings.Contains(e.Detail, "not_affected") {
			t.Errorf("evidence detail = %q", e.Detail)
		}
	}
	if !found {
		t.Error("no vendor-vex evidence was recorded")
	}

	if len(hubs) != 1 || hubs[0].Matched != 1 || hubs[0].Products != 3 {
		t.Errorf("hub result = %+v", hubs)
	}
}

// One fetch per product, not per finding.
func TestVexOverlayLooksUpEachProductOnce(t *testing.T) {
	var hits int
	findings := []Finding{
		osFinding("SUSE-RU-2026:1228-1", "shadow"),
		osFinding("SUSE-RU-2026:1228-1", "login_defs"),
		osFinding("SUSE-FU-2026:21213-1", "libgcrypt20"),
		osFinding("CVE-1999-0001", "bash"),
	}

	hubs := vexOverlay(context.Background(), []string{hubServer(t, &hits)}, findings, nil, quiet)

	// index.json plus one document, however many findings share the product.
	if hits != 2 {
		t.Errorf("%d requests, want 2 (index + one document)", hits)
	}
	if hubs[0].Matched != 3 {
		t.Errorf("matched %d, want 3", hubs[0].Matched)
	}
	if findings[3].VEX != nil {
		t.Errorf("an advisory the hub says nothing about was annotated: %+v", findings[3].VEX)
	}
}

// A finding whose product the hub does not index is left exactly as it was.
func TestVexOverlayLeavesUncoveredProductsAlone(t *testing.T) {
	var hits int
	f := osFinding("SUSE-RU-2026:1228-1", "shadow")
	f.Product = "pkg:oci/debian?repository_url=index.docker.io/library/debian"
	findings := []Finding{f}

	hubs := vexOverlay(context.Background(), []string{hubServer(t, &hits)}, findings, nil, quiet)

	if findings[0].VEX != nil || len(findings[0].Evidence) != 0 {
		t.Errorf("an uncovered product was annotated: %+v", findings[0])
	}
	if hubs[0].Matched != 0 {
		t.Errorf("matched %d, want 0", hubs[0].Matched)
	}
	if hits != 1 {
		t.Errorf("%d requests, want 1 (index only)", hits)
	}
}

// The asymmetry that matters: a hub that cannot be read is recorded and warned
// about, and changes nothing about the findings.
func TestAFailedHubIsRecordedAndChangesNothing(t *testing.T) {
	findings := []Finding{osFinding("SUSE-RU-2026:1228-1", "shadow")}
	before := findings[0]

	var logged []string
	hubs := vexOverlay(context.Background(), []string{"https://invalid.example/nope"}, findings, nil,
		func(f string, a ...any) { logged = append(logged, f) })

	if len(hubs) != 1 || hubs[0].Error == "" {
		t.Fatalf("the failure was not recorded: %+v", hubs)
	}
	if findings[0].VEX != nil || findings[0].Status != before.Status {
		t.Errorf("the finding changed: %+v", findings[0])
	}
	if len(logged) == 0 {
		t.Error("a hub failed silently")
	}
}

// The first hub named wins, so an internal hub can be listed ahead of a
// vendor's to override it.
func TestTheFirstHubToSpeakWins(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.json", `{"version":1,"packages":[{"id":"`+k8sProduct+`","location":"docs/x.json"}]}`)
	write(filepath.Join("docs", "x.json"), `{"author":"Internal AppSec","timestamp":"2026-01-01T00:00:00Z","statements":[
		{"vulnerability":{"name":"SUSE-RU-2026:1228-1"},
		 "products":[{"@id":"`+k8sProduct+`","subcomponents":[{"@id":"pkg:rpm/suse/shadow"}]}],
		 "status":"affected","action_statement":"We ship this path; patch it."}]}`)

	var hits int
	findings := []Finding{osFinding("SUSE-RU-2026:1228-1", "shadow")}
	hubs := vexOverlay(context.Background(), []string{dir, hubServer(t, &hits)}, findings, nil, quiet)

	if got := findings[0].VEX.Author; got != "Internal AppSec" {
		t.Errorf("author = %q, want the first hub's", got)
	}
	if got := findings[0].VEX.Status; got != "affected" {
		t.Errorf("status = %q, want the first hub's, not the vendor's not_affected", got)
	}
	if hubs[0].Matched != 1 || hubs[1].Matched != 0 {
		t.Errorf("matched counts = %d, %d; want 1, 0", hubs[0].Matched, hubs[1].Matched)
	}
}

func TestVexOverlayIsANoOpWithoutHubs(t *testing.T) {
	findings := []Finding{osFinding("SUSE-RU-2026:1228-1", "shadow")}
	if hubs := vexOverlay(context.Background(), nil, findings, nil, quiet); hubs != nil {
		t.Errorf("hubs = %+v, want nil", hubs)
	}
	if findings[0].VEX != nil {
		t.Error("a finding was annotated with no hub configured")
	}
}

// The image is the product for every finding a plugin did not claim a narrower
// one for, and the Go plugin's own answer is never overwritten.
func TestProductOverlayFillsInTheImageWithoutOverriding(t *testing.T) {
	findings := []Finding{
		{CVE: "CVE-1", PURL: "pkg:deb/debian/libc6@2.36"},
		{CVE: "CVE-2", PURL: "pkg:golang/golang.org/x/net@v0.44.0", Product: "pkg:golang/github.com/rancher/rancher"},
	}
	productOverlay(findings, "rancher/hardened-kubernetes:v1.30.1")

	if got := findings[0].Product; got != k8sProduct {
		t.Errorf("product = %q, want %q", got, k8sProduct)
	}
	if got := findings[1].Product; got != "pkg:golang/github.com/rancher/rancher" {
		t.Errorf("the plugin's own product was overwritten: %q", got)
	}
}

// --rootfs analyzes a tree nobody recorded the provenance of, so there is no
// product to invent.
func TestProductOverlayDoesNothingWithoutAnImage(t *testing.T) {
	findings := []Finding{{CVE: "CVE-1", PURL: "pkg:deb/debian/libc6@2.36"}}
	productOverlay(findings, "")
	if findings[0].Product != "" {
		t.Errorf("product = %q, want empty for a rootfs scan", findings[0].Product)
	}
}

func TestFindingIDsCoversEverySpelling(t *testing.T) {
	got := findingIDs(Finding{ID: "GHSA-x", CVE: "GHSA-x", GoID: "GO-2025-1"}, nil)
	if len(got) != 2 || got[0] != "GHSA-x" || got[1] != "GO-2025-1" {
		t.Errorf("findingIDs = %v", got)
	}
}

// The case that decides whether a hub matches anything at all: the finding is
// named GO-2025-3547 and the hub filed under CVE-2024-7598, with nothing on
// either side carrying the other's spelling.
func TestFindingIDsBridgesToTheHubsSpellingViaOSVAliases(t *testing.T) {
	aliases := map[string][]string{
		"GO-2025-3547": {"GO-2025-3547", "CVE-2024-7598", "GHSA-r56h-j38w-hrqq"},
	}
	got := findingIDs(Finding{ID: "GO-2025-3547", CVE: "GO-2025-3547"}, aliases)
	if !contains(got, "CVE-2024-7598") {
		t.Errorf("findingIDs = %v, want the CVE the hub files under", got)
	}
}

// A hub filing under the CVE reaches a finding that only knows its GO id. This
// is the gap the first live run against rancher/vexhub exposed: 13 advisories,
// 133 hub ids, zero overlap until the aliases were expanded.
func TestVexOverlayMatchesThroughAnAlias(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"index.json": `{"version":1,"packages":[{"id":"pkg:golang/k8s.io/kubernetes","location":"docs/k.json"}]}`,
		filepath.Join("docs", "k.json"): `{"author":"Rancher Security team","timestamp":"2026-01-01T00:00:00Z","statements":[
			{"vulnerability":{"name":"CVE-2024-7598"},
			 "products":[{"@id":"pkg:golang/k8s.io/kubernetes",
			              "subcomponents":[{"@id":"pkg:golang/k8s.io/apiserver@v0.29.0"}]}],
			 "status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	newFinding := func() Finding {
		return Finding{
			Ecosystem: "golang", ID: "GO-2025-3547", CVE: "GO-2025-3547", GoID: "GO-2025-3547",
			// The percent-encoded form the Go plugin actually emits.
			PURL:    "pkg:golang/k8s.io%2Fapiserver@v0.31.2",
			Product: "pkg:golang/k8s.io/kubernetes",
			Status:  StatusLinked,
		}
	}
	aliases := map[string][]string{"GO-2025-3547": {"GO-2025-3547", "CVE-2024-7598"}}

	findings := []Finding{newFinding()}
	hubs := vexOverlay(context.Background(), []string{dir}, findings, aliases, quiet)
	if findings[0].VEX == nil {
		t.Fatalf("no match through the alias; hub = %+v", hubs)
	}

	// Without the alias map the same scan finds nothing, so the expansion is
	// doing the work rather than something else in the chain.
	plain := []Finding{newFinding()}
	vexOverlay(context.Background(), []string{dir}, plain, nil, quiet)
	if plain[0].VEX != nil {
		t.Error("the id matched without needing the alias, so this test proves nothing")
	}
}

func TestVEXStatementExculpatory(t *testing.T) {
	var nilStmt *ecosystem.VEXStatement
	if nilStmt.Exculpatory() {
		t.Error("a nil statement is exculpatory")
	}
	for status, want := range map[string]bool{
		"not_affected": true, "fixed": true,
		"affected": false, "under_investigation": false, "": false,
	} {
		if got := (&ecosystem.VEXStatement{Status: status}).Exculpatory(); got != want {
			t.Errorf("Exculpatory(%q) = %v, want %v", status, got, want)
		}
	}
}
