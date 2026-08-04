package vex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The hub under testdata/ is the real rancher/vexhub index and two of its real
// documents, trimmed to their first few statements, plus one synthetic product
// (example/synthetic) that carries the cases the live data does not happen to
// contain: a product-wide statement, two statements competing for one
// vulnerability, and a subcomponent whose type differs from the finding's.

const (
	k8sProduct       = "pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes"
	clickhouseModule = "github.com/Altinity/clickhouse-backup/v2"
	syntheticProduct = "pkg:oci/synthetic?repository_url=index.docker.io/example/synthetic"
)

func openTestHub(t *testing.T) *Hub {
	t.Helper()
	h, err := Open(context.Background(), filepath.Join("testdata", "hub"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return h
}

func lookup(t *testing.T, h *Hub, product string) *Doc {
	t.Helper()
	doc, ok, err := h.Lookup(context.Background(), product)
	if err != nil {
		t.Fatalf("Lookup(%s): %v", product, err)
	}
	if !ok {
		t.Fatalf("Lookup(%s): no document, want one", product)
	}
	return doc
}

// ImageProduct has to produce the exact string the hub used as a key, so every
// case here is an image reference next to the index entry it must equal.
func TestImageProductMatchesTheIndexSpelling(t *testing.T) {
	cases := []struct{ ref, want string }{
		{"rancher/hardened-kubernetes:v1.30.1", k8sProduct},
		{"rancher/hardened-kubernetes", k8sProduct},
		{"docker.io/rancher/hardened-kubernetes:latest", k8sProduct},
		{"index.docker.io/rancher/hardened-kubernetes", k8sProduct},
		// A bare name is under library/, the way Docker resolves it.
		{"nginx", "pkg:oci/nginx?repository_url=index.docker.io/library/nginx"},
		{"nginx:1.27", "pkg:oci/nginx?repository_url=index.docker.io/library/nginx"},
		// A digest is not part of the product identity, and contains a ':'
		// that must not be mistaken for a tag separator.
		{"quay.io/stackstate/agent@sha256:" + strings.Repeat("a", 64),
			"pkg:oci/agent?repository_url=quay.io/stackstate/agent"},
		{"registry.suse.com/rancher/hardened-kubernetes:v1.30.1",
			"pkg:oci/hardened-kubernetes?repository_url=registry.suse.com/rancher/hardened-kubernetes"},
		// A port makes the first segment a registry even without a dot.
		{"localhost:5000/team/app:dev", "pkg:oci/app?repository_url=localhost:5000/team/app"},
		{"", ""},
		{":", ""},
	}
	for _, c := range cases {
		if got := ImageProduct(c.ref); got != c.want {
			t.Errorf("ImageProduct(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

func TestGoProduct(t *testing.T) {
	if got, want := GoProduct(clickhouseModule), "pkg:golang/"+clickhouseModule; got != want {
		t.Errorf("GoProduct = %q, want %q", got, want)
	}
	if got := GoProduct(""); got != "" {
		t.Errorf("GoProduct(\"\") = %q, want empty", got)
	}
}

// The index writes its keys percent-encoded and the @id inside the document it
// points at does not, so a lookup only works if both go through the same
// canonicalization.
func TestLookupMatchesAPercentEncodedIndexKey(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, k8sProduct)
	if doc.Author != "Rancher Security team" {
		t.Errorf("author = %q", doc.Author)
	}
	// The key was pkg:oci/...%2Francher%2F...; the statement inside is not
	// encoded. If canonicalization were one-sided, Match would find nothing.
	if st, _ := Match(doc, k8sProduct, []string{"SUSE-FU-2026:21213-1"}, "pkg:rpm/sles/libgcrypt20@1.9.4?arch=x86_64"); st == nil {
		t.Fatal("no match against the decoded product @id")
	}
}

func TestLookupOfAProductTheHubDoesNotCover(t *testing.T) {
	h := openTestHub(t)
	doc, ok, err := h.Lookup(context.Background(), ImageProduct("debian:12"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if ok || doc != nil {
		t.Fatalf("got a document for debian:12, want none")
	}
}

// The disagreement this whole matching rule exists for: the hub writes
// pkg:rpm/suse/libgcrypt20 and vexscan writes pkg:rpm/sles/libgcrypt20@ver?arch.
func TestSubcomponentMatchesAcrossTheRealPurlDisagreement(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, k8sProduct)

	finding := "pkg:rpm/sles/libgcrypt20@1.9.4-150600.1.1?arch=x86_64"
	st, note := Match(doc, k8sProduct, []string{"SUSE-FU-2026:21213-1"}, finding)
	if st == nil {
		t.Fatal("no match")
	}
	if st.Status != StatusNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if !strings.Contains(st.ImpactStatement, "libgcrypt") {
		t.Errorf("impact statement = %q", st.ImpactStatement)
	}
	// The tolerance is deliberate, so it has to be visible.
	if !strings.Contains(note, "pkg:rpm/suse/libgcrypt20") || !strings.Contains(note, finding) {
		t.Errorf("note does not record the disagreement: %q", note)
	}
}

// Two statements in the real document share one advisory id and differ only by
// subcomponent, which is exactly what the subcomponent comparison is for.
func TestSubcomponentPicksBetweenTwoStatementsOnOneAdvisory(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, k8sProduct)

	for _, name := range []string{"login_defs", "shadow"} {
		st, _ := Match(doc, k8sProduct, []string{"SUSE-RU-2026:1228-1"},
			"pkg:rpm/sles/"+name+"@4.8.1?arch=x86_64")
		if st == nil {
			t.Fatalf("%s: no match", name)
		}
	}
	// A third package under the same advisory is not covered by either.
	if st, _ := Match(doc, k8sProduct, []string{"SUSE-RU-2026:1228-1"}, "pkg:rpm/sles/bash@5.2?arch=x86_64"); st != nil {
		t.Errorf("bash matched a statement written about login_defs and shadow")
	}
}

// A finding carries several ids for the same vulnerability and the hub files
// under only one of them, so any of them has to be enough.
func TestAnAliasIsEnoughToMatch(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, GoProduct(clickhouseModule))

	sub := "pkg:golang/github.com/nwaples/rardecode/v2@v2.1.1"
	for _, id := range []string{"CVE-2025-11579", "GO-2025-4020", "GHSA-rwvp-r38j-9rgg", "ghsa-rwvp-r38j-9rgg"} {
		st, _ := Match(doc, GoProduct(clickhouseModule), []string{id}, sub)
		if st == nil {
			t.Errorf("%s: no match", id)
		}
	}
	if st, _ := Match(doc, GoProduct(clickhouseModule), []string{"CVE-1999-0001"}, sub); st != nil {
		t.Error("an unrelated id matched")
	}
}

// The Go subcomponent version moves with every dependency bump; matching on it
// would make every statement go stale the moment the image is rebuilt.
func TestGoSubcomponentMatchesRegardlessOfVersion(t *testing.T) {
	h := openTestHub(t)
	product := GoProduct(clickhouseModule)
	doc := lookup(t, h, product)

	st, note := Match(doc, product, []string{"CVE-2025-47911"}, "pkg:golang/golang.org/x/net@v0.46.0")
	if st == nil {
		t.Fatal("no match")
	}
	if !strings.Contains(note, "v0.44.0") {
		t.Errorf("note should record the version the statement was written against: %q", note)
	}
	// The full module path is the name for golang -- dropping the leading
	// segment the way an OS namespace is dropped would match anything.
	if st, _ := Match(doc, product, []string{"CVE-2025-47911"}, "pkg:golang/example.com/x/net@v0.46.0"); st != nil {
		t.Error("a different module with the same trailing path matched")
	}
}

func TestExactPurlAgreementLeavesNoNote(t *testing.T) {
	h := openTestHub(t)
	product := GoProduct(clickhouseModule)
	doc := lookup(t, h, product)

	st, note := Match(doc, product, []string{"CVE-2025-47911"}, "pkg:golang/golang.org/x/net@v0.44.0")
	if st == nil {
		t.Fatal("no match")
	}
	if note != "" {
		t.Errorf("note = %q, want empty when the spellings agree", note)
	}
}

func TestAProductWideStatementCoversAnySubcomponent(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, syntheticProduct)

	st, _ := Match(doc, syntheticProduct, []string{"CVE-2020-0001"}, "pkg:rpm/sles/anything@1.0")
	if st == nil {
		t.Fatal("no match")
	}
	if st.Justification != "component_not_present" {
		t.Errorf("justification = %q", st.Justification)
	}
}

// Two statements can speak to one finding, and which one wins must not depend
// on the order they happen to appear in the document.
func TestTheMoreSpecificStatementWinsOverTheProductWideOne(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, syntheticProduct)

	st, _ := Match(doc, syntheticProduct, []string{"CVE-2020-0002"}, "pkg:rpm/sles/libgcrypt20@1.9.4")
	if st == nil {
		t.Fatal("no match")
	}
	// The product-wide statement is both listed first and newer; naming the
	// dependency still beats both.
	if st.Status != StatusNotAffected {
		t.Errorf("status = %q, want the subcomponent-scoped not_affected", st.Status)
	}
	// A different package under the same advisory falls back to the
	// product-wide claim.
	st, _ = Match(doc, syntheticProduct, []string{"CVE-2020-0002"}, "pkg:rpm/sles/bash@5.2")
	if st == nil {
		t.Fatal("no fallback to the product-wide statement")
	}
	if st.Status != StatusAffected {
		t.Errorf("status = %q, want the product-wide affected", st.Status)
	}
}

func TestTheNewerOfTwoEquallySpecificStatementsWins(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, syntheticProduct)

	st, _ := Match(doc, syntheticProduct, []string{"CVE-2020-0003"}, "pkg:rpm/sles/shadow@4.8.1")
	if st == nil {
		t.Fatal("no match")
	}
	if st.Status != StatusFixed {
		t.Errorf("status = %q, want the amended fixed, not the earlier under_investigation", st.Status)
	}
}

func TestTypeIsPartOfTheSubcomponentIdentity(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, syntheticProduct)

	if st, _ := Match(doc, syntheticProduct, []string{"CVE-2020-0004"}, "pkg:golang/lodash@1.0.0"); st != nil {
		t.Error("a golang purl matched a statement written about an npm package")
	}
	if st, _ := Match(doc, syntheticProduct, []string{"CVE-2020-0004"}, "pkg:npm/lodash@4.17.21"); st == nil {
		t.Error("the npm package did not match its own statement")
	}
}

func TestAStatementForAnotherProductIsNotUsed(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, k8sProduct)

	if st, _ := Match(doc, syntheticProduct, []string{"SUSE-FU-2026:21213-1"}, "pkg:rpm/sles/libgcrypt20@1.9.4"); st != nil {
		t.Error("a statement matched under a product it does not name")
	}
}

// A statement that names no vulnerability or no product can never match
// anything, so it is dropped at parse time rather than carried as an entry that
// silently never fires.
func TestUnmatchableStatementsAreDropped(t *testing.T) {
	h := openTestHub(t)
	doc := lookup(t, h, syntheticProduct)

	if got, want := len(doc.Statements), 6; got != want {
		t.Errorf("parsed %d statements, want %d", got, want)
	}
	for _, s := range doc.Statements {
		if s.Vulnerability == "" || len(s.Products) == 0 {
			t.Errorf("kept an unmatchable statement: %+v", s)
		}
	}
}

// A statement without its own timestamp inherits the document's, so the
// newest-wins tiebreak has something to compare.
func TestAStatementInheritsTheDocumentTimestamp(t *testing.T) {
	doc, err := ParseDoc([]byte(`{"author":"A","timestamp":"2026-01-01T00:00:00Z","statements":[
		{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/x"}],"status":"fixed"}]}`))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	if got := doc.Statements[0].Timestamp; got != "2026-01-01T00:00:00Z" {
		t.Errorf("timestamp = %q", got)
	}
}

func TestExculpatory(t *testing.T) {
	cases := map[string]bool{
		StatusNotAffected:        true,
		StatusFixed:              true,
		StatusAffected:           false,
		StatusUnderInvestigation: false,
		"":                       false,
		"nonsense":               false,
	}
	for status, want := range cases {
		if got := Exculpatory(status); got != want {
			t.Errorf("Exculpatory(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestMatchOnANilDocument(t *testing.T) {
	if st, note := Match(nil, k8sProduct, []string{"CVE-1"}, "pkg:rpm/sles/x@1"); st != nil || note != "" {
		t.Error("a nil document produced a match")
	}
}

// A GitHub repository URL is what a reader would paste, so it has to resolve to
// the raw host without them knowing that form exists.
func TestGitHubURLsResolveToRawPaths(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://github.com/rancher/vexhub", "https://raw.githubusercontent.com/rancher/vexhub/HEAD/"},
		{"https://github.com/rancher/vexhub/", "https://raw.githubusercontent.com/rancher/vexhub/HEAD/"},
		{"https://example.internal/vex", "https://example.internal/vex/"},
		{"https://example.internal/vex/", "https://example.internal/vex/"},
	}
	for _, c := range cases {
		got, local, err := resolveBase(c.in)
		if err != nil {
			t.Errorf("resolveBase(%q): %v", c.in, err)
			continue
		}
		if local {
			t.Errorf("resolveBase(%q) reported a local path", c.in)
		}
		if got != c.want {
			t.Errorf("resolveBase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, _, err := resolveBase("https://github.com/rancher"); err == nil {
		t.Error("an owner-only GitHub URL was accepted")
	}
	if _, _, err := resolveBase(filepath.Join("testdata", "hub", "index.json")); err == nil {
		t.Error("a file was accepted as a hub")
	}
	if _, _, err := resolveBase("  "); err == nil {
		t.Error("an empty location was accepted")
	}
}

func TestOpenOverHTTPAndCacheDocuments(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		b, err := os.ReadFile(filepath.Join("testdata", "hub", filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/"))))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()

	h, err := Open(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if h.Size() != 3 {
		t.Errorf("Size = %d, want 3", h.Size())
	}
	for i := 0; i < 3; i++ {
		if _, ok, err := h.Lookup(context.Background(), k8sProduct); err != nil || !ok {
			t.Fatalf("Lookup: ok=%v err=%v", ok, err)
		}
	}
	// index.json plus the document once: repeated lookups are served from the
	// cache, which is what keeps a scan of a hundred findings to one fetch.
	if hits != 2 {
		t.Errorf("%d requests, want 2 (index + one document)", hits)
	}
}

func TestOpenReportsAnUnreachableHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := Open(context.Background(), srv.URL); err == nil {
		t.Fatal("Open succeeded against a hub with no index")
	} else if !strings.Contains(err.Error(), "read index") {
		t.Errorf("error does not say what failed: %v", err)
	}
	if _, err := Open(context.Background(), filepath.Join("testdata", "nonexistent")); err == nil {
		t.Fatal("Open succeeded on a missing directory")
	}
}

func TestOpenRejectsAnIndexWithNoPackages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"version":1,"packages":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil {
		t.Error("an empty index was accepted, which would look identical to a hub with nothing to say")
	}
}

// A 404 is the ordinary answer for a product a hub does not cover, so it must
// not cost three attempts and two seconds.
func TestNotFoundIsNotRetried(t *testing.T) {
	if (&StatusError{Status: 404}).Retryable() {
		t.Error("404 is retryable")
	}
	for _, s := range []int{429, 500, 503} {
		if !(&StatusError{Status: s}).Retryable() {
			t.Errorf("%d is not retryable", s)
		}
	}
}
