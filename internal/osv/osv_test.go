package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

const sampleResponse = `{
  "vulns": [
    {
      "id": "GO-2023-1988",
      "aliases": ["CVE-2023-39325", "GHSA-4374-p667-p6c8"],
      "affected": [
        {
          "package": {"name": "golang.org/x/net"},
          "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/http2"}]}
        }
      ]
    },
    {
      "id": "GHSA-only-record",
      "aliases": ["CVE-2023-39325"],
      "affected": [
        {
          "package": {"name": "golang.org/x/net"},
          "ecosystem_specific": {"imports": []}
        }
      ]
    }
  ]
}`

func goRef(name, version string) Ref {
	return Ref{Ecosystem: GoEcosystem, Name: name, Version: version}
}

func TestQueryAliasMappingAndPreference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleResponse))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL

	m, err := c.Query(context.Background(), goRef("golang.org/x/net", "v0.7.0"))
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"GO-2023-1988", "CVE-2023-39325", "GHSA-4374-p667-p6c8"} {
		adv, ok := m[key]
		if !ok {
			t.Fatalf("expected key %q in map", key)
		}
		if len(adv.Pkgs) != 1 || adv.Pkgs[0] != "golang.org/x/net/http2" {
			t.Errorf("key %q: expected http2 import path, got %v", key, adv.Pkgs)
		}
	}

	// CVE-2023-39325 is aliased by both records; the one carrying import paths
	// must win over the empty GHSA-only record.
	if got := m["CVE-2023-39325"].ID; got != "GO-2023-1988" {
		t.Errorf("expected import-carrying record to win, got ID %q", got)
	}
}

// Every distro database relates its records with "upstream" and none with
// "aliases". The shape below is SUSE-SU-2026:0312-1's, trimmed: no aliases at
// all, and eight CVEs it says its patch fixes.
const suseResponse = `{
  "vulns": [
    {
      "id": "SUSE-SU-2026:0312-1",
      "aliases": [],
      "upstream": ["CVE-2024-2511", "CVE-2024-4603", "CVE-2024-5535"],
      "affected": [{"package": {"name": "openssl-3"}}]
    },
    {
      "id": "SUSE-SU-2026:1177-1",
      "aliases": [],
      "upstream": ["CVE-2024-5535"],
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
      "affected": [{"package": {"name": "openssl-3"}}]
    }
  ]
}`

func TestUpstreamIsReadButIsNotAnAlias(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(suseResponse))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL

	m, err := c.Query(context.Background(), Ref{Ecosystem: "SUSE", Name: "openssl-3", Version: "3.1.4"})
	if err != nil {
		t.Fatal(err)
	}

	adv, ok := m["SUSE-SU-2026:0312-1"]
	if !ok {
		t.Fatal("the advisory is not in the map under its own id")
	}
	if len(adv.Upstream) != 3 || adv.Upstream[0] != "CVE-2024-2511" {
		t.Errorf("Upstream = %v, want the three CVEs the record addresses", adv.Upstream)
	}
	if len(adv.Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty -- upstream must not leak into it", adv.Aliases)
	}

	// A bundle is findable by what it fixes, which is what makes --cves work on
	// a distro whose ids name no CVE at all. It is the same advisory under each
	// key, not a copy per CVE: one row is still one thing the distro published.
	for _, cve := range adv.Upstream {
		got, ok := m[cve]
		if !ok {
			t.Errorf("%s is not a key; --cves could not reach the bundle that fixes it", cve)
			continue
		}
		if got != adv {
			t.Errorf("%s resolves to %s, want the same advisory its own id does", cve, got.ID)
		}
	}

	// Two SUSE records sharing an upstream CVE are two different patches, and
	// the second's vector must not be borrowed onto the first. This is what the
	// ordering inside buildMap buys: borrowSeverity runs before the CVE keys
	// exist, so it can never walk from one bundle-mate to another.
	if adv.CVSSVector != "" {
		t.Errorf("CVSSVector = %q, want empty -- severity was borrowed across a shared upstream CVE", adv.CVSSVector)
	}
}

// TestARealRecordOutranksABundleThatMerelyFixesIt pins the precedence between
// the two passes. When a query returns both a CVE's own record and a distro
// advisory addressing it, looking up the CVE must find the record about it --
// with its own severity and its own ranges -- not the patch that mentions it.
func TestARealRecordOutranksABundleThatMerelyFixesIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[
			{"id":"SUSE-SU-2026:0312-1","upstream":["CVE-2024-2511"]},
			{"id":"CVE-2024-2511","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
		]}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL

	m, err := c.Query(context.Background(), Ref{Ecosystem: "SUSE", Name: "openssl-3", Version: "3.1.4"})
	if err != nil {
		t.Fatal(err)
	}
	if got := m["CVE-2024-2511"]; got == nil || got.ID != "CVE-2024-2511" {
		t.Fatalf("CVE-2024-2511 resolves to %v, want the record about it", got)
	}
}

func TestQueryNormalizesStdlibVersion(t *testing.T) {
	tests := []struct {
		name        string
		ref         Ref
		wantVersion string
	}{
		{"module v prefix", goRef("golang.org/x/net", "v0.7.0"), "0.7.0"},
		{"stdlib go prefix", goRef("stdlib", "go1.24.0"), "1.24.0"},
		// A Debian version is an opaque string. Trimming a leading "v" or "go"
		// off one would silently query a version that does not exist.
		{"a deb version is left alone", Ref{Ecosystem: "Debian:12", Name: "golang-1.19", Version: "1.19.8-2"}, "1.19.8-2"},
		{"a deb version starting with v is left alone", Ref{Ecosystem: "Debian:12", Name: "vim", Version: "v2:9.0-1"}, "v2:9.0-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got queryRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&got)
				_, _ = w.Write([]byte(`{"vulns":[]}`))
			}))
			defer srv.Close()

			c := NewClient()
			c.BaseURL = srv.URL
			if _, err := c.Query(context.Background(), tt.ref); err != nil {
				t.Fatal(err)
			}
			if got.Version != tt.wantVersion {
				t.Errorf("version sent to OSV = %q, want %q", got.Version, tt.wantVersion)
			}
			if got.Package.Name != tt.ref.Name {
				t.Errorf("name sent to OSV = %q, want %q", got.Package.Name, tt.ref.Name)
			}
			if got.Package.Ecosystem != tt.ref.Ecosystem {
				t.Errorf("ecosystem sent to OSV = %q, want %q", got.Package.Ecosystem, tt.ref.Ecosystem)
			}
		})
	}
}

// ecosystem_specific.imports exists only in the Go database. Reading it for a
// Debian record would produce an empty Pkgs list that callers read as "OSV
// published no import paths for this Go module" -- a meaningful signal in Go,
// and a fabricated one everywhere else.
func TestImportsAreExtractedOnlyForGo(t *testing.T) {
	const body = `{"vulns":[{"id":"X","affected":[{"package":{"name":"openssl"},
		"ecosystem_specific":{"imports":[{"path":"should/not/be/read"}]}}]}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL

	deb, err := c.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := deb["X"].Pkgs; len(got) != 0 {
		t.Errorf("Debian advisory carried import paths %v", got)
	}

	// Same payload, Go ref: the field is read.
	gomod, err := c.Query(context.Background(), goRef("openssl", "v1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if got := gomod["X"].Pkgs; len(got) != 1 || got[0] != "should/not/be/read" {
		t.Errorf("Go advisory lost its import paths: %v", got)
	}
}

func TestQueryCarriesAdvisoryProse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[{"id":"DSA-1","summary":"openssl update","details":"a long story"}]}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL
	m, err := c.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "openssl"})
	if err != nil {
		t.Fatal(err)
	}
	if m["DSA-1"].Summary != "openssl update" || m["DSA-1"].Details != "a long story" {
		t.Errorf("advisory prose lost: %+v", m["DSA-1"])
	}
}

func TestFixedVersionIsExtractedForEveryEcosystem(t *testing.T) {
	// A distro record with one range and one fixed event -- the common shape.
	// The affected package name is the source name the join keys on.
	const body = `{"vulns":[{"id":"DEBIAN-CVE-2025-8941","aliases":["CVE-2025-8941"],
		"affected":[{"package":{"name":"pam","ecosystem":"Debian:12"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.5.2-6+deb12u2"}]}]}]}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL
	m, err := c.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "pam", Version: "1.5.2-6+deb12u1"})
	if err != nil {
		t.Fatal(err)
	}
	// Reachable under the id and under the CVE alias, since a finding may name
	// either.
	for _, key := range []string{"DEBIAN-CVE-2025-8941", "CVE-2025-8941"} {
		if got := m[key].Fixed["pam"]; got != "1.5.2-6+deb12u2" {
			t.Errorf("%s: Fixed[pam] = %q, want the patched version", key, got)
		}
	}
}

func TestLatestFixedEventWins(t *testing.T) {
	// Two ranges patch the same package at different versions. The later one is
	// the upgrade target for anything still on an older version.
	const body = `{"vulns":[{"id":"X","affected":[{"package":{"name":"zlib1g","ecosystem":"Debian:12"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.11"},
		{"introduced":"1.2.12"},{"fixed":"1.2.13"}]}]}]}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL
	m, err := c.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "zlib1g"})
	if err != nil {
		t.Fatal(err)
	}
	if got := m["X"].Fixed["zlib1g"]; got != "1.2.13" {
		t.Errorf("Fixed[zlib1g] = %q, want the latest fixed event 1.2.13", got)
	}
}

// A record carries an affected entry per release. A fixed version must be read
// only from the entry that names the release the query was for -- reading a
// sibling release's fix is how a bookworm scan ends up recommending a sid
// version bookworm never shipped.
func TestFixedVersionIsScopedToTheQueriedRelease(t *testing.T) {
	// zlib is fixed in Debian:13 but has no fix in Debian:12: the bookworm
	// entry carries only an "introduced" event.
	const body = `{"vulns":[{"id":"DEBIAN-CVE-2023-45853","affected":[
		{"package":{"name":"zlib","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
		{"package":{"name":"zlib","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.3.dfsg-2"}]}]}
	]}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL
	m, err := c.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "zlib", Version: "1:1.2.13.dfsg-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := m["DEBIAN-CVE-2023-45853"].Fixed["zlib"]; ok {
		t.Errorf("read a fix %q from a sibling release; bookworm has none", got)
	}
}

// A bad ecosystem name is a bug in our mapping table, and OSV says so in the
// response body. It must reach the caller on the first try rather than be
// retried into a bare "unexpected status 400".
func TestInvalidEcosystemIsNotRetried(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":3,"message":"invalid ecosystem"}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL
	_, err := c.Query(context.Background(), Ref{Ecosystem: "Debain:12", Name: "openssl"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Errorf("made %d attempts, want 1", attempts)
	}

	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not a *StatusError: %v", err)
	}
	if se.Retryable() {
		t.Error("a 400 must not be retryable")
	}
	if !strings.Contains(err.Error(), "invalid ecosystem") {
		t.Errorf("the message OSV sent was dropped: %v", err)
	}
}

func TestServerErrorIsRetried(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GO-1"}]}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.BaseURL = srv.URL
	m, err := c.Query(context.Background(), goRef("m", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Errorf("made %d attempts, want 3", attempts)
	}
	if m["GO-1"] == nil {
		t.Error("lost the advisory the retry recovered")
	}
}

func TestStatusErrorRetryable(t *testing.T) {
	for status, want := range map[int]bool{
		400: false, 403: false, 404: false,
		429: true, 500: true, 502: true, 503: true,
	} {
		if got := (&StatusError{Status: status}).Retryable(); got != want {
			t.Errorf("status %d: Retryable() = %v, want %v", status, got, want)
		}
	}
}

// batchServer answers /querybatch from a ref -> ids table and /vulns/{id} from
// an id -> record table, counting hits on each.
type batchServer struct {
	t *testing.T

	mu         sync.Mutex
	batchCalls int
	vulnCalls  map[string]int
	queries    []queryRequest
}

func newBatchServer(t *testing.T, ids map[string][]string, records map[string]string) (*Client, *batchServer) {
	t.Helper()
	rec := &batchServer{t: t, vulnCalls: map[string]int{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding querybatch: %v", err)
		}
		rec.mu.Lock()
		rec.batchCalls++
		rec.queries = append(rec.queries, req.Queries...)
		rec.mu.Unlock()

		var parts []string
		for _, q := range req.Queries {
			var vulns []string
			for _, id := range ids[q.Package.Ecosystem+"/"+q.Package.Name] {
				vulns = append(vulns, fmt.Sprintf(`{"id":%q,"modified":"2024-01-01T00:00:00Z"}`, id))
			}
			parts = append(parts, `{"vulns":[`+strings.Join(vulns, ",")+`]}`)
		}
		_, _ = w.Write([]byte(`{"results":[` + strings.Join(parts, ",") + `]}`))
	})
	mux.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/vulns/")
		rec.mu.Lock()
		rec.vulnCalls[id]++
		rec.mu.Unlock()

		body, ok := records[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{HTTP: srv.Client(), BaseURL: srv.URL}, rec
}

func TestQueryBatch(t *testing.T) {
	client, rec := newBatchServer(t,
		map[string][]string{
			"Debian:12/openssl": {"DSA-1", "DSA-2"},
			"Debian:12/curl":    {"DSA-2"},
			"Debian:12/zlib":    nil,
		},
		map[string]string{
			"DSA-1": `{"id":"DSA-1","aliases":["CVE-2024-0001"],"summary":"one"}`,
			"DSA-2": `{"id":"DSA-2","aliases":["CVE-2024-0002"],"summary":"two"}`,
		})

	refs := []Ref{
		{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"},
		{Ecosystem: "Debian:12", Name: "curl", Version: "7.88-1"},
		{Ecosystem: "Debian:12", Name: "zlib", Version: "1.2.13-1"},
	}
	got, err := client.QueryBatch(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != len(refs) {
		t.Fatalf("got %d result sets for %d refs", len(got), len(refs))
	}
	if rec.batchCalls != 1 {
		t.Errorf("made %d querybatch calls, want 1", rec.batchCalls)
	}
	// DSA-2 covers two packages. Hydrating it twice is exactly the cost
	// batching exists to avoid.
	if rec.vulnCalls["DSA-2"] != 1 {
		t.Errorf("fetched DSA-2 %d times, want 1", rec.vulnCalls["DSA-2"])
	}

	if got[0]["DSA-1"] == nil || got[0]["CVE-2024-0001"] == nil || got[0]["DSA-2"] == nil {
		t.Errorf("openssl advisories = %v", sortedKeys(got[0]))
	}
	if len(got[1]) != 2 || got[1]["CVE-2024-0002"] == nil {
		t.Errorf("curl advisories = %v", sortedKeys(got[1]))
	}
	if len(got[2]) != 0 {
		t.Errorf("zlib should have no advisories, got %v", sortedKeys(got[2]))
	}
	if got[0]["DSA-1"].Summary != "one" {
		t.Errorf("hydration lost the summary: %+v", got[0]["DSA-1"])
	}
}

func TestQueryBatchEmpty(t *testing.T) {
	client, rec := newBatchServer(t, nil, nil)
	got, err := client.QueryBatch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d results for no refs", len(got))
	}
	if rec.batchCalls != 0 {
		t.Errorf("queried the API with nothing to ask about")
	}
}

// A hydration failure fails the whole batch. Dropping the unreadable record
// and returning the rest would under-report advisories, and an advisory that
// is never seen can never be triaged.
func TestQueryBatchFailsWhenHydrationFails(t *testing.T) {
	client, _ := newBatchServer(t,
		map[string][]string{"Debian:12/openssl": {"DSA-1", "DSA-MISSING"}},
		map[string]string{"DSA-1": `{"id":"DSA-1"}`})

	_, err := client.QueryBatch(context.Background(),
		[]Ref{{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "DSA-MISSING") {
		t.Errorf("error does not name the record it could not fetch: %v", err)
	}
}

func TestQueryBatchChunksAtTheAPILimit(t *testing.T) {
	client, rec := newBatchServer(t, nil, nil)

	refs := make([]Ref, batchLimit+1)
	for i := range refs {
		refs[i] = Ref{Ecosystem: "Debian:12", Name: fmt.Sprintf("pkg%d", i)}
	}
	got, err := client.QueryBatch(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(refs) {
		t.Fatalf("got %d results for %d refs", len(got), len(refs))
	}
	if rec.batchCalls != 2 {
		t.Errorf("made %d querybatch calls for %d refs, want 2", rec.batchCalls, len(refs))
	}
	if len(rec.queries) != len(refs) {
		t.Errorf("sent %d queries for %d refs", len(rec.queries), len(refs))
	}
}

// The result must stay index-aligned with the input, or every advisory lands
// on the wrong package.
func TestQueryBatchResultsStayAlignedWithRefs(t *testing.T) {
	client, _ := newBatchServer(t,
		map[string][]string{"Debian:12/b": {"DSA-B"}},
		map[string]string{"DSA-B": `{"id":"DSA-B"}`})

	refs := []Ref{
		{Ecosystem: "Debian:12", Name: "a"},
		{Ecosystem: "Debian:12", Name: "b"},
		{Ecosystem: "Debian:12", Name: "c"},
	}
	got, err := client.QueryBatch(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{0, 1, 0} {
		if len(got[i]) != want {
			t.Errorf("refs[%d] (%s) got %d advisories, want %d", i, refs[i].Name, len(got[i]), want)
		}
	}
}

func TestRefString(t *testing.T) {
	cases := map[Ref]string{
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.7.0"}: "Go/golang.org/x/net@v0.7.0",
		{Ecosystem: "Debian:12", Name: "openssl"}:                      "Debian:12/openssl",
	}
	for ref, want := range cases {
		if got := ref.String(); got != want {
			t.Errorf("Ref.String() = %q, want %q", got, want)
		}
	}
}

func sortedKeys(m map[string]*Advisory) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
