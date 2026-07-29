package analyze

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
)

// llmServer stands in for the GitHub Models endpoint, recording the user
// message of every request so a test can assert what the overlay asked about.
type llmServer struct {
	srv *httptest.Server

	mu    sync.Mutex
	asked []string
}

func newLLMServer(t *testing.T, status int, verdict string) (*llm.Client, *llmServer) {
	t.Helper()
	rec := &llmServer{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		rec.mu.Lock()
		for _, m := range req.Messages {
			if m.Role == "user" {
				rec.asked = append(rec.asked, m.Content)
			}
		}
		rec.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":` + jsonQuote(verdict) + `}}]}`))
	}))
	t.Cleanup(rec.srv.Close)

	c, err := llm.NewClient("test-model", "test-token")
	if err != nil {
		t.Fatalf("llm.NewClient: %v", err)
	}
	c.Endpoint = rec.srv.URL
	c.MinInterval = 0
	return c, rec
}

// jsonQuote renders s as a JSON string literal.
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (r *llmServer) questions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.asked...)
}

const okVerdict = `{"exploitable":"likely","confidence":"high","rationale":"reachable over the network"}`

func TestLLMOverlayOnlyAsksAboutAffectedFindings(t *testing.T) {
	client, rec := newLLMServer(t, http.StatusOK, okVerdict)

	findings := []Finding{
		{CVE: "CVE-1", Module: "m", Binary: "/a", Status: StatusNotPresent},
		{CVE: "CVE-2", Module: "m", Binary: "/a", Status: StatusNotInPath},
		{CVE: "CVE-3", Module: "m", Binary: "/a", Status: StatusUndetermined},
		{CVE: "CVE-4", Module: "m", Binary: "/a", Status: StatusLinked, Reachability: "linked"},
		{CVE: "CVE-5", Module: "m", Status: StatusReachable, Reachability: "reachable"},
	}
	llmOverlay(context.Background(), client, findings, "source tree", func(string, ...any) {})

	for i, f := range findings {
		wantVerdict := f.Affected()
		if (f.LLM != nil) != wantVerdict {
			t.Errorf("findings[%d] (%s, %s): verdict attached = %v, want %v", i, f.CVE, f.Status, f.LLM != nil, wantVerdict)
		}
	}
	if got := len(rec.questions()); got != 2 {
		t.Errorf("asked the model %d times, want 2", got)
	}
}

func TestLLMOverlayNamesTheSourceTreeWhenThereIsNoBinary(t *testing.T) {
	client, rec := newLLMServer(t, http.StatusOK, okVerdict)

	findings := []Finding{
		{CVE: "CVE-1", Module: "m", Version: "v1", Binary: "/usr/bin/app", Status: StatusLinked, Reachability: "linked"},
		{CVE: "CVE-2", Module: "m", Version: "v1", Status: StatusReachable, Reachability: "reachable"},
	}
	llmOverlay(context.Background(), client, findings, "source tree", func(string, ...any) {})

	asked := rec.questions()
	if len(asked) != 2 {
		t.Fatalf("asked %d questions, want 2", len(asked))
	}
	if !strings.Contains(asked[0], "Binary: /usr/bin/app") {
		t.Errorf("image finding should name its binary, got:\n%s", asked[0])
	}
	// A repo-mode finding has no artifact; the prompt must still say what was
	// analyzed rather than leave the field blank.
	if !strings.Contains(asked[1], "Binary: source tree") {
		t.Errorf("repo finding should name the source tree, got:\n%s", asked[1])
	}
}

// A failed assessment must not take the deterministic finding down with it:
// the whole point is that the model is optional.
func TestLLMOverlayKeepsFindingsWhenTheModelFails(t *testing.T) {
	client, _ := newLLMServer(t, http.StatusBadRequest, "")

	var logged int
	findings := []Finding{{CVE: "CVE-1", Module: "m", Status: StatusLinked, Reachability: "linked"}}
	llmOverlay(context.Background(), client, findings, "", func(string, ...any) { logged++ })

	if findings[0].Status != StatusLinked {
		t.Errorf("status changed to %s", findings[0].Status)
	}
	if findings[0].LLM != nil {
		t.Error("a failed assessment must not attach a verdict")
	}
	if logged == 0 {
		t.Error("a failed assessment should be reported to the log")
	}
}

func TestLLMOverlayWithoutAClientIsANoop(t *testing.T) {
	findings := []Finding{{CVE: "CVE-1", Status: StatusLinked}}
	llmOverlay(context.Background(), nil, findings, "", func(string, ...any) {})
	if findings[0].LLM != nil {
		t.Error("no client means no verdict")
	}
}

func TestSortFindings(t *testing.T) {
	findings := []Finding{
		{Binary: "/usr/bin/b", CVE: "CVE-1"},
		{Binary: "/usr/bin/a", CVE: "CVE-2"},
		{Binary: "/usr/bin/a", CVE: "CVE-1"},
	}
	sortFindings(findings)

	want := []string{"/usr/bin/a CVE-1", "/usr/bin/a CVE-2", "/usr/bin/b CVE-1"}
	var got []string
	for _, f := range findings {
		got = append(got, f.Binary+" "+f.CVE)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Repo-mode findings carry no binary, so the shared comparator has to fall
// through to the advisory id — the order repo mode has always emitted.
func TestSortFindingsWithoutBinaries(t *testing.T) {
	findings := []Finding{{CVE: "CVE-3"}, {CVE: "CVE-1"}, {CVE: "CVE-2"}}
	sortFindings(findings)
	for i, want := range []string{"CVE-1", "CVE-2", "CVE-3"} {
		if findings[i].CVE != want {
			t.Errorf("findings[%d] = %s, want %s", i, findings[i].CVE, want)
		}
	}
}

// osvFake serves the three endpoints the OSV client uses -- /query,
// /querybatch and /vulns/{id} -- so a test can assert which names were asked
// about and how many round trips it took.
type osvFake struct {
	client *osv.Client

	// vulns maps "<ecosystem>/<name>" to the advisory ids that match it.
	vulns map[string][]string
	// aliases maps an advisory id to the other ids it is known by.
	aliases map[string][]string
	// failBatch makes /querybatch answer 500, to exercise the fallback.
	failBatch bool

	mu      sync.Mutex
	asked   []string // "<ecosystem>/<name>@<version>", in request order
	batches int
	singles int
}

func newOSVFake(t *testing.T, f *osvFake) *osvFake {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	f.client = &osv.Client{HTTP: srv.Client(), BaseURL: srv.URL}
	return f
}

type fakeQuery struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

func (q fakeQuery) key() string  { return q.Package.Ecosystem + "/" + q.Package.Name }
func (q fakeQuery) full() string { return q.key() + "@" + q.Version }

func (f *osvFake) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/querybatch"):
		if f.failBatch {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req struct {
			Queries []fakeQuery `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		f.mu.Lock()
		f.batches++
		results := make([]string, 0, len(req.Queries))
		for _, q := range req.Queries {
			f.asked = append(f.asked, q.full())
			var ids []string
			for _, id := range f.vulns[q.key()] {
				ids = append(ids, `{"id":`+jsonQuote(id)+`}`)
			}
			results = append(results, `{"vulns":[`+strings.Join(ids, ",")+`]}`)
		}
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"results":[` + strings.Join(results, ",") + `]}`))

	case strings.HasSuffix(r.URL.Path, "/query"):
		var q fakeQuery
		_ = json.NewDecoder(r.Body).Decode(&q)

		f.mu.Lock()
		f.singles++
		f.asked = append(f.asked, q.full())
		var recs []string
		for _, id := range f.vulns[q.key()] {
			recs = append(recs, f.record(id))
		}
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"vulns":[` + strings.Join(recs, ",") + `]}`))

	default: // /vulns/{id}
		f.mu.Lock()
		rec := f.record(path.Base(r.URL.Path))
		f.mu.Unlock()
		_, _ = w.Write([]byte(rec))
	}
}

func (f *osvFake) record(id string) string {
	b, _ := json.Marshal(map[string]any{
		"id":      id,
		"aliases": f.aliases[id],
		"summary": id + " summary",
	})
	return string(b)
}

func (f *osvFake) questions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

func TestResolverQueriesEachComponentOnce(t *testing.T) {
	f := newOSVFake(t, &osvFake{
		vulns:   map[string][]string{"Go/golang.org/x/net": {"GO-2023-2102"}},
		aliases: map[string][]string{"GO-2023-2102": {"CVE-2023-39325"}},
	})
	r := &advisoryResolver{client: f.client, cache: map[string]map[string]*osv.Advisory{}}

	// Two components sharing a key: the same module version linked into two
	// different binaries must not cost two lookups.
	components := []ecosystem.Component{
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0", Locations: []string{"/usr/bin/a"}},
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0", Locations: []string{"/usr/bin/b"}},
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.18.0"},
	}
	items := r.workItems(context.Background(), components, []string{"CVE-2023-39325"}, func(string, ...any) {})

	if len(items) != 3 {
		t.Fatalf("got %d work items, want 3", len(items))
	}
	// The client strips the Go "v" prefix on the way out; OSV wants it bare.
	want := []string{"Go/golang.org/x/net@0.17.0", "Go/golang.org/x/net@0.18.0"}
	if got := f.questions(); !reflect.DeepEqual(got, want) {
		t.Errorf("asked OSV about %v, want %v", got, want)
	}
	if f.batches != 1 || f.singles != 0 {
		t.Errorf("made %d batch and %d single queries, want 1 and 0", f.batches, f.singles)
	}
	for i, it := range items {
		if it.Advisories["CVE-2023-39325"] == nil {
			t.Errorf("items[%d] lost its advisory", i)
		}
		if !reflect.DeepEqual(it.Requested, []string{"CVE-2023-39325"}) {
			t.Errorf("items[%d] requested = %v", i, it.Requested)
		}
	}
}

// Which name a distribution files advisories under is not consistent, so a
// component may carry several. Missing the one that matches reports a
// vulnerable package as clean.
func TestResolverQueriesEveryNameAComponentIsKnownBy(t *testing.T) {
	f := newOSVFake(t, &osvFake{
		// Only the source name carries the advisory, as on Debian.
		vulns:   map[string][]string{"Debian:12/openssl": {"DSA-5417-1"}},
		aliases: map[string][]string{"DSA-5417-1": {"CVE-2023-0464"}},
	})
	r := &advisoryResolver{client: f.client, cache: map[string]map[string]*osv.Advisory{}}

	items := r.workItems(context.Background(), []ecosystem.Component{
		{Ecosystem: "Debian:12", Name: "libssl3", AltNames: []string{"openssl"}, Version: "3.0.11-1"},
	}, nil, func(string, ...any) {})

	want := []string{"Debian:12/libssl3@3.0.11-1", "Debian:12/openssl@3.0.11-1"}
	if got := f.questions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("asked OSV about %v, want %v", got, want)
	}
	if items[0].Advisories["CVE-2023-0464"] == nil {
		t.Error("the advisory filed under the source name was lost")
	}
}

// An advisory filed under both of a component's names is still one advisory.
func TestResolverMergesAdvisoriesAcrossNames(t *testing.T) {
	f := newOSVFake(t, &osvFake{
		vulns: map[string][]string{
			"Red Hat/openssl":      {"RHSA-2023:1234"},
			"Red Hat/openssl-libs": {"RHSA-2023:1234"},
		},
		aliases: map[string][]string{"RHSA-2023:1234": {"CVE-2023-0464"}},
	})
	r := &advisoryResolver{client: f.client, cache: map[string]map[string]*osv.Advisory{}}

	items := r.workItems(context.Background(), []ecosystem.Component{
		{Ecosystem: "Red Hat", Name: "openssl-libs", AltNames: []string{"openssl"}, Version: "1:3.0.7-24.el9"},
	}, nil, func(string, ...any) {})

	// Keyed by id and by alias, so two keys for one advisory -- but only one
	// distinct record behind them.
	seen := map[*osv.Advisory]bool{}
	for _, adv := range items[0].Advisories {
		seen[adv] = true
	}
	if len(seen) != 1 {
		t.Errorf("got %d distinct advisories, want 1", len(seen))
	}
}

// A batch failure must cost the run its speed, not its advisories.
func TestResolverFallsBackWhenTheBatchFails(t *testing.T) {
	f := newOSVFake(t, &osvFake{
		failBatch: true,
		vulns:     map[string][]string{"Debian:12/openssl": {"DSA-5417-1"}},
		aliases:   map[string][]string{"DSA-5417-1": {"CVE-2023-0464"}},
	})
	r := &advisoryResolver{client: f.client, cache: map[string]map[string]*osv.Advisory{}}

	var logged int
	items := r.workItems(context.Background(), []ecosystem.Component{
		{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"},
		{Ecosystem: "Debian:12", Name: "zlib", Version: "1:1.2.13"},
	}, nil, func(string, ...any) { logged++ })

	if items[0].Advisories["CVE-2023-0464"] == nil {
		t.Error("the fallback lost the advisory")
	}
	if f.singles != 2 {
		t.Errorf("made %d per-component queries, want 2", f.singles)
	}
	if logged == 0 {
		t.Error("abandoning the batch should be reported to the log")
	}
}

// A lookup failure yields an empty advisory set rather than an error, which is
// what lets an explicitly requested id still report as undetermined instead of
// aborting the run.
func TestResolverSurvivesOSVFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	r := &advisoryResolver{
		client: &osv.Client{HTTP: srv.Client(), BaseURL: srv.URL},
		cache:  map[string]map[string]*osv.Advisory{},
	}

	var logged int
	items := r.workItems(context.Background(),
		[]ecosystem.Component{{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"}},
		[]string{"CVE-2023-39325"},
		func(string, ...any) { logged++ })

	if len(items) != 1 {
		t.Fatalf("got %d work items, want 1", len(items))
	}
	if items[0].Advisories == nil {
		t.Error("a failed lookup must yield an empty map, not a nil one")
	}
	if len(items[0].Advisories) != 0 {
		t.Errorf("got %d advisories from a failing server", len(items[0].Advisories))
	}
	if logged == 0 {
		t.Error("a failed lookup should be reported to the log")
	}
}

// The resolver passes a component's own ecosystem through to OSV rather than
// assuming Go, and leaves a non-Go version unrewritten on the way.
func TestResolverQueriesEachComponentsOwnEcosystem(t *testing.T) {
	f := newOSVFake(t, &osvFake{})
	r := &advisoryResolver{client: f.client, cache: map[string]map[string]*osv.Advisory{}}
	r.workItems(context.Background(),
		[]ecosystem.Component{{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"}},
		nil,
		func(string, ...any) {})

	want := []string{"Debian:12/openssl@3.0.11-1"}
	if got := f.questions(); !reflect.DeepEqual(got, want) {
		t.Errorf("queried %v, want %v", got, want)
	}
}

// A component with no ecosystem cannot be queried at all. That must be
// reported, not answered with a silent empty advisory set that reads as clean.
func TestResolverReportsComponentsWithNoEcosystem(t *testing.T) {
	f := newOSVFake(t, &osvFake{})
	r := &advisoryResolver{client: f.client, cache: map[string]map[string]*osv.Advisory{}}

	var logged int
	items := r.workItems(context.Background(),
		[]ecosystem.Component{{Name: "openssl", Version: "3.0.11-1"}},
		nil,
		func(string, ...any) { logged++ })

	if got := f.questions(); len(got) != 0 {
		t.Errorf("queried OSV with no ecosystem: %v", got)
	}
	if len(items[0].Advisories) != 0 {
		t.Error("expected no advisories")
	}
	if logged == 0 {
		t.Error("skipping a component should be reported to the log")
	}
}

func TestSubjectsFor(t *testing.T) {
	got := subjectsFor(Options{Module: "golang.org/x/net"})
	want := []ecosystem.Subject{{Name: "golang.org/x/net", Raw: "golang.org/x/net"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestRegistryCapabilities(t *testing.T) {
	plugins := registryFor(Options{}).All()

	ids := func(list []string) string { return strings.Join(list, ",") }
	var image, source []string
	for _, p := range ecosystem.ImageAnalyzers(plugins) {
		image = append(image, p.ID())
	}
	for _, p := range ecosystem.SourceAnalyzers(plugins) {
		source = append(source, p.ID())
	}

	// Go analyzes from either end. OS packages only exist in an image: there
	// is no source checkout of "the distribution's openssl".
	if ids(image) != "golang,os" {
		t.Errorf("image analyzers = %s, want golang,os", ids(image))
	}
	if ids(source) != "golang" {
		t.Errorf("source analyzers = %s, want golang", ids(source))
	}
}
