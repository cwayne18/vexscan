package analyze

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

// osvServer returns a fixed advisory list and counts how often it is called.
func osvServer(t *testing.T) (*osv.Client, *int) {
	t.Helper()
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GO-2023-2102","aliases":["CVE-2023-39325"],
			"affected":[{"package":{"name":"golang.org/x/net"},
			"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/http2"}]}}]}]}`))
	}))
	t.Cleanup(srv.Close)
	return &osv.Client{HTTP: srv.Client(), URL: srv.URL}, &calls
}

func TestResolverQueriesEachComponentOnce(t *testing.T) {
	client, calls := osvServer(t)
	r := &advisoryResolver{client: client, cache: map[string]map[string]*osv.Advisory{}}

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
	if *calls != 2 {
		t.Errorf("made %d OSV queries, want 2", *calls)
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

// A lookup failure yields an empty advisory set rather than an error, which is
// what lets an explicitly requested id still report as undetermined instead of
// aborting the run.
func TestResolverSurvivesOSVFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	r := &advisoryResolver{
		client: &osv.Client{HTTP: srv.Client(), URL: srv.URL},
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

// Until internal/osv speaks other databases, a non-Go component must produce a
// logged empty advisory set rather than a Go-database query under a wrong name.
func TestResolverDoesNotQueryNonGoEcosystems(t *testing.T) {
	client, calls := osvServer(t)
	r := &advisoryResolver{client: client, cache: map[string]map[string]*osv.Advisory{}}

	var logged int
	items := r.workItems(context.Background(),
		[]ecosystem.Component{{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"}},
		nil,
		func(string, ...any) { logged++ })

	if *calls != 0 {
		t.Errorf("queried the Go database for a Debian component (%d calls)", *calls)
	}
	if len(items[0].Advisories) != 0 {
		t.Error("expected no advisories")
	}
	if logged == 0 {
		t.Error("skipping an ecosystem should be reported to the log")
	}
}

func TestSubjectsFor(t *testing.T) {
	got := subjectsFor(Options{Module: "golang.org/x/net"})
	want := []ecosystem.Subject{{Name: "golang.org/x/net", Raw: "golang.org/x/net"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestRegistryHasBothGoCapabilities(t *testing.T) {
	plugins := registryFor(Options{}).All()
	if len(ecosystem.ImageAnalyzers(plugins)) != 1 {
		t.Error("the Go plugin must be an image analyzer")
	}
	if len(ecosystem.SourceAnalyzers(plugins)) != 1 {
		t.Error("the Go plugin must be a source analyzer")
	}
}
