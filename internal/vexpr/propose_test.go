package vexpr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// fakeHub is a minimal in-memory GitHub API standing in for a VEX hub, enough to
// drive Propose and Submit through their real HTTP client.
type fakeHub struct {
	files      map[string]string // path -> content, at the base commit
	createdRef string
	prHead     string
	prBase     string
	prTitle    string
	committed  []string // paths written into the commit tree
}

func (h *fakeHub) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/user":
			writeJSON(w, map[string]any{"login": "octo"})
		case strings.HasSuffix(p, "/git/ref/heads/main"):
			writeJSON(w, map[string]any{"object": map[string]any{"sha": "basesha"}})
		case strings.Contains(p, "/git/commits/"):
			writeJSON(w, map[string]any{"tree": map[string]any{"sha": "basetree"}})
		case strings.HasSuffix(p, "/git/trees") && r.Method == http.MethodPost:
			var body struct {
				Tree []struct {
					Path string `json:"path"`
				} `json:"tree"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			for _, e := range body.Tree {
				h.committed = append(h.committed, e.Path)
			}
			writeJSON(w, map[string]any{"sha": "newtree"})
		case strings.HasSuffix(p, "/git/commits") && r.Method == http.MethodPost:
			writeJSON(w, map[string]any{"sha": "newcommit"})
		case strings.HasSuffix(p, "/git/refs") && r.Method == http.MethodPost:
			var body struct {
				Ref string `json:"ref"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			h.createdRef = body.Ref
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]any{"ref": body.Ref})
		case strings.HasSuffix(p, "/pulls") && r.Method == http.MethodPost:
			var body struct{ Head, Base, Title string }
			json.NewDecoder(r.Body).Decode(&body)
			h.prHead, h.prBase, h.prTitle = body.Head, body.Base, body.Title
			writeJSON(w, map[string]any{"html_url": "https://github.com/acme/hub/pull/7"})
		case strings.Contains(p, "/contents/"):
			file := p[strings.Index(p, "/contents/")+len("/contents/"):]
			content, ok := h.files[file]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				writeJSON(w, map[string]any{"message": "Not Found"})
				return
			}
			writeJSON(w, map[string]any{
				"content":  base64.StdEncoding.EncodeToString([]byte(content)),
				"encoding": "base64",
			})
		case strings.HasSuffix(p, "/acme/hub") || strings.HasSuffix(p, "/acme/hub/"):
			writeJSON(w, map[string]any{"default_branch": "main"})
		default:
			t.Logf("unhandled %s %s", r.Method, p)
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"message": "unhandled: " + p})
		}
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func TestProposeAndSubmit(t *testing.T) {
	hub := &fakeHub{files: map[string]string{
		"index.json": `{"version":1,"packages":[
			{"id":"pkg:oci/synthetic?repository_url=index.docker.io%2Fexample%2Fsynthetic","location":"pkg/oci/index.docker.io/example/synthetic/scan.openvex.json"}
		]}`,
		"pkg/oci/index.docker.io/example/synthetic/scan.openvex.json": `{
			"@context":"https://openvex.dev/ns/v0.2.0","author":"Prev","version":1,
			"timestamp":"2026-01-01T00:00:00Z","statements":[
				{"vulnerability":{"name":"CVE-OLD"},
				 "products":[{"@id":"pkg:oci/synthetic?repository_url=index.docker.io/example/synthetic",
				   "subcomponents":[{"@id":"pkg:deb/debian/old@1"}]}],
				 "status":"not_affected"}
			]}`,
	}}
	srv := httptest.NewServer(hub.handler(t))
	defer srv.Close()

	res := &analyze.Result{
		Target: "example/synthetic:latest",
		Findings: []analyze.Finding{
			{ID: "CVE-NEW", CVE: "CVE-NEW", Product: testProduct, PURL: "pkg:deb/debian/new@2",
				Status: analyze.StatusNotPresent, Justification: "component_not_present", Method: "pkgdb"},
			// Already in the hub's document -> must be merged out.
			{ID: "CVE-OLD", CVE: "CVE-OLD", Product: testProduct, PURL: "pkg:deb/debian/old@1",
				Status: analyze.StatusNotInPath, Justification: "vulnerable_code_not_in_execute_path"},
		},
	}

	plan, err := Propose(context.Background(), res, Options{
		HubURL:    "https://github.com/acme/hub",
		Token:     "t",
		Version:   "v-test",
		Timestamp: testTime,
		apiBase:   srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() {
		t.Fatal("plan is empty; expected the new CVE to be proposed")
	}
	if plan.Statements != 1 {
		t.Fatalf("statements = %d, want 1 (CVE-OLD deduped away)", plan.Statements)
	}
	// Only the product document changes; index.json is untouched (existing product).
	if len(plan.Changes) != 1 {
		t.Fatalf("changes = %d, want 1: %+v", len(plan.Changes), plan.Changes)
	}
	if !strings.Contains(string(plan.Changes[0].Content), "CVE-NEW") {
		t.Errorf("document does not contain the new CVE:\n%s", plan.Changes[0].Content)
	}
	if !strings.Contains(string(plan.Changes[0].Content), "CVE-OLD") {
		t.Errorf("merge dropped the pre-existing statement:\n%s", plan.Changes[0].Content)
	}

	url, err := plan.Submit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://github.com/acme/hub/pull/7" {
		t.Errorf("pr url = %q", url)
	}
	if hub.createdRef != "refs/heads/"+plan.Branch {
		t.Errorf("created ref = %q, want the plan branch %q", hub.createdRef, plan.Branch)
	}
	if hub.prHead != plan.Branch || hub.prBase != "main" {
		t.Errorf("PR head/base = %q/%q, want %q/main", hub.prHead, hub.prBase, plan.Branch)
	}
	if len(hub.committed) != 1 {
		t.Errorf("committed files = %v, want the single product document", hub.committed)
	}
}

func TestProposeEmptyWhenNothingRuledOut(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{
		{ID: "CVE-1", CVE: "CVE-1", Product: testProduct, PURL: "pkg:deb/debian/a@1", Status: analyze.StatusLinked},
	}}
	plan, err := Propose(context.Background(), res, Options{HubURL: "https://github.com/acme/hub", Token: "t", Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Empty() {
		t.Fatalf("plan not empty: %+v", plan)
	}
}

func TestParseGitHubRepo(t *testing.T) {
	cases := map[string][2]string{
		"https://github.com/rancher/vexhub":                      {"rancher", "vexhub"},
		"https://github.com/rancher/vexhub.git":                  {"rancher", "vexhub"},
		"https://raw.githubusercontent.com/rancher/vexhub/HEAD/": {"rancher", "vexhub"},
	}
	for in, want := range cases {
		o, r, err := parseGitHubRepo(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if o != want[0] || r != want[1] {
			t.Errorf("%s -> %s/%s, want %s/%s", in, o, r, want[0], want[1])
		}
	}
	for _, bad := range []string{"", "/some/local/dir", "https://example.com/x/y"} {
		if _, _, err := parseGitHubRepo(bad); err == nil {
			t.Errorf("parseGitHubRepo(%q) = nil error, want error", bad)
		}
	}
}
