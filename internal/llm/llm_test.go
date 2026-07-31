package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(endpoint string) *Client {
	return NewClientWithTransport(&HTTPTransport{
		HTTP:     &http.Client{Timeout: 5 * time.Second},
		Endpoint: endpoint,
		Model:    "test",
		Token:    "test",
	})
}

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"plain", `{"exploitable":"likely","confidence":"high","rationale":"reachable parser"}`, "likely"},
		{"fenced", "```json\n{\"exploitable\":\"unlikely\",\"confidence\":\"medium\",\"rationale\":\"x\"}\n```", "unlikely"},
		{"prose_wrapped", "Here is my answer:\n{\"exploitable\":\"unknown\",\"confidence\":\"low\",\"rationale\":\"y\"}\nThanks", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseVerdict(tc.content)
			if err != nil {
				t.Fatal(err)
			}
			if v.Exploitable != tc.want {
				t.Errorf("got %q, want %q", v.Exploitable, tc.want)
			}
		})
	}
}

func TestParseVerdictNonJSON(t *testing.T) {
	v, err := parseVerdict("I cannot determine this.")
	if err != nil {
		t.Fatal(err)
	}
	if v.Exploitable != "unknown" {
		t.Errorf("expected unknown fallback, got %q", v.Exploitable)
	}
}

// TestAssessNonJSONError verifies a non-JSON error body (the case behind
// "invalid character 'T'...") surfaces as a legible status-based error rather
// than an opaque JSON parse failure.
func TestAssessNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("The request was malformed."))
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Assess(context.Background(), Request{CVE: "CVE-x"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got == "" ||
		!containsAll(got, "llm endpoint", "400", "malformed") {
		t.Fatalf("unhelpful error: %q", got)
	}
}

// TestAssessRetryThenSuccess verifies transient 429s are retried and a later
// 200 succeeds.
func TestAssessRetryThenSuccess(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too Many Requests"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"exploitable\":\"likely\",\"confidence\":\"high\",\"rationale\":\"ok\"}"}}]}`))
	}))
	defer srv.Close()

	v, err := testClient(srv.URL).Assess(context.Background(), Request{CVE: "CVE-x"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Exploitable != "likely" {
		t.Errorf("got %q, want likely", v.Exploitable)
	}
	if calls < 2 {
		t.Errorf("expected a retry, saw %d call(s)", calls)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// TestAssessCachesVerdict verifies that a second identical request (differing
// only by binary name) is served from cache without a second API call.
func TestAssessCachesVerdict(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"exploitable\":\"likely\",\"confidence\":\"high\",\"rationale\":\"ok\"}"}}]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL)
	base := Request{CVE: "CVE-1", Module: "golang.org/x/net", Version: "v0.7.0", Reachable: "linked"}
	if _, err := c.Assess(context.Background(), Request{CVE: base.CVE, Module: base.Module, Version: base.Version, Reachable: base.Reachable, Binary: "bin-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Assess(context.Background(), Request{CVE: base.CVE, Module: base.Module, Version: base.Version, Reachable: base.Reachable, Binary: "bin-b"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("expected 1 API call (second served from cache), got %d", calls)
	}
}

// The Go prompt and the Go user message are load-bearing history: every verdict
// the tool has produced was produced by them, so a new ecosystem must not be
// able to reach them and an old caller must not be able to miss them.
func TestGoPromptIsUnreachableFromAnotherEcosystem(t *testing.T) {
	if promptFor("") != goPrompt || promptFor("golang") != goPrompt {
		t.Error("the Go prompt is not what an unset or Go ecosystem gets")
	}
	if promptFor("os") == goPrompt {
		t.Error("an OS package gets the Go prompt")
	}
	if !strings.Contains(promptFor("os"), "container image") {
		t.Error("the OS prompt does not say what it is looking at")
	}

	r := Request{CVE: "CVE-1", Module: "golang.org/x/net", Version: "v0.7.0",
		Packages: []string{"http2"}, Binary: "/app", Reachable: "linked"}
	want := "CVE: CVE-1\nModule: golang.org/x/net@v0.7.0\nVulnerable packages: http2\n" +
		"Binary: /app\nStatic analysis says the vulnerable code is: linked\nAssess exploitability."
	if got := userMessage(r); got != want {
		t.Errorf("the Go user message changed:\ngot  %q\nwant %q", got, want)
	}
}

// "Module" and "Binary" are the wrong nouns for a package installed into an
// image, and a prompt that uses the wrong noun invites an answer about the
// wrong thing.
func TestOSMessageNamesAPackageAndAnImage(t *testing.T) {
	got := userMessage(Request{Ecosystem: "os", CVE: "CVE-1", Module: "openssl",
		Version: "3.0.11-1", Binary: "debian:12", Reachable: "loaded"})
	for _, want := range []string{"Package: openssl 3.0.11-1", "Image: debian:12", "loaded"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "Module:") {
		t.Errorf("message calls an OS package a module: %q", got)
	}
}

// A Python distribution is neither a Go module nor an OS package, and the
// prompt has to say what makes it different: nothing was eliminated at build
// time, so being imported says nothing about what runs.
func TestPyPIPromptAndMessage(t *testing.T) {
	if promptFor("pypi") == goPrompt || promptFor("pypi") == osPrompt {
		t.Error("a Python distribution gets another ecosystem's prompt")
	}
	if !strings.Contains(promptFor("pypi"), "removes no dead code") {
		t.Error("the PyPI prompt does not say how weak the evidence behind it is")
	}

	got := userMessage(Request{Ecosystem: "pypi", CVE: "CVE-1", Module: "pyyaml",
		Version: "6.0.1", Binary: "python:3.12-slim", Reachable: "imported"})
	for _, want := range []string{"Distribution: pyyaml 6.0.1", "Image: python:3.12-slim", "imported"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "Module:") {
		t.Errorf("message calls a Python distribution a module: %q", got)
	}
}

// npm's distinguishing fact is the depth of the tree: a package five levels
// down is installed because something needed something that needed it, and the
// prompt has to say that being installed and required is not being called.
func TestNPMPromptAndMessage(t *testing.T) {
	for _, other := range []string{"golang", "os", "pypi"} {
		if promptFor("npm") == promptFor(other) {
			t.Errorf("an npm package gets the %s prompt", other)
		}
	}
	if !strings.Contains(promptFor("npm"), "removes no dead code") {
		t.Error("the npm prompt does not say how weak the evidence behind it is")
	}

	got := userMessage(Request{Ecosystem: "npm", CVE: "CVE-1", Module: "lodash",
		Version: "4.17.20", Binary: "node:22-slim", Reachable: "required"})
	for _, want := range []string{"Package: lodash 4.17.20", "Image: node:22-slim", "required"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "Module:") {
		t.Errorf("message calls an npm package a module: %q", got)
	}
}

// The same CVE against a Go module and against an OS package of the same name
// are different questions, so one must not serve the other's cached answer.
func TestCacheKeySeparatesEcosystems(t *testing.T) {
	base := Request{CVE: "CVE-1", Module: "openssl", Version: "3.0", Reachable: "linked"}
	goKey, osKey := cacheKey(base), cacheKey(Request{Ecosystem: "os", CVE: base.CVE,
		Module: base.Module, Version: base.Version, Reachable: base.Reachable})
	if goKey == osKey {
		t.Errorf("both ecosystems share the cache key %q", goKey)
	}
}

// TestRetryAfterHonorsLongDelay verifies a Retry-After larger than the old 30s
// cap is honored (up to maxRetryWait) rather than silently clamped.
func TestRetryAfterHonorsLongDelay(t *testing.T) {
	res := &http.Response{Header: http.Header{}}
	res.Header.Set("Retry-After", "75")
	if got := retryAfter(res); got != 75*time.Second {
		t.Errorf("retryAfter = %v, want 75s", got)
	}
}
