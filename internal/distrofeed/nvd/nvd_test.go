package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// cveResponse builds a minimal CVE API response body for one CVE carrying the
// given cvssMetricV31/V40 vector strings and base scores. An empty slice means
// the metrics field for that version is simply absent, matching how NVD omits
// a version it never scored.
func cveResponse(v31, v40 []metricFixture) string {
	body := `{"totalResults":1,"vulnerabilities":[{"cve":{"metrics":{`
	parts := []string{}
	if len(v40) > 0 {
		parts = append(parts, `"cvssMetricV40":`+metricsJSON(v40))
	}
	if len(v31) > 0 {
		parts = append(parts, `"cvssMetricV31":`+metricsJSON(v31))
	}
	for i, p := range parts {
		if i > 0 {
			body += ","
		}
		body += p
	}
	body += `}}}]}`
	return body
}

type metricFixture struct {
	vector string
	score  float64
}

func metricsJSON(entries []metricFixture) string {
	out := "["
	for i, e := range entries {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"cvssData":{"vectorString":%q,"baseScore":%v}}`, e.vector, e.score)
	}
	return out + "]"
}

const emptyResponse = `{"totalResults":0,"vulnerabilities":[]}`

// serve starts an httptest.Server answering the CVE API for the given CVEs,
// counting every request it receives.
func serve(t *testing.T, bodies map[string]string, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		cve := r.URL.Query().Get("cveId")
		body, ok := bodies[cve]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testProvider(baseURL string) *Provider {
	return &Provider{
		HTTP:        http.DefaultClient,
		BaseURL:     baseURL,
		MinInterval: 0,
	}
}

func TestNameIsNVD(t *testing.T) {
	if got := (&Provider{}).Name(); got != "NVD" {
		t.Fatalf("Name() = %q, want %q", got, "NVD")
	}
}

func TestScoresPicksHighestAcrossVersions(t *testing.T) {
	var hits int32
	srv := serve(t, map[string]string{
		"CVE-2026-78660": cveResponse(
			[]metricFixture{{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5}},
			[]metricFixture{{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1}},
		),
	}, &hits)
	p := testProvider(srv.URL)
	out, err := p.Scores(context.Background(), []string{"CVE-2026-78660"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	want := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
	if out["CVE-2026-78660"] != want {
		t.Fatalf("got %q, want %q (the higher-scoring v3.1 entry)", out["CVE-2026-78660"], want)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestScoresPrefersV40WhenItScoresHigher(t *testing.T) {
	var hits int32
	srv := serve(t, map[string]string{
		"CVE-2026-00001": cveResponse(
			[]metricFixture{{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3}},
			[]metricFixture{{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3}},
		),
	}, &hits)
	p := testProvider(srv.URL)
	out, err := p.Scores(context.Background(), []string{"CVE-2026-00001"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	want := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	if out["CVE-2026-00001"] != want {
		t.Fatalf("got %q, want %q (the higher-scoring v4.0 entry)", out["CVE-2026-00001"], want)
	}
}

func TestScoresSkipsNonCVEIds(t *testing.T) {
	var hits int32
	srv := serve(t, map[string]string{}, &hits)
	p := testProvider(srv.URL)
	out, err := p.Scores(context.Background(), []string{"GHSA-xxxx-yyyy-zzzz", "GO-2026-6610", "not-a-cve"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("out = %v, want empty", out)
	}
	if hits != 0 {
		t.Fatalf("hits = %d, want 0: non-CVE ids must never be looked up", hits)
	}
}

func TestScoresTreatsNoRecordAsAbsentNotError(t *testing.T) {
	var hits int32
	srv := serve(t, map[string]string{
		"CVE-2026-11111": emptyResponse, // 200, totalResults:0
		// CVE-2026-22222 is simply absent from bodies, so serve answers 404.
	}, &hits)
	p := testProvider(srv.URL)
	out, err := p.Scores(context.Background(), []string{"CVE-2026-11111", "CVE-2026-22222"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("out = %v, want empty: no record is a decline, not a score", out)
	}
}

func TestScoresRetriesOnRateLimit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cveResponse([]metricFixture{{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5}}, nil)))
	}))
	defer srv.Close()
	p := testProvider(srv.URL)
	p.RetryBackoff = time.Millisecond
	out, err := p.Scores(context.Background(), []string{"CVE-2026-33333"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2 (one rate-limited, one retry)", hits)
	}
	if out["CVE-2026-33333"] == "" {
		t.Fatalf("out = %v, want a vector after the retry succeeded", out)
	}
}

func TestScoresGivesUpAfterMaxAttempts(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	p := testProvider(srv.URL)
	p.MaxAttempts = 2
	p.RetryBackoff = time.Millisecond
	_, err := p.Scores(context.Background(), []string{"CVE-2026-44444"})
	if err == nil {
		t.Fatalf("Scores: want an error after exhausting retries, got nil")
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2 (MaxAttempts)", hits)
	}
}

func TestScoresSendsAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyResponse))
	}))
	defer srv.Close()
	p := testProvider(srv.URL)
	p.APIKey = "test-key-123"
	if _, err := p.Scores(context.Background(), []string{"CVE-2026-55555"}); err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if gotKey != "test-key-123" {
		t.Fatalf("apiKey header = %q, want %q", gotKey, "test-key-123")
	}
}

func TestScoresCachesWithinAProvider(t *testing.T) {
	var hits int32
	srv := serve(t, map[string]string{
		"CVE-2026-66666": cveResponse([]metricFixture{{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5}}, nil),
	}, &hits)
	p := testProvider(srv.URL)
	ctx := context.Background()
	if _, err := p.Scores(ctx, []string{"CVE-2026-66666"}); err != nil {
		t.Fatalf("Scores (1st): %v", err)
	}
	if _, err := p.Scores(ctx, []string{"CVE-2026-66666"}); err != nil {
		t.Fatalf("Scores (2nd): %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1: a CVE already fetched this run must not be fetched again", hits)
	}
}

func TestOnlyCVEsDedupesAndUppercases(t *testing.T) {
	got := onlyCVEs([]string{"cve-2026-1", "CVE-2026-1", "GHSA-xxxx", "CVE-2026-2"})
	want := []string{"CVE-2026-1", "CVE-2026-2"}
	if len(got) != len(want) {
		t.Fatalf("onlyCVEs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("onlyCVEs = %v, want %v", got, want)
		}
	}
}

func TestRetryAfterOf(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "5")
	if d := retryAfterOf(h); d != 5*time.Second {
		t.Fatalf("retryAfterOf(5) = %v, want 5s", d)
	}
	h.Set("Retry-After", "0")
	if d := retryAfterOf(h); d != 0 {
		t.Fatalf("retryAfterOf(0) = %v, want 0", d)
	}
	empty := http.Header{}
	if d := retryAfterOf(empty); d != 0 {
		t.Fatalf("retryAfterOf(missing) = %v, want 0", d)
	}
}
