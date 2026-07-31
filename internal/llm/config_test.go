package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClientSelectsATransport(t *testing.T) {
	tests := []struct {
		name         string
		cfg          Config
		wantErr      string
		wantDescribe string
	}{
		{
			name: "endpoint", cfg: Config{Endpoint: "http://x/v1/chat/completions", Model: "m"},
			wantDescribe: "m at http://x/v1/chat/completions",
		},
		{
			name: "command", cfg: Config{Command: "claude -p"},
			wantDescribe: "command claude",
		},
		// Neither is the case that matters. GitHub Models was the default
		// until it was retired, and a scan that quietly asks nobody produces a
		// report with no exploitability opinions in it -- which is what a
		// report full of unremarkable findings also looks like.
		{name: "neither", cfg: Config{}, wantErr: "no LLM provider"},
		{
			name: "both", cfg: Config{Endpoint: "http://x", Command: "claude -p"},
			wantErr: "not both",
		},
		{name: "unterminated quote", cfg: Config{Command: `claude "-p`}, wantErr: "unterminated"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.cfg)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("NewClient(%+v) succeeded, want an error", tc.cfg)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if got := c.Describe(); got != tc.wantDescribe {
				t.Errorf("Describe() = %q, want %q", got, tc.wantDescribe)
			}
		})
	}
}

// A local server -- Ollama, llama.cpp, vLLM -- wants no credential, and some of
// them reject a bearer header with nothing after it. An empty token has to mean
// "send no header", not "send an empty one".
func TestNoTokenSendsNoAuthorizationHeader(t *testing.T) {
	var sawAuth, sawHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawHeader = r.Header["Authorization"]
		sawAuth = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"exploitable\":\"unknown\"}"}}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{Endpoint: srv.URL, Model: "llama3.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Assess(context.Background(), Request{CVE: "CVE-1"}); err != nil {
		t.Fatal(err)
	}
	if sawHeader || sawAuth {
		t.Error("an unauthenticated endpoint was sent an Authorization header")
	}
}

func TestTokenIsSentAsBearer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"exploitable\":\"unknown\"}"}}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{Endpoint: srv.URL, Model: "gpt-4o", Token: "sk-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Assess(context.Background(), Request{CVE: "CVE-1"}); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer sk-secret" {
		t.Errorf("Authorization = %q", got)
	}
}

// Describe goes into a log line, so it must name the provider without naming
// the credential.
func TestDescribeCarriesNoCredential(t *testing.T) {
	c, err := NewClient(Config{Endpoint: "https://api.openai.com/v1/chat/completions", Model: "gpt-4o", Token: "sk-do-not-print-me"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.Describe(), "sk-do-not-print-me") {
		t.Errorf("Describe() leaks the token: %q", c.Describe())
	}
}
