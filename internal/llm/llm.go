// Package llm asks a GitHub Models chat model whether a CVE that is genuinely
// linked into a binary is plausibly exploitable in that context. It is an
// optional, advisory layer on top of the deterministic pclntab / govulncheck
// analysis.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cwayne18/vexscan/internal/envx"
)

// DefaultEndpoint is the GitHub Models OpenAI-compatible inference endpoint.
const DefaultEndpoint = "https://models.github.ai/inference/chat/completions"

// DefaultModel is used when no model is specified.
const DefaultModel = "openai/gpt-4o"

// DefaultMinInterval is the default minimum spacing between API requests. GitHub
// Models applies a low per-minute burst limit; spacing requests out keeps a
// multi-binary scan from tripping the secondary (abuse) rate limit. Override
// with VEXSCAN_LLM_MIN_INTERVAL (a Go duration such as "2s" or "0" to disable).
const DefaultMinInterval = time.Second

// maxRetryWait caps how long a single backoff wait can be, including a
// server-provided Retry-After. GitHub's rate-limit windows are frequently 60s+,
// so this must be large enough to actually outlast one.
const maxRetryWait = 120 * time.Second

// Verdict is the model's structured assessment.
type Verdict struct {
	Exploitable string `json:"exploitable"` // "likely" | "unlikely" | "unknown"
	Confidence  string `json:"confidence"`  // "low" | "medium" | "high"
	Rationale   string `json:"rationale"`
}

// Request describes one CVE to assess in the context of a specific binary.
type Request struct {
	CVE       string
	Module    string
	Version   string
	Packages  []string
	Binary    string
	Reachable string // "linked" | "reachable" | "unknown"
}

// Client talks to the GitHub Models API.
type Client struct {
	HTTP     *http.Client
	Endpoint string
	Model    string
	Token    string

	// MinInterval is the minimum spacing enforced between outgoing requests.
	MinInterval time.Duration

	throttleMu sync.Mutex
	lastReq    time.Time

	cacheMu sync.Mutex
	cache   map[string]*Verdict
}

// NewClient builds a Client. The token is read from GITHUB_TOKEN (or GH_TOKEN)
// unless supplied explicitly. It returns an error if no token is available.
func NewClient(model, token string) (*Client, error) {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found (set GITHUB_TOKEN or GH_TOKEN)")
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{
		HTTP:        &http.Client{Timeout: 60 * time.Second},
		Endpoint:    DefaultEndpoint,
		Model:       model,
		Token:       token,
		MinInterval: minIntervalFromEnv(),
		cache:       make(map[string]*Verdict),
	}, nil
}

// minIntervalFromEnv resolves the request spacing, honoring an optional
// VEXSCAN_LLM_MIN_INTERVAL override.
func minIntervalFromEnv() time.Duration {
	v := envx.Get("LLM_MIN_INTERVAL")
	if v == "" {
		return DefaultMinInterval
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return d
	}
	return DefaultMinInterval
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

const systemPrompt = `You are a security analyst assessing Go dependency vulnerabilities (VEX triage).
You are given a CVE whose vulnerable package has been confirmed to be linked into (and possibly reachable from) a shipped Go binary.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this binary.
Consider: whether the vulnerable functions are likely invoked with attacker-controlled input, network exposure, and typical usage of the package.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// Assess returns the model's verdict for a single CVE. Identical requests
// (same CVE, module, version, packages and reachability) are served from an
// in-memory cache, so image-mode scans that link the same CVE into many
// binaries only pay for one API call.
func (c *Client) Assess(ctx context.Context, r Request) (*Verdict, error) {
	key := cacheKey(r)
	if v := c.cached(key); v != nil {
		return v, nil
	}

	reach := r.Reachable
	if reach == "" {
		reach = "unknown"
	}
	user := fmt.Sprintf(
		"CVE: %s\nModule: %s@%s\nVulnerable packages: %s\nBinary: %s\nStatic analysis says the vulnerable code is: %s\nAssess exploitability.",
		r.CVE, r.Module, r.Version, strings.Join(r.Packages, ", "), r.Binary, reach,
	)

	reqBody := chatRequest{
		Model:       c.Model,
		Temperature: 0,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: user},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	const maxAttempts = 6
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.throttle(ctx)
		res, raw, err := c.do(ctx, body)
		if err != nil {
			lastErr = err
			if !sleepBeforeRetry(ctx, attempt, maxAttempts, 0) {
				return nil, err
			}
			continue
		}

		// The API does not always return JSON: rate limiting, gateway timeouts
		// and auth failures can come back as plain text or HTML. Decode
		// defensively and prefer the HTTP status when the body isn't JSON.
		var cr chatResponse
		decodeErr := json.Unmarshal(raw, &cr)

		if res.StatusCode != http.StatusOK {
			if decodeErr == nil && cr.Error != nil && cr.Error.Message != "" {
				lastErr = fmt.Errorf("github models: %s (status %d)", cr.Error.Message, res.StatusCode)
			} else {
				lastErr = fmt.Errorf("github models: status %d: %s", res.StatusCode, snippet(raw))
			}
			if isRetryable(res.StatusCode) && sleepBeforeRetry(ctx, attempt, maxAttempts, retryAfter(res)) {
				continue
			}
			return nil, lastErr
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("github models: could not parse response: %s", snippet(raw))
		}
		if cr.Error != nil && cr.Error.Message != "" {
			return nil, fmt.Errorf("github models: %s", cr.Error.Message)
		}
		if len(cr.Choices) == 0 {
			return nil, fmt.Errorf("github models: empty response")
		}
		v, err := parseVerdict(cr.Choices[0].Message.Content)
		if err != nil {
			return nil, err
		}
		c.store(key, v)
		return v, nil
	}
	return nil, lastErr
}

// cacheKey canonicalizes a Request for verdict caching. It deliberately omits
// the binary name so the same CVE, linked the same way, is only assessed once
// even when it appears in many binaries.
func cacheKey(r Request) string {
	pkgs := append([]string(nil), r.Packages...)
	sort.Strings(pkgs)
	return strings.Join([]string{r.CVE, r.Module, r.Version, strings.Join(pkgs, ","), r.Reachable}, "|")
}

func (c *Client) cached(key string) *Verdict {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	return c.cache[key]
}

func (c *Client) store(key string, v *Verdict) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]*Verdict)
	}
	c.cache[key] = v
}

// throttle blocks until at least MinInterval has elapsed since the previous
// request, smoothing bursts so a large scan does not trip the burst limit.
func (c *Client) throttle(ctx context.Context) {
	if c.MinInterval <= 0 {
		return
	}
	c.throttleMu.Lock()
	defer c.throttleMu.Unlock()
	if !c.lastReq.IsZero() {
		if wait := c.MinInterval - time.Since(c.lastReq); wait > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
		}
	}
	c.lastReq = time.Now()
}

// do sends one request and returns the response (with a drained body) and the
// raw body bytes.
func (c *Client) do(ctx context.Context, body []byte) (*http.Response, []byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("Accept", "application/json")

	res, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	return res, raw, nil
}

// isRetryable reports whether an HTTP status warrants another attempt.
func isRetryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// retryAfter parses the Retry-After header into a duration. GitHub Models sends
// a delay in seconds, but the header may also be an HTTP date; both are handled.
func retryAfter(res *http.Response) time.Duration {
	if res == nil {
		return 0
	}
	v := strings.TrimSpace(res.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// sleepBeforeRetry waits before the next attempt, using the server-provided
// delay when available or exponential backoff otherwise. It returns false when
// no further attempts should be made (last attempt or context cancelled).
func sleepBeforeRetry(ctx context.Context, attempt, maxAttempts int, hint time.Duration) bool {
	if attempt >= maxAttempts {
		return false
	}
	wait := hint
	if wait <= 0 {
		// Exponential backoff (1s, 2s, 4s, ...) capped modestly; a server that
		// wants us to wait longer says so via Retry-After (the hint above).
		wait = time.Duration(1<<uint(attempt-1)) * time.Second
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
	}
	if wait > maxRetryWait {
		wait = maxRetryWait
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(wait):
		return true
	}
}

var jsonObjRe = regexp.MustCompile(`(?s)\{.*\}`)

// snippet returns a compact, single-line preview of a raw response body for use
// in error messages, so non-JSON replies (rate-limit notices, HTML gateway
// errors, etc.) are legible instead of dumping the whole payload.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.Join(strings.Fields(s), " ")
	const max = 200
	if len(s) > max {
		s = s[:max] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

// parseVerdict extracts the JSON object from a model reply, tolerating stray
// markdown fences or prose around it.
func parseVerdict(content string) (*Verdict, error) {
	match := jsonObjRe.FindString(content)
	if match == "" {
		return &Verdict{Exploitable: "unknown", Confidence: "low", Rationale: strings.TrimSpace(content)}, nil
	}
	var v Verdict
	if err := json.Unmarshal([]byte(match), &v); err != nil {
		return &Verdict{Exploitable: "unknown", Confidence: "low", Rationale: strings.TrimSpace(content)}, nil
	}
	if v.Exploitable == "" {
		v.Exploitable = "unknown"
	}
	return &v, nil
}
