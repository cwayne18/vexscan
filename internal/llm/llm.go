// Package llm asks a GitHub Models chat model two questions about a CVE that
// the deterministic analysis has already decided is genuinely present: whether
// it is plausibly exploitable in context (Assess), and which checkable
// identifiers the advisory text names (Mine).
//
// Both are optional and advisory. Assess never sets a status -- it attaches an
// opinion to a finding that already has one. Mine produces nothing but
// candidate strings, and the caller must validate them against something it
// can observe before any of them supports a conclusion; an unvalidatable hint
// is indistinguishable from a hallucination, so validation is what makes a
// wrong answer inert rather than dangerous. That validation deliberately lives
// with the caller that has the facts to do it, not here.
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

// Request describes one CVE to assess in the context of a specific location.
type Request struct {
	// Ecosystem is the plugin that produced the finding ("golang", "os"). It
	// selects the system prompt and is part of the cache key: the same CVE
	// against a Go module and against an OS package are different questions.
	Ecosystem string

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
	hints   map[string]*Hints
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
		hints:       make(map[string]*Hints),
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

// goPrompt is the original prompt, kept verbatim. Changing a word of it would
// move every Go verdict the tool has ever produced, so new ecosystems get new
// prompts rather than a shared one that has been generalized into vagueness.
const goPrompt = `You are a security analyst assessing Go dependency vulnerabilities (VEX triage).
You are given a CVE whose vulnerable package has been confirmed to be linked into (and possibly reachable from) a shipped Go binary.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this binary.
Consider: whether the vulnerable functions are likely invoked with attacker-controlled input, network exposure, and typical usage of the package.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// osPrompt asks the same question about an OS package.
//
// The evidence behind an OS finding is weaker than behind a Go one and the
// prompt says so: "linked" here means the dynamic linker would load a library
// the package installs, which is a much lower bar than a symbol surviving
// dead-code elimination. The prompt also names the reasons an installed,
// loaded library is routinely not exploitable -- a CLI tool nothing invokes, a
// codec path the image never exercises -- because those are the cases the
// deterministic layer cannot see and the whole reason to ask at all.
const osPrompt = `You are a security analyst assessing operating-system package vulnerabilities in a container image (VEX triage).
You are given a CVE against an installed OS package (deb, rpm or apk) whose shared libraries the dynamic linker would load when the image runs.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this image.
Consider: whether the vulnerable code path is reachable from the image's own workload rather than only from a command-line tool that happens to be installed, whether the input it parses could be attacker-controlled, and whether exploitation requires local access, a specific configuration, or a non-default feature.
Note that a library being loaded says nothing about which of its functions are called.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// pypiPrompt asks the same question about an installed Python distribution.
//
// The two lines that are not in the OS prompt are the two things that are
// actually different about Python. The first is that the evidence is weaker
// still: "imported" means a static import graph reached a module, which says
// nothing about which functions run. The second is the shape Python advisories
// keep taking -- one unsafe entry point beside a safe default, yaml.load
// against yaml.safe_load being the archetype -- because whether the
// application uses the unsafe one is exactly the question the deterministic
// layer cannot answer and the only reason to ask a model at all.
const pypiPrompt = `You are a security analyst assessing Python package vulnerabilities in a container image (VEX triage).
You are given a CVE against an installed Python distribution whose modules the code the image runs imports.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this image.
Consider: whether the vulnerable API is likely called with attacker-controlled input rather than only from a command-line tool or a test path, whether an application would use the affected entry point at all (many Python advisories affect one unsafe function that has a safe documented default beside it), and whether exploitation requires a specific configuration or a non-default feature.
Note that Python removes no dead code, so a distribution being installed and imported says nothing about which of its functions are called.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// npmPrompt asks the same question about an installed Node package.
//
// The line that is not in the Python prompt is npm's own distinguishing fact:
// the dependency tree is deep and mostly transitive, so the package the
// advisory names is usually not one the application chose. Whether the one
// call path that reaches it passes attacker input is the question, and a model
// that does not know the package is transitive will answer as though the
// application uses it directly.
const npmPrompt = `You are a security analyst assessing Node.js package vulnerabilities in a container image (VEX triage).
You are given a CVE against an installed npm package whose modules the code the image runs requires.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this image.
Consider: whether the vulnerable API is likely called with attacker-controlled input rather than only from a build script, a CLI tool or a test path, whether the package is a deep transitive dependency reached only through one narrow call path, and whether exploitation requires a specific configuration, a non-default option, or a prototype-pollution sink the application does not have.
Note that npm removes no dead code, so a package being installed and required says nothing about which of its functions are called.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// mavenPrompt asks the same question about a Java artifact in an image.
//
// The evidence behind a Maven finding is the weakest of the five, and the
// prompt has to say so plainly: there is no reference graph for Java here, so
// "present" means the archive is on the disk and nothing more. Nothing has
// established that a classloader ever opens it.
//
// The three considerations that are not in the npm prompt are the three things
// actually different about Java in a container. A jar in a lib directory may
// belong to a servlet container's own tooling rather than to the application.
// Java advisories are dominated by deserialization sinks and by lookups that
// fire only when a feature is configured on -- Log4Shell needed a message
// pattern that interpolates user input -- so configuration is more often the
// deciding fact than a call path. And the affected artifact is usually a
// transitive dependency of a framework, reached, if at all, through one narrow
// path the application never wrote.
const mavenPrompt = `You are a security analyst assessing Java dependency vulnerabilities in a container image (VEX triage).
You are given a CVE against a Maven artifact (a jar, war or ear) that is present in the image.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this image.
Consider: whether the vulnerable class is likely instantiated or invoked with attacker-controlled input rather than only from a build tool, an optional integration or a test path; whether exploitation requires a non-default configuration, a specific feature to be enabled, or the application to deserialize untrusted data; and whether the artifact is a deep transitive dependency of a framework rather than something the application uses directly.
Note that this scan has established only that the artifact is present. Java loads classes lazily and this scan has no call graph, so nothing here says any of its code runs.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// promptFor selects the system prompt for an ecosystem.
//
// The empty ecosystem is Go: that is what every caller meant before this
// function existed, and a caller that forgets to set the field should get the
// old behavior rather than a generic prompt that quietly changes its verdicts.
func promptFor(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "os":
		return osPrompt
	case "pypi":
		return pypiPrompt
	case "npm":
		return npmPrompt
	case "maven":
		return mavenPrompt
	default:
		return goPrompt
	}
}

// userMessage states the facts for one assessment.
//
// The Go wording is preserved exactly, for the same reason as the prompt. The
// OS wording differs only in its labels: "Module" and "Binary" are the wrong
// nouns for a package installed into an image, and a prompt that uses the
// wrong noun invites the model to answer about the wrong thing.
func userMessage(r Request) string {
	reach := r.Reachable
	if reach == "" {
		reach = "unknown"
	}
	if strings.EqualFold(r.Ecosystem, "os") {
		where := r.Binary
		if where == "" {
			where = "the image"
		}
		return fmt.Sprintf(
			"CVE: %s\nPackage: %s %s\nImage: %s\nStatic analysis says the vulnerable code is: %s\nAssess exploitability.",
			r.CVE, r.Module, r.Version, where, reach,
		)
	}
	if strings.EqualFold(r.Ecosystem, "pypi") {
		where := r.Binary
		if where == "" {
			where = "the image"
		}
		return fmt.Sprintf(
			"CVE: %s\nDistribution: %s %s\nImage: %s\nStatic analysis says the vulnerable code is: %s\nAssess exploitability.",
			r.CVE, r.Module, r.Version, where, reach,
		)
	}
	if strings.EqualFold(r.Ecosystem, "npm") {
		where := r.Binary
		if where == "" {
			where = "the image"
		}
		return fmt.Sprintf(
			"CVE: %s\nPackage: %s %s\nImage: %s\nStatic analysis says the vulnerable code is: %s\nAssess exploitability.",
			r.CVE, r.Module, r.Version, where, reach,
		)
	}
	return fmt.Sprintf(
		"CVE: %s\nModule: %s@%s\nVulnerable packages: %s\nBinary: %s\nStatic analysis says the vulnerable code is: %s\nAssess exploitability.",
		r.CVE, r.Module, r.Version, strings.Join(r.Packages, ", "), r.Binary, reach,
	)
}

// Assess returns the model's verdict for a single CVE. Identical requests
// (same CVE, module, version, packages and reachability) are served from an
// in-memory cache, so image-mode scans that link the same CVE into many
// binaries only pay for one API call.
func (c *Client) Assess(ctx context.Context, r Request) (*Verdict, error) {
	key := cacheKey(r)
	if v := c.cached(key); v != nil {
		return v, nil
	}

	raw, err := c.chat(ctx, promptFor(r.Ecosystem), userMessage(r))
	if err != nil {
		return nil, err
	}
	v, err := parseVerdict(raw)
	if err != nil {
		return nil, err
	}
	c.store(key, v)
	return v, nil
}

// chat sends one system/user exchange and returns the model's reply text,
// retrying the failures that are worth retrying.
func (c *Client) chat(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:       c.Model,
		Temperature: 0,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return "", err
	}

	const maxAttempts = 6
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.throttle(ctx)
		res, raw, err := c.do(ctx, body)
		if err != nil {
			lastErr = err
			if !sleepBeforeRetry(ctx, attempt, maxAttempts, 0) {
				return "", err
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
			return "", lastErr
		}
		if decodeErr != nil {
			return "", fmt.Errorf("github models: could not parse response: %s", snippet(raw))
		}
		if cr.Error != nil && cr.Error.Message != "" {
			return "", fmt.Errorf("github models: %s", cr.Error.Message)
		}
		if len(cr.Choices) == 0 {
			return "", fmt.Errorf("github models: empty response")
		}
		return cr.Choices[0].Message.Content, nil
	}
	return "", lastErr
}

// cacheKey canonicalizes a Request for verdict caching. It deliberately omits
// the binary name so the same CVE, linked the same way, is only assessed once
// even when it appears in many binaries.
func cacheKey(r Request) string {
	pkgs := append([]string(nil), r.Packages...)
	sort.Strings(pkgs)
	return strings.Join([]string{r.Ecosystem, r.CVE, r.Module, r.Version, strings.Join(pkgs, ","), r.Reachable}, "|")
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
