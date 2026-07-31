// Package llm asks a chat model two questions about a CVE that the
// deterministic analysis has already decided is genuinely present: whether it
// is plausibly exploitable in context (Assess), and which checkable identifiers
// the advisory text names (Mine).
//
// Both are optional and advisory. Assess never sets a status -- it attaches an
// opinion to a finding that already has one. Mine produces nothing but
// candidate strings, and the caller must validate them against something it
// can observe before any of them supports a conclusion; an unvalidatable hint
// is indistinguishable from a hallucination, so validation is what makes a
// wrong answer inert rather than dangerous. That validation deliberately lives
// with the caller that has the facts to do it, not here.
//
// Which model answers is the user's choice, via Config: an OpenAI-compatible
// endpoint, a local server speaking the same format, or a CLI already
// installed on the machine. Nothing here is tied to a provider, and nothing
// needs to be -- because no answer from any of them can set a status, the
// choice trades rationale quality and cost, not correctness.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cwayne18/vexscan/internal/envx"
)

// DefaultModel is the OpenAI-compatible model id used when none is given. It
// is a bare name rather than a provider-qualified one because that is what
// every endpoint except a router expects; OpenRouter and friends want
// "vendor/model" and the user supplies it.
const DefaultModel = "gpt-4o"

// DefaultMinInterval is the default minimum spacing between requests: none.
//
// This was once a second, to stay under GitHub Models' burst limit. A
// general endpoint has no such limit, and the ones that do rate-limit say so
// with a 429 and a Retry-After that the retry loop already honors. Slowing
// every scan down for a provider the user may not be using is the wrong
// default. Override with VEXSCAN_LLM_MIN_INTERVAL (a Go duration such as "2s").
const DefaultMinInterval = 0

// maxRetryWait caps how long a single backoff wait can be, including a
// server-provided Retry-After. Rate-limit windows are frequently 60s+, so this
// must be large enough to actually outlast one.
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

// Config says which model to ask and how to reach it.
//
// Exactly one of Endpoint and Command must be set. There is no default for
// either, and that is the point: the tool used to have one, GitHub Models,
// which was free with a token most users already had. It was retired, and a
// scanner that silently picked a replacement -- or silently stopped asking --
// would be reporting an absence of exploitability opinions that looks exactly
// like a set of findings nothing had an opinion about.
type Config struct {
	// Endpoint is an OpenAI-compatible chat/completions URL.
	Endpoint string
	// Model is the model id to send. Ignored when Command is set: a CLI
	// chooses its own model, or takes one in its own arguments.
	Model string
	// Token is the bearer credential for Endpoint. Empty is valid and means
	// no Authorization header, which is what the local servers want.
	Token string
	// Command is a locally installed CLI to run instead of calling an
	// endpoint. See CommandTransport for what this costs.
	Command string
}

// Client asks a model the package's two questions, once each per distinct
// input.
type Client struct {
	Transport Transport

	// MinInterval is the minimum spacing enforced between outgoing requests.
	MinInterval time.Duration

	throttleMu sync.Mutex
	lastReq    time.Time

	cacheMu sync.Mutex
	cache   map[string]*Verdict
	hints   map[string]*Hints
}

// NewClient builds a Client for a provider.
func NewClient(cfg Config) (*Client, error) {
	var tr Transport
	switch {
	case cfg.Endpoint != "" && cfg.Command != "":
		return nil, errors.New("set either an LLM endpoint or an LLM command, not both")
	case cfg.Command != "":
		cmd, err := NewCommandTransport(cfg.Command)
		if err != nil {
			return nil, err
		}
		tr = cmd
	case cfg.Endpoint != "":
		model := cfg.Model
		if model == "" {
			model = DefaultModel
		}
		tr = &HTTPTransport{
			HTTP:     &http.Client{Timeout: 60 * time.Second},
			Endpoint: cfg.Endpoint,
			Model:    model,
			Token:    cfg.Token,
		}
	default:
		return nil, ErrNoProvider
	}
	return NewClientWithTransport(tr), nil
}

// ErrNoProvider is returned when --llm is on and nothing says who to ask.
//
// It is a paragraph rather than a sentence because it is the error every
// existing user hits exactly once, on the day their working command line stops
// working, and the useful thing to tell them is not what went wrong but which
// three things they can type instead.
var ErrNoProvider = errors.New(`no LLM provider configured, and there is no default (GitHub Models, which used to be one, has been retired). Choose one:

  an OpenAI-compatible endpoint
    export VEXSCAN_LLM_ENDPOINT=https://api.openai.com/v1/chat/completions
    export VEXSCAN_LLM_TOKEN=sk-...            # or set OPENAI_API_KEY

  a model on this machine, via Ollama
    export VEXSCAN_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions
    export VEXSCAN_LLM_MODEL=llama3.1          # no token needed

  a CLI already installed and logged in
    export VEXSCAN_LLM_COMMAND='claude -p'

or pass --llm-endpoint / --llm-command`)

// ConfigFrom resolves a provider from explicit values and the environment,
// explicit values first.
//
// The token is env-only and has no flag on purpose: everything on a command
// line is readable in the process table by every user on the machine, and a
// credential is the one thing here that must not be.
func ConfigFrom(endpoint, model, command string) Config {
	if endpoint == "" {
		endpoint = envx.Get("LLM_ENDPOINT")
	}
	if command == "" {
		command = envx.Get("LLM_COMMAND")
	}
	if model == "" {
		model = envx.Get("LLM_MODEL")
	}
	return Config{Endpoint: endpoint, Model: model, Command: command, Token: tokenFromEnv()}
}

// tokenFromEnv finds the bearer credential for an endpoint.
//
// The provider-specific names are accepted after vexscan's own because they
// are already exported in the shell of anyone who uses these APIs, and asking
// them to copy a key into a second variable buys nothing.
func tokenFromEnv() string {
	if v := envx.Get("LLM_TOKEN"); v != "" {
		return v
	}
	for _, k := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// NewClientWithTransport wraps a Transport the caller built itself.
func NewClientWithTransport(tr Transport) *Client {
	return &Client{
		Transport:   tr,
		MinInterval: minIntervalFromEnv(),
		cache:       make(map[string]*Verdict),
		hints:       make(map[string]*Hints),
	}
}

// Describe names the provider, for a log line saying who is being asked.
func (c *Client) Describe() string {
	if c == nil || c.Transport == nil {
		return "none"
	}
	return c.Transport.Describe()
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
// retrying the failures the transport says are worth retrying.
func (c *Client) chat(ctx context.Context, system, user string) (string, error) {
	if c.Transport == nil {
		return "", errors.New("llm: no transport configured")
	}
	const maxAttempts = 6
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.throttle(ctx)
		out, err := c.Transport.Chat(ctx, system, user)
		if err == nil {
			return out, nil
		}
		lastErr = err
		again, hint := retryHint(err)
		if !again || !sleepBeforeRetry(ctx, attempt, maxAttempts, hint) {
			return "", err
		}
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
