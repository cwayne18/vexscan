// Package nvd reads CVSS scores directly from the National Vulnerability
// Database's own CVE API, for --prefer-vendor nvd.
//
// NVD is not a vendor the way SUSE is: it does not build the package, and the
// number it carries for a CVE was not always set by the CNA that owns the id.
// A CNA may publish no CVSS of its own -- the Go security team does not score
// the entries in https://pkg.go.dev/vuln, for instance -- and NVD fills the gap
// itself, either through an Authorized Data Publisher such as CISA or its own
// analysts. That score exists only inside NVD's database. OSV, which is where
// every other rating this tool reads comes from, does not mirror it, so a CVE
// can sit at UNKNOWN in vexscan's own output while NVD's page for the same id
// shows a number. --prefer-vendor nvd exists to reach that number.
//
// The CVE API (https://nvd.nist.gov/developers/vulnerabilities) answers one CVE
// per request; there is no "give me these N ids" bulk call, so scoring a scan's
// worth of CVEs costs one HTTP round trip per CVE. NVD's published rate limit is
// 5 requests per rolling 30 seconds without an API key, 50 with one
// (https://nvd.nist.gov/developers/start-here), so this package paces its own
// requests to stay under that rather than let NVD start answering 403 partway
// through a run. Without a key, a scan with many distinct CVEs can take minutes;
// setting NVD_API_KEY (or VEXSCAN_NVD_API_KEY) is the fix.
//
// Among the CVSS versions NVD may carry for one CVE -- v3.0, v3.1, v4.0, and the
// Primary/Secondary entries within each -- this reads whichever has the highest
// base score, the same fail-towards-severe rule bestVendorVector already applies
// when a finding's several aliases carry different vendor ratings. It is not a
// judgment that one source inside NVD is more authoritative than another; CVE-
// 2026-78660 itself has no Primary entry at all, only a Secondary one from CISA's
// enrichment pipeline, so requiring Primary would mean never finding it. CVSS v2
// is ignored, consistent with the rest of this tool.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cwayne18/vexscan/internal/envx"
)

// DefaultBaseURL is the CVE API root; one CVE is read at
// DefaultBaseURL + "?cveId=CVE-YYYY-NNNNN".
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// author is recorded as the vendor name in evidence text, e.g. "NVD rates this
// CRITICAL ... (preferred vendor score)".
const author = "NVD"

// DefaultMinInterval and DefaultMinIntervalWithAPIKey space requests to stay
// under NVD's published rate limit -- 5 requests per rolling 30 seconds
// unauthenticated, 50 with an API key -- with a small safety margin.
const (
	DefaultMinInterval        = 6500 * time.Millisecond
	DefaultMinIntervalWithKey = 650 * time.Millisecond
)

// DefaultMaxAttempts bounds retries after a rate-limited (403/429) response
// before a CVE is given up on. DefaultRetryBackoff is the wait used when a
// rate-limited response names no Retry-After: attempt N waits N *
// DefaultRetryBackoff.
const (
	DefaultMaxAttempts  = 4
	DefaultRetryBackoff = 10 * time.Second
)

// Provider reads CVSS scores from the NVD CVE API.
type Provider struct {
	// HTTP is the client used to fetch records; http.DefaultClient when nil.
	HTTP *http.Client
	// BaseURL is the CVE API root; DefaultBaseURL when empty.
	BaseURL string
	// APIKey is sent as the apiKey header when set, raising the rate limit NVD
	// allows this provider.
	APIKey string
	// MinInterval is the minimum spacing between requests; set from whether
	// APIKey is present when the Provider is built with New.
	MinInterval time.Duration
	// MaxAttempts and RetryBackoff override the retry defaults above when set.
	MaxAttempts  int
	RetryBackoff time.Duration

	reqMu   sync.Mutex
	lastReq time.Time

	cacheMu sync.Mutex
	cache   map[string]cachedScore
}

// cachedScore is one memoised lookup. vector is empty for a CVE NVD has no
// score for, which is a real answer worth caching, not a miss.
type cachedScore struct {
	vector string
}

// New returns a Provider using NVD_API_KEY (or VEXSCAN_NVD_API_KEY /
// GOMODVEX_NVD_API_KEY) from the environment when set, with request spacing
// adjusted accordingly.
func New() *Provider {
	return NewWithAPIKey(apiKeyFromEnv())
}

// NewWithAPIKey returns a Provider using the given API key; an empty key runs
// unauthenticated at the slower default spacing.
func NewWithAPIKey(key string) *Provider {
	interval := DefaultMinInterval
	if key != "" {
		interval = DefaultMinIntervalWithKey
	}
	return &Provider{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		BaseURL:     DefaultBaseURL,
		APIKey:      key,
		MinInterval: interval,
	}
}

// apiKeyFromEnv mirrors llm.go's tokenFromEnv: vexscan's own name wins, then
// the plain NVD_API_KEY name anyone who already uses NVD's API has exported.
func apiKeyFromEnv() string {
	if v := envx.Get("NVD_API_KEY"); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("NVD_API_KEY"))
}

// Name implements distrofeed.Scorer.
func (p *Provider) Name() string { return author }

var cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)

// Scores implements distrofeed.Scorer: one lookup per CVE against NVD's CVE
// API, keyed by uppercase CVE id. A CVE NVD has no record of, or has a record
// of with no CVSS metrics at all, is simply absent from the result rather than
// an error.
func (p *Provider) Scores(ctx context.Context, cves []string) (map[string]string, error) {
	ids := onlyCVEs(cves)
	if len(ids) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	var errs []error
	for _, id := range ids {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		vec, err := p.scoreOne(ctx, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		if vec != "" {
			out[id] = vec
		}
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("nvd: %d CVE(s) could not be read: %w", len(errs), errors.Join(errs...))
	}
	return out, nil
}

// onlyCVEs upper-cases a list of ids, keeps the ones that are real CVE ids, and
// de-duplicates them. NVD's CVE API is keyed by CVE alone, so a GHSA or a GO id
// -- which a finding's alias set carries alongside the CVE -- is dropped here
// rather than looked up to a certain miss.
func onlyCVEs(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		up := strings.ToUpper(strings.TrimSpace(id))
		if !cveRE.MatchString(up) || seen[up] {
			continue
		}
		seen[up] = true
		out = append(out, up)
	}
	return out
}

// scoreOne returns one CVE's best vector, consulting and populating the
// per-run cache so a Scores call never looks the same CVE up twice.
func (p *Provider) scoreOne(ctx context.Context, cve string) (string, error) {
	if c, ok := p.cached(cve); ok {
		return c.vector, nil
	}
	vec, err := p.fetch(ctx, cve)
	if err != nil {
		return "", err
	}
	p.store(cve, vec)
	return vec, nil
}

func (p *Provider) cached(cve string) (cachedScore, bool) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	c, ok := p.cache[cve]
	return c, ok
}

func (p *Provider) store(cve, vector string) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.cache == nil {
		p.cache = map[string]cachedScore{}
	}
	p.cache[cve] = cachedScore{vector: vector}
}

// rateLimited is request's error for a 403 or 429 response, carrying any
// Retry-After the response named so fetch can honour it instead of guessing.
type rateLimited struct {
	retryAfter time.Duration
}

func (e *rateLimited) Error() string { return "rate limited by NVD" }

// fetch retries a single CVE's lookup across a rate-limited response, honouring
// a Retry-After header when NVD sent one and falling back to a fixed backoff
// when it did not. Any other error is returned immediately: there is no reason
// to believe a second attempt at a malformed response or a decode failure would
// come out differently.
func (p *Provider) fetch(ctx context.Context, cve string) (string, error) {
	attempts := p.MaxAttempts
	if attempts <= 0 {
		attempts = DefaultMaxAttempts
	}
	backoff := p.RetryBackoff
	if backoff <= 0 {
		backoff = DefaultRetryBackoff
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		p.throttle(ctx)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		vec, err := p.request(ctx, cve)
		if err == nil {
			return vec, nil
		}
		var rl *rateLimited
		if !errors.As(err, &rl) {
			return "", err
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		wait := rl.retryAfter
		if wait <= 0 {
			wait = time.Duration(attempt) * backoff
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(wait):
		}
	}
	return "", lastErr
}

// throttle blocks until MinInterval has elapsed since the previous request
// this Provider made, so a scan with many CVEs cannot outrun NVD's rate limit
// regardless of how fast each individual response comes back.
func (p *Provider) throttle(ctx context.Context) {
	if p.MinInterval <= 0 {
		return
	}
	p.reqMu.Lock()
	defer p.reqMu.Unlock()
	if !p.lastReq.IsZero() {
		if wait := p.MinInterval - time.Since(p.lastReq); wait > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
		}
	}
	p.lastReq = time.Now()
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}

// request makes one HTTP call for a CVE and returns its best vector. A 404 and
// a 200 with zero results both mean NVD has no record, returned as ("", nil)
// rather than an error -- the same decline-not-fail treatment SUSE's provider
// gives a 404.
func (p *Provider) request(ctx context.Context, cve string) (string, error) {
	url := p.BaseURL + "?cveId=" + cve
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if p.APIKey != "" {
		req.Header.Set("apiKey", p.APIKey)
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return "", &rateLimited{retryAfter: retryAfterOf(resp.Header)}
	default:
		return "", fmt.Errorf("fetch %s: %s: %s", url, resp.Status, snippet(body))
	}

	var doc nvdResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse %s: %w", url, err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return "", nil
	}
	return bestVector(doc.Vulnerabilities[0].CVE.Metrics), nil
}

// nvdResponse is the CVE API's response shape, reduced to the metrics a score
// needs.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Metrics nvdMetrics `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdMetrics is one CVE's cvssMetricVxx arrays. v2 is deliberately not read,
// consistent with the rest of this tool.
type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
}

type nvdMetric struct {
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// bestVector picks the published vector with the highest base score across
// every version and every Primary/Secondary entry NVD carries, the same
// fail-towards-severe selection suse.bestVector makes among a CSAF document's
// scores. It trusts the baseScore NVD published to choose among entries;
// cvss.Score recomputes and validates the winning vector when the caller
// actually uses it, the same two-step split the rest of this tool follows.
func bestVector(m nvdMetrics) string {
	var best string
	bestScore := -1.0
	consider := func(entries []nvdMetric) {
		for _, e := range entries {
			vec := strings.TrimSpace(e.CVSSData.VectorString)
			if vec == "" {
				continue
			}
			if e.CVSSData.BaseScore > bestScore {
				best, bestScore = vec, e.CVSSData.BaseScore
			}
		}
	}
	consider(m.V40)
	consider(m.V31)
	consider(m.V30)
	return best
}

// retryAfterOf reads a Retry-After header as either a second count or an HTTP
// date, returning 0 when absent or unparsable so the caller falls back to its
// own backoff.
func retryAfterOf(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// snippet trims and collapses a response body for an error message, so a
// verbose HTML error page does not swamp the warning a failed lookup prints.
func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	const max = 200
	if len(s) > max {
		s = s[:max] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
