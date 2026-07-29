// Package osv resolves vulnerability advisories for a package version from the
// OSV database (https://osv.dev).
//
// An advisory is keyed by every identifier it is known by (its own OSV id plus
// every alias, such as CVE- and GHSA- ids), and the record that actually
// carries package-level detail wins when the same key is contributed by more
// than one source record.
//
// The Go database is the only one that publishes vulnerable import paths, so
// Advisory.Pkgs is populated for Go refs and left empty for everything else --
// see advisoryFor.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the OSV v1 API root. Endpoints are derived from it.
const DefaultBaseURL = "https://api.osv.dev/v1"

// GoEcosystem is the OSV ecosystem name for Go modules and the standard
// library.
const GoEcosystem = "Go"

// batchLimit is the maximum number of queries the OSV API accepts in one
// /v1/querybatch request.
const batchLimit = 1000

// defaultConcurrency bounds the per-id hydration fetches QueryBatch makes.
const defaultConcurrency = 8

// Ref is an OSV package coordinate: an ecosystem name, a package name as that
// ecosystem's database spells it, and a version. Version may be empty to ask
// for every advisory against the package regardless of version.
type Ref struct {
	// Ecosystem is an OSV ecosystem string, e.g. "Go", "Debian:12",
	// "Alpine:v3.19". See Release.Ecosystem for how these are derived for OS
	// distributions.
	Ecosystem string
	Name      string
	Version   string
}

func (r Ref) String() string {
	s := r.Ecosystem + "/" + r.Name
	if r.Version != "" {
		s += "@" + r.Version
	}
	return s
}

// Advisory is the resolved information for a single vulnerability id.
type Advisory struct {
	// ID is the canonical OSV identifier (e.g. GO-2024-1234, DSA-5678-1).
	ID string
	// Aliases are all other identifiers this advisory is known by.
	Aliases []string
	// Summary and Details are the advisory prose. They are the input to
	// advisory-text mining for ecosystems that publish no package-level data.
	Summary string
	Details string
	// Pkgs is the set of vulnerable import paths declared for a Go module.
	// Empty when OSV publishes no import paths (e.g. GitHub-only GHSA
	// records), in which case callers should fall back to module granularity,
	// and always empty for non-Go ecosystems.
	Pkgs []string
}

// Client queries the OSV API.
type Client struct {
	HTTP *http.Client
	// BaseURL is the API root; DefaultBaseURL when empty.
	BaseURL string
	// Concurrency bounds the parallel per-id fetches QueryBatch makes;
	// defaultConcurrency when zero.
	Concurrency int
}

// NewClient returns a Client with sane defaults.
func NewClient() *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		BaseURL: DefaultBaseURL,
	}
}

func (c *Client) endpoint(path string) string {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	return strings.TrimSuffix(base, "/") + path
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// StatusError is a non-200 answer from the OSV API.
type StatusError struct {
	Status int
	URL    string
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("osv: %s: unexpected status %d", e.URL, e.Status)
	}
	return fmt.Sprintf("osv: %s: unexpected status %d: %s", e.URL, e.Status, e.Body)
}

// Retryable reports whether repeating the request could plausibly succeed.
//
// A 4xx other than 429 is a defect in the request, not a transient fault. The
// one that matters here is an unrecognized ecosystem name: OSV answers
// {"code":3,"message":"invalid ecosystem"} with HTTP 400. Retrying that three
// times and then reporting "unexpected status 400" buries the one message that
// says what is wrong.
func (e *StatusError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// wire types

type queryRequest struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type vuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path string `json:"path"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

type queryResponse struct {
	Vulns []vuln `json:"vulns"`
}

type batchRequest struct {
	Queries []queryRequest `json:"queries"`
}

// batchResponse mirrors /v1/querybatch, which answers with ids only -- no
// affected ranges, no imports. Hydration through /v1/vulns/{id} is therefore
// not optional.
type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// Query returns the map of advisory-id -> Advisory for ref. Every alias
// identifier is a key in the returned map, so a caller may look up a CVE, GHSA
// or GO id interchangeably.
func (c *Client) Query(ctx context.Context, ref Ref) (map[string]*Advisory, error) {
	var resp queryResponse
	err := c.retry(ctx, func() error {
		resp = queryResponse{}
		return c.postJSON(ctx, c.endpoint("/query"), queryFor(ref), &resp)
	})
	if err != nil {
		return nil, err
	}
	return buildMap(ref, resp.Vulns), nil
}

// QueryBatch resolves many refs at once. result[i] is what Query(refs[i])
// would have returned, so the answer is always the same length as refs.
//
// A whole-image scan is thousands of lookups; one /v1/query round trip each is
// not viable. /v1/querybatch takes 1000 refs per request but answers with ids
// only, so every distinct id is then fetched once through /v1/vulns/{id} --
// distinct being the point, since an OS advisory typically covers many of the
// packages in one image.
func (c *Client) QueryBatch(ctx context.Context, refs []Ref) ([]map[string]*Advisory, error) {
	perRef := make([][]string, len(refs))
	for start := 0; start < len(refs); start += batchLimit {
		end := min(start+batchLimit, len(refs))
		ids, err := c.batchIDs(ctx, refs[start:end])
		if err != nil {
			return nil, err
		}
		copy(perRef[start:end], ids)
	}

	unique := map[string]bool{}
	for _, ids := range perRef {
		for _, id := range ids {
			unique[id] = true
		}
	}
	records, err := c.hydrate(ctx, keys(unique))
	if err != nil {
		return nil, err
	}

	out := make([]map[string]*Advisory, len(refs))
	for i, ref := range refs {
		var vulns []vuln
		for _, id := range perRef[i] {
			if v, ok := records[id]; ok {
				vulns = append(vulns, v)
			}
		}
		out[i] = buildMap(ref, vulns)
	}
	return out, nil
}

// Vuln fetches one advisory record by its OSV id.
func (c *Client) Vuln(ctx context.Context, id string) (*Advisory, error) {
	v, err := c.vuln(ctx, id)
	if err != nil {
		return nil, err
	}
	// No ref, so no ecosystem: import paths are left to a Query that knows
	// which package it asked about.
	return advisoryFor(Ref{}, v), nil
}

func (c *Client) vuln(ctx context.Context, id string) (vuln, error) {
	var v vuln
	err := c.retry(ctx, func() error {
		v = vuln{}
		return c.getJSON(ctx, c.endpoint("/vulns/"+url.PathEscape(id)), &v)
	})
	return v, err
}

// batchIDs returns, for each ref, the advisory ids OSV matched against it.
func (c *Client) batchIDs(ctx context.Context, refs []Ref) ([][]string, error) {
	req := batchRequest{Queries: make([]queryRequest, len(refs))}
	for i, ref := range refs {
		req.Queries[i] = queryFor(ref)
	}

	var resp batchResponse
	err := c.retry(ctx, func() error {
		resp = batchResponse{}
		return c.postJSON(ctx, c.endpoint("/querybatch"), req, &resp)
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != len(refs) {
		return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(refs))
	}

	out := make([][]string, len(refs))
	for i, r := range resp.Results {
		for _, v := range r.Vulns {
			if v.ID != "" {
				out[i] = append(out[i], v.ID)
			}
		}
	}
	return out, nil
}

// hydrate fetches every id, bounded to Concurrency in flight. The first
// failure wins and cancels the rest: a partially hydrated result set would
// under-report advisories, which is the failure direction this tool must never
// take silently.
func (c *Client) hydrate(ctx context.Context, ids []string) (map[string]vuln, error) {
	out := make(map[string]vuln, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	n := c.Concurrency
	if n <= 0 {
		n = defaultConcurrency
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, n)
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			v, err := c.vuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstEr == nil {
					firstEr = fmt.Errorf("osv: fetching %s: %w", id, err)
					cancel()
				}
				return
			}
			out[id] = v
		}(id)
	}
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}
	return out, nil
}

func queryFor(ref Ref) queryRequest {
	var q queryRequest
	q.Package.Ecosystem = ref.Ecosystem
	q.Package.Name = ref.Name
	q.Version = normalizeVersion(ref)
	return q
}

// normalizeVersion strips the prefixes a Go version carries but OSV does not
// want: the module "v" and the stdlib "go" ("go1.24.0" -> "1.24.0").
//
// Only Go versions are rewritten. An OS package version is an opaque string to
// us, and the same trim would quietly corrupt real ones -- Debian's
// "golang-1.21" source versions and Alpine's "v"-prefixed tags among them.
func normalizeVersion(ref Ref) string {
	if ref.Ecosystem != GoEcosystem {
		return ref.Version
	}
	v := strings.TrimPrefix(ref.Version, "v")
	return strings.TrimPrefix(v, "go")
}

func buildMap(ref Ref, vulns []vuln) map[string]*Advisory {
	out := map[string]*Advisory{}
	for _, v := range vulns {
		adv := advisoryFor(ref, v)
		for _, key := range append([]string{v.ID}, v.Aliases...) {
			if key == "" {
				continue
			}
			// Prefer whichever record carries import paths so an import-less
			// GHSA record never clobbers a richer GO record's package list.
			if existing, ok := out[key]; !ok || (len(existing.Pkgs) == 0 && len(adv.Pkgs) > 0) {
				out[key] = adv
			}
		}
	}
	return out
}

func advisoryFor(ref Ref, v vuln) *Advisory {
	adv := &Advisory{ID: v.ID, Aliases: v.Aliases, Summary: v.Summary, Details: v.Details}

	// ecosystem_specific.imports is a Go-database field. Reading it for any
	// other ecosystem yields an empty list that is indistinguishable from "OSV
	// published no import paths for this Go module" -- which callers treat as
	// a signal to fall back to module granularity. Gating on the ecosystem
	// keeps the absence meaningful.
	if ref.Ecosystem != GoEcosystem {
		return adv
	}

	pkgs := map[string]struct{}{}
	for _, aff := range v.Affected {
		if aff.Package.Name != ref.Name {
			continue
		}
		for _, imp := range aff.EcosystemSpecific.Imports {
			if imp.Path != "" {
				pkgs[imp.Path] = struct{}{}
			}
		}
	}
	adv.Pkgs = make([]string, 0, len(pkgs))
	for p := range pkgs {
		adv.Pkgs = append(adv.Pkgs, p)
	}
	return adv
}

// retry runs fn up to three times, backing off a second per attempt. A
// non-retryable status (see StatusError.Retryable) fails immediately.
func (c *Client) retry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		if err = fn(); err == nil {
			return nil
		}
		var se *StatusError
		if errors.As(err, &se) && !se.Retryable() {
			return err
		}
		if ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (c *Client) postJSON(ctx context.Context, endpoint string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return &StatusError{
			Status: res.StatusCode,
			URL:    req.URL.String(),
			Body:   strings.TrimSpace(string(snippet)),
		}
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
