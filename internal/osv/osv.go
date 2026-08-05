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

	"github.com/cwayne18/vexscan/internal/cvss"
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

	// Release narrows a bare-family ecosystem to a single product release. It
	// is empty for every ecosystem whose query already names its release, and
	// when set an advisory survives only if one of its affected entries names
	// a product of that release. See Release.ProductRelease for why SUSE
	// cannot be handled in the query itself.
	Release string
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
	// Upstream is the vulnerabilities this record addresses, which for a distro
	// advisory is the CVEs its patch fixes.
	//
	// It is deliberately not merged into Aliases, because an alias is a claim
	// of identity and this is not one. Every distro database uses this field
	// and none uses aliases: SUSE-SU-2026:0312-1 addresses eight unrelated
	// CVEs, RHSA-2024:2447 seven. Treating those as eight names for one thing
	// would let buildMap file the record under eight keys and borrowSeverity
	// copy one CVE's vector onto the other seven.
	//
	// Consumers that join on CVE read it anyway, because a bundle still has to
	// be findable by what it fixes -- see advisoryResolver.cveSets.
	Upstream []string
	// Summary and Details are the advisory prose. They are the input to
	// advisory-text mining for ecosystems that publish no package-level data.
	Summary string
	Details string
	// Pkgs is the set of vulnerable import paths declared for a Go module.
	// Empty when OSV publishes no import paths (e.g. GitHub-only GHSA
	// records), in which case callers should fall back to module granularity,
	// and always empty for non-Go ecosystems.
	Pkgs []string

	// Fixed maps an affected package name to the version its patch lands in,
	// read from the record's affected ranges. It is the single most actionable
	// field a report can show -- "this is what to upgrade to" -- and unlike
	// Pkgs it is populated for every ecosystem.
	//
	// A package is absent when the record publishes no fixed version for it,
	// which is a real and common state: the flaw is acknowledged and no patch
	// has shipped. Callers must show that as "no fix" rather than as blank,
	// because the two mean opposite things. When a package has several fixed
	// events the latest is kept, which is the upgrade target for anything
	// still on an older version.
	Fixed map[string]string

	// CVSSVector is the CVSS:3.0 or CVSS:3.1 base vector the record publishes,
	// empty when it publishes none or publishes only a version this tool does
	// not score. It is kept as the string rather than only as a number so a
	// report can show the metrics behind a rating someone disputes.
	CVSSVector string
	// PublisherSeverity is the qualitative rating the database itself assigned,
	// verbatim. Empty when the record carries no label.
	//
	// It is kept separate from CVSSVector because the two are independent
	// claims that disagree more often than one would expect. See Severity.
	PublisherSeverity string
}

// Severity is the rating to display for this advisory: the more severe of what
// the publisher said and what its CVSS v3 vector computes to.
//
// Taking the maximum is not indecision about a conflict. It is the only rule
// available here that never demotes a finding on a metadata technicality. The
// two sources disagree in both directions -- measured across 442 GHSA records,
// the v3 vector is milder than GitHub's own label 27 times and harsher 20
// times -- so neither "always trust the vector" nor "always trust the label"
// avoids quietly lowering the severity of some real findings.
//
// Neither source is wrong. GitHub rates the advisory, increasingly against the
// CVSS 4.0 vector it also publishes and this tool deliberately does not score,
// while the v3 vector is a separate and older statement about the same flaw.
// The computed score cannot simply be dropped in the label's favour either: a
// Debian record carries a vector and no label at all, and scoring it is what
// makes it comparable with a GHSA one in the same table.
//
// Erring upward costs a reader time on a finding milder than billed. Erring
// downward costs them the finding.
func (a *Advisory) Severity() string {
	computed := cvss.Unknown
	if score, ok := a.CVSSScore(); ok {
		computed = cvss.Label(score)
	}
	published := cvss.Normalize(a.PublisherSeverity)

	// An absent rating loses to any real one. This is checked before the
	// comparison rather than folded into it because cvss.Rank is a display
	// order, in which UNKNOWN deliberately sorts above MEDIUM so that
	// unrated findings are not scrolled past -- correct for laying out a
	// table, and exactly wrong for choosing between two candidate ratings,
	// where it would let "nobody said" outrank a source that did.
	switch {
	case published == cvss.Unknown:
		return computed
	case computed == cvss.Unknown:
		return published
	case cvss.Rank(published) < cvss.Rank(computed):
		return published
	default:
		return computed
	}
}

// CVSSScore returns the base score for the advisory's vector. The bool is false
// when there is no vector, or it is a version this tool does not score, and
// callers must not read that as a score of zero -- 0.0 is a real CVSS answer.
func (a *Advisory) CVSSScore() (float64, bool) {
	return cvss.Score(a.CVSSVector)
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
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	// Upstream is what a distro advisory says it fixes. See Advisory.Upstream
	// for why it is kept apart from Aliases.
	Upstream []string `json:"upstream"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	// Severity is OSV's list of scores, one per scoring system. A record may
	// carry a CVSS_V3 entry, a CVSS_V4 entry, both, or neither.
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	// DatabaseSpecific is a free-form object whose contents depend on the
	// publishing database. Only "severity" is read, and only GitHub sets it.
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
			// Ecosystem is the *product* this entry applies to, which for a
			// bare-family query is finer-grained than the ecosystem asked for:
			// a "SUSE" query returns entries reading "SUSE:Linux Micro 6.2".
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path string `json:"path"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
		// Ranges carries the version events for this package: an "introduced"
		// where the flaw begins and a "fixed" where a patch lands. A distro
		// record almost always has one range with one fixed event, which is
		// the version to upgrade to.
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
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
	kept := make([]*Advisory, 0, len(vulns))
	for _, v := range vulns {
		if !appliesToRelease(ref, v) {
			continue
		}
		adv := advisoryFor(ref, v)
		kept = append(kept, adv)
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
	borrowSeverity(out, kept)
	indexUpstream(out, kept)
	return out
}

// indexUpstream makes a bundle findable by the CVEs it fixes, without letting
// them speak for it.
//
// --cves CVE-2024-5535 has to reach the SUSE-SU record that patches it; on a
// SUSE image today it reaches nothing, because no SUSE advisory names a CVE in
// its own id or its aliases. So the upstream list has to become map keys.
//
// What must not follow is severity crossing between bundle-mates, and the
// ordering is what prevents it: this runs strictly after every identity key is
// placed and after borrowSeverity has finished, so borrowSeverity never sees
// these entries and cannot copy one CVE's vector onto the other seven. It also
// never displaces an existing key, so a real record about CVE-2024-5535 always
// outranks a bundle that merely fixes it.
//
// Where two bundles address the same CVE and neither is itself a record for it,
// the first the API returned wins -- the same first-wins rule merge applies to
// conflicting names. The question asked was whether anything patches this CVE,
// and either answer is true.
func indexUpstream(out map[string]*Advisory, kept []*Advisory) {
	for _, adv := range kept {
		for _, key := range adv.Upstream {
			if key == "" {
				continue
			}
			if _, ok := out[key]; !ok {
				out[key] = adv
			}
		}
	}
}

// borrowSeverity fills in a winning advisory's missing severity from another
// record for the same vulnerability.
//
// The preference above is about import paths, and for Go it systematically
// picks the record that has no severity: a GO- record publishes the vulnerable
// packages and no rating at all, while the GHSA record aliased to it publishes
// a vector and a label and no packages. Without this, every Go finding would
// report UNKNOWN while the answer sat in a record already fetched, decoded and
// discarded in the same call.
//
// Two records sharing an identifier are two descriptions of one vulnerability,
// so taking severity from the other is not mixing sources -- it is reading the
// half of the same advisory that the packages did not come from. Only empty
// fields are filled; a record that stated its own rating keeps it.
func borrowSeverity(out map[string]*Advisory, kept []*Advisory) {
	for _, adv := range kept {
		if adv.CVSSVector == "" && adv.PublisherSeverity == "" {
			continue
		}
		for _, key := range append([]string{adv.ID}, adv.Aliases...) {
			winner, ok := out[key]
			if !ok || winner == adv {
				continue
			}
			if winner.CVSSVector == "" {
				winner.CVSSVector = adv.CVSSVector
			}
			if winner.PublisherSeverity == "" {
				winner.PublisherSeverity = adv.PublisherSeverity
			}
		}
	}
}

// appliesToRelease reports whether an advisory names a product of ref.Release.
//
// An advisory with no affected entry at all is kept: /v1/querybatch answers
// with bare ids and the hydration that follows can fail, and dropping an
// advisory because its detail is missing would report an image as clean on the
// strength of a failed fetch.
func appliesToRelease(ref Ref, v vuln) bool {
	if ref.Release == "" || len(v.Affected) == 0 {
		return true
	}
	for _, aff := range v.Affected {
		if MatchesProductRelease(aff.Package.Ecosystem, ref.Release) {
			return true
		}
	}
	return false
}

// affectedInScope reports whether an affected entry's ecosystem names the same
// release the query was for, so a fixed version is read from the bookworm entry
// and not the sid one.
//
// For a distro whose release is carried out-of-band (SUSE's bare "SUSE" family
// with a Release token) the product spelling is matched loosely, exactly as
// appliesToRelease does. For every other ecosystem the release is already in
// the ecosystem string -- "Debian:12", "Go", "PyPI" -- and an exact match is
// what keeps a Debian:13 entry from answering a Debian:12 query. An empty
// ecosystem is out of scope: it cannot be shown to name this release, and a
// wrong upgrade target is worse than none.
func affectedInScope(ref Ref, ecosystem string) bool {
	if ref.Release != "" {
		return MatchesProductRelease(ecosystem, ref.Release)
	}
	return ecosystem == ref.Ecosystem
}

func advisoryFor(ref Ref, v vuln) *Advisory {
	adv := &Advisory{
		ID:                v.ID,
		Aliases:           v.Aliases,
		Upstream:          v.Upstream,
		Summary:           v.Summary,
		Details:           v.Details,
		CVSSVector:        cvssVector(v),
		PublisherSeverity: v.DatabaseSpecific.Severity,
	}

	// Fixed versions are read for every ecosystem, before the Go-only import
	// gating below returns. Only affected entries that name this ref's release
	// are read: an OSV record carries an entry per release, and zlib's
	// DEBIAN-CVE-2023-45853 is fixed in Debian:13 but has no fix in Debian:12,
	// so reading every entry would tell a bookworm user to upgrade to a
	// version bookworm never shipped. The last fixed event in an in-scope
	// entry wins: OSV lists events in ascending version order, so for a
	// package patched more than once the latest is the upgrade target.
	for _, aff := range v.Affected {
		name := aff.Package.Name
		if name == "" || !affectedInScope(ref, aff.Package.Ecosystem) {
			continue
		}
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed == "" {
					continue
				}
				if adv.Fixed == nil {
					adv.Fixed = map[string]string{}
				}
				adv.Fixed[name] = ev.Fixed
			}
		}
	}

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

// cvssVector picks the scorable base vector out of a record's severity list.
//
// The list is keyed by scoring system and a record may hold several: a GHSA
// commonly publishes CVSS_V3 and CVSS_V4 side by side. Only a v3 vector is
// returned, because that is the only one internal/cvss will score, and the
// entry's own type is not trusted to say which -- the vector string carries its
// own version prefix, and honouring that rather than the label means a record
// that files a 4.0 vector under a CVSS_V3 type cannot be scored with the wrong
// formula.
func cvssVector(v vuln) string {
	for _, s := range v.Severity {
		vector := strings.TrimSpace(s.Score)
		if strings.HasPrefix(vector, "CVSS:3.0/") || strings.HasPrefix(vector, "CVSS:3.1/") {
			return vector
		}
	}
	return ""
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
