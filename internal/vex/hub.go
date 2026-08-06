package vex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Hub is one opened VEX repository: its index, plus whatever documents have
// been fetched out of it so far.
//
// A Hub is safe for concurrent use. Lookup is the only method, and two
// goroutines asking for the same product will each fetch it -- the cache
// deduplicates the answer, not the request, which is the right trade for a
// handful of products per scan.
type Hub struct {
	// URL is the hub as the user named it, for messages and for the record in
	// the JSON output.
	URL string

	HTTP *http.Client

	// base is the resolved root that locations are relative to: an http(s)
	// prefix ending in "/", or a local directory.
	base  string
	local bool

	// index maps a canonical product purl to its document's relative location.
	index map[string]string

	// indexRaw is index.json exactly as published. Kept because a writer that
	// adds a product to the index has to reproduce every field this package does
	// not model, and re-serialising the decoded form would quietly drop them.
	indexRaw []byte

	mu   sync.Mutex
	docs map[string]*Doc
}

// StatusError is a non-200 answer from a hub.
type StatusError struct {
	Status int
	URL    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("vex: %s: unexpected status %d", e.URL, e.Status)
}

// Retryable reports whether repeating the request could plausibly succeed. A
// 404 is the common case here -- a hub that simply has no document for this
// product -- and retrying it three times only makes the scan slower.
func (e *StatusError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// Open fetches a hub's index.
//
// The location may be a GitHub repository URL, a raw base URL, or a local
// directory. A GitHub URL is rewritten to raw.githubusercontent.com, which is
// what makes `--vexhub https://github.com/rancher/vexhub` -- the thing a reader
// would paste -- work without them having to know the raw form.
//
// A deliberate deviation from the VEX Repository spec: the spec distributes a
// hub as the tarball named in vex-repository.json. rancher/vexhub's index is
// 208 KB and a scan needs one or two documents out of it, against a ~30 MB
// archive. Fetching the index and then only the documents actually wanted is
// dramatically cheaper. The tarball transport is worth adding if a hub turns up
// that does not serve its files individually; none does today.
func Open(ctx context.Context, location string) (*Hub, error) {
	h := &Hub{URL: location, HTTP: &http.Client{Timeout: 30 * time.Second}}

	base, local, err := resolveBase(location)
	if err != nil {
		return nil, err
	}
	h.base, h.local = base, local

	raw, err := h.fetch(ctx, "index.json")
	if err != nil {
		return nil, fmt.Errorf("vex: %s: read index: %w", location, err)
	}
	var idx struct {
		Packages []struct {
			ID       string `json:"id"`
			Location string `json:"location"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("vex: %s: parse index: %w", location, err)
	}
	h.index = make(map[string]string, len(idx.Packages))
	for _, p := range idx.Packages {
		if p.ID == "" || p.Location == "" {
			continue
		}
		// Index keys are percent-encoded and the @id inside the document they
		// point at is not, so both go through the same canonicalization.
		h.index[canonicalProduct(p.ID)] = p.Location
	}
	if len(h.index) == 0 {
		return nil, fmt.Errorf("vex: %s: index lists no packages", location)
	}
	h.indexRaw = raw
	h.docs = make(map[string]*Doc)
	return h, nil
}

// Size reports how many products the hub indexes, for the log line that tells a
// reader the hub was actually read.
func (h *Hub) Size() int { return len(h.index) }

// IndexRaw is index.json as the hub published it.
func (h *Hub) IndexRaw() []byte { return h.indexRaw }

// Location is where the hub files a product's document, relative to its root,
// matching the product the same way Lookup does.
func (h *Hub) Location(product string) (string, bool) {
	loc, ok := h.index[canonicalProduct(product)]
	return loc, ok
}

// Raw reads one file out of the hub verbatim, by a location the index gave.
//
// It exists for the writer in internal/vexpr, which merges into an existing
// document and must reproduce every field OpenVEX allows -- including the ones
// Doc does not model. Lookup's parsed form cannot do that, so this returns the
// bytes. A file the hub does not have is ok=false rather than an error: the
// caller's next step for "no document yet" is to start one.
func (h *Hub) Raw(ctx context.Context, loc string) ([]byte, bool, error) {
	b, err := h.fetch(ctx, loc)
	if err == nil {
		return b, true, nil
	}
	var se *StatusError
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		return nil, false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("vex: %s: %s: %w", h.URL, loc, err)
}

// Lookup returns the document covering a product. The bool is false when the
// hub has no document for it, which is the ordinary case and not an error --
// a hub covers one vendor's artifacts, and most scans are of something else.
func (h *Hub) Lookup(ctx context.Context, product string) (*Doc, bool, error) {
	if product == "" {
		return nil, false, nil
	}
	loc, ok := h.index[canonicalProduct(product)]
	if !ok {
		return nil, false, nil
	}

	h.mu.Lock()
	doc, cached := h.docs[loc]
	h.mu.Unlock()
	if cached {
		return doc, doc != nil, nil
	}

	raw, err := h.fetch(ctx, loc)
	if err != nil {
		return nil, false, fmt.Errorf("vex: %s: %w", product, err)
	}
	doc, err = ParseDoc(raw)
	if err != nil {
		return nil, false, fmt.Errorf("vex: %s: %w", product, err)
	}

	h.mu.Lock()
	h.docs[loc] = doc
	h.mu.Unlock()
	return doc, true, nil
}

// resolveBase turns what the user typed into a root that locations hang off.
func resolveBase(location string) (base string, local bool, err error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return "", false, errors.New("vex: empty hub location")
	}
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		u, err := url.Parse(location)
		if err != nil {
			return "", false, fmt.Errorf("vex: %s: %w", location, err)
		}
		if strings.EqualFold(u.Host, "github.com") {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) < 2 {
				return "", false, fmt.Errorf("vex: %s: not an owner/repo URL", location)
			}
			// HEAD rather than main: a hub is free to use any default branch,
			// and raw.githubusercontent.com resolves HEAD to whichever it is.
			return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/HEAD/", parts[0], parts[1]), false, nil
		}
		return strings.TrimSuffix(u.String(), "/") + "/", false, nil
	}
	abs, err := filepath.Abs(location)
	if err != nil {
		return "", false, fmt.Errorf("vex: %s: %w", location, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", false, fmt.Errorf("vex: %s: %w", location, err)
	}
	if !info.IsDir() {
		return "", false, fmt.Errorf("vex: %s: not a directory", location)
	}
	return abs, true, nil
}

// fetch reads one file out of the hub, by a location relative to its root.
func (h *Hub) fetch(ctx context.Context, loc string) ([]byte, error) {
	loc = strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(loc, "/")), "/")
	if h.local {
		return os.ReadFile(filepath.Join(h.base, filepath.FromSlash(loc)))
	}

	var body []byte
	err := h.retry(ctx, func() error {
		var err error
		body, err = h.get(ctx, h.base+loc)
		return err
	})
	return body, err
}

func (h *Hub) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	client := h.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, &StatusError{Status: resp.StatusCode, URL: endpoint}
	}
	return io.ReadAll(resp.Body)
}

// retry runs fn up to three times, backing off a second per attempt, matching
// osv.Client.retry. A non-retryable status fails immediately.
func (h *Hub) retry(ctx context.Context, fn func() error) error {
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
