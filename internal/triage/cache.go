package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cwayne18/vexscan/internal/envx"
)

// maxBody caps a feed download. EPSS is 2.5 MB compressed and KEV 1.6 MB; the
// limit is generous enough to survive years of growth and small enough that a
// misconfigured proxy serving something enormous cannot exhaust memory.
const maxBody = 128 << 20

// cache is a directory of downloaded feeds.
//
// Nothing else in this tree caches to disk, so the rules are worth stating.
// The cache is an optimisation and never a source of truth about freshness: a
// payload is only ever used either because the server said 304, or because the
// server could not be reached at all, and the second case is reported to the
// reader. Every failure to read or write it is survivable -- a cache that is
// unwritable makes vexscan slower, not wrong.
type cache struct{ dir string }

// dir resolves where feeds are stored: VEXSCAN_TRIAGE_CACHE, else the
// platform cache directory.
//
// envx.Get is right here, unlike in pager.go: an empty VEXSCAN_TRIAGE_CACHE is
// a variable someone forgot to fill in, not a request to disable caching.
func (l *Loader) dir() string {
	if l.Dir != "" {
		return l.Dir
	}
	return cacheDir()
}

func cacheDir() string {
	if d := envx.Get("TRIAGE_CACHE"); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil {
		// No HOME and no XDG_CACHE_HOME. Downloading afresh every run is worse
		// than a temp directory and better than failing.
		base = os.TempDir()
	}
	return filepath.Join(base, "vexscan", "triage")
}

func (c cache) path(name string) string { return filepath.Join(c.dir, name) }

// read returns a cached payload, or an error if there is not one.
func (c cache) read(name string) ([]byte, error) {
	if c.dir == "" {
		return nil, errors.New("no cache directory")
	}
	return os.ReadFile(c.path(name))
}

// write stores a payload. A failure is logged by the caller and otherwise
// ignored: the download already succeeded, so the run is fine.
func (c cache) write(name string, body []byte) error {
	if c.dir == "" {
		return errors.New("no cache directory")
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	// Written beside the target and renamed, so a killed process cannot leave a
	// half-written feed that the next run reads as complete.
	tmp, err := os.CreateTemp(c.dir, name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path(name))
}

// validators are the HTTP cache validators for a payload, stored beside it.
type validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

func (c cache) readValidators(name string) validators {
	var v validators
	b, err := c.read(name + ".meta")
	if err != nil {
		return v
	}
	_ = json.Unmarshal(b, &v) // a corrupt sidecar just means an unconditional GET
	return v
}

func (c cache) writeValidators(name string, v validators) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.write(name+".meta", b)
}

// download performs a GET, sending v as conditional headers when it has any.
//
// A 304 returns a nil body and notModified true. Any non-2xx status is an
// error, so a mirror serving an HTML error page cannot be parsed as a feed.
func download(ctx context.Context, hc *http.Client, url string, v validators) (body []byte, got validators, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, got, false, err
	}
	if v.ETag != "" {
		req.Header.Set("If-None-Match", v.ETag)
	}
	if v.LastModified != "" {
		req.Header.Set("If-Modified-Since", v.LastModified)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, got, false, err
	}
	defer resp.Body.Close()

	got = validators{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil, got, true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, got, false, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, got, false, fmt.Errorf("%s: %w", url, err)
	}
	return body, got, false, nil
}
