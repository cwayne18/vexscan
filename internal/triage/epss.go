package triage

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// epssKeep is how many dated feeds to leave on disk. A 2.5 MB file a day would
// otherwise accumulate forever. Two, so that a run whose network is down still
// has yesterday's after today's has been fetched and something goes wrong with
// it.
const epssKeep = 2

// epssName matches the dated filenames the feed publishes, which is how the
// score date is known before a single byte of the payload is downloaded.
var epssName = regexp.MustCompile(`^epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$`)

// scoreDate pulls the date out of the "#model_version:v...,score_date:..."
// comment the feed opens with.
var scoreDate = regexp.MustCompile(`score_date:(\d{4}-\d{2}-\d{2})`)

// loadEPSS returns the scores for want, the feed's score date, and whether the
// data came off disk because the network could not be reached.
//
// The strategy turns on one detail of how EPSS is published: the -current URL
// is a 302 to a dated filename. A HEAD costs zero bytes and yields that name,
// and a dated file can never change, so a cache hit needs no revalidation and
// no download at all. That makes the common case -- several scans a day -- one
// redirect and nothing else.
func (l *Loader) loadEPSS(ctx context.Context, c cache, want map[string]bool) (map[string]Score, string, bool, error) {
	name, dated := l.currentEPSS(ctx)
	if name != "" {
		if body, err := c.read(name); err == nil {
			scores, date, err := parseEPSS(body, want)
			if err == nil {
				return scores, orElse(date, dated), false, nil
			}
			l.logf("triage: cached EPSS feed %s is unreadable (%v); downloading again", name, err)
		}
	}

	target := l.epssURL()
	if name != "" {
		target = resolve(target, name)
	}
	body, _, _, err := download(ctx, l.client(), target, validators{})
	if err == nil {
		var scores map[string]Score
		var date string
		if scores, date, err = parseEPSS(body, want); err == nil {
			if name == "" {
				// The HEAD did not redirect, so the payload's own header is the
				// only thing that knows which day this is.
				name = "epss_scores-" + orElse(date, "undated") + ".csv.gz"
			}
			if err := c.write(name, body); err != nil {
				l.logf("triage: could not cache the EPSS feed: %v", err)
			}
			c.pruneEPSS(epssKeep)
			return scores, orElse(date, dated), false, nil
		}
	}

	// Nothing usable from the network. Yesterday's percentiles beat none, as
	// long as the reader is told which day they are.
	scores, date, cacheErr := c.newestEPSS(want)
	if cacheErr != nil {
		return nil, "", false, err
	}
	return scores, date, true, nil
}

func (l *Loader) epssURL() string { return orElse(l.EPSSURL, EPSSURL) }

// currentEPSS asks the -current URL where it points, without following. It
// returns the dated filename and the date in it, or empty strings if anything
// at all went wrong -- every caller has a path that copes.
func (l *Loader) currentEPSS(ctx context.Context) (name, date string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, l.epssURL(), nil)
	if err != nil {
		return "", ""
	}
	// A copy, so a caller's client is not mutated. http.Client is a plain
	// struct of settings; the transport it points at is shared, which is what
	// we want.
	noFollow := *l.client()
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := noFollow.Do(req)
	if err != nil {
		return "", ""
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", ""
	}
	name = lastSegment(loc)
	m := epssName.FindStringSubmatch(name)
	if m == nil {
		return "", ""
	}
	return name, m[1]
}

// parseEPSS reads the gzipped CSV, keeping only the CVEs in want (nil keeps
// all), and returns the score date from the header comment.
//
// Split by hand rather than through encoding/csv: the feed is three unquoted
// columns over 355,000 rows, and a hand split is both faster and easier to make
// forgiving. A row that does not parse is skipped rather than fatal -- one bad
// line must not cost the other 355,093.
func parseEPSS(gzipped []byte, want map[string]bool) (map[string]Score, string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return nil, "", fmt.Errorf("epss: %w", err)
	}
	defer zr.Close()

	scores := map[string]Score{}
	var date string
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if m := scoreDate.FindStringSubmatch(line); m != nil {
				date = m[1]
			}
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		cve := strings.TrimSpace(fields[0])
		if !strings.HasPrefix(cve, "CVE-") { // the column header, and nothing else
			continue
		}
		if want != nil && !want[cve] {
			continue
		}
		epss, err1 := strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		scores[cve] = Score{EPSS: epss, Percentile: pct}
	}
	if err := sc.Err(); err != nil {
		return nil, "", fmt.Errorf("epss: %w", err)
	}
	return scores, date, nil
}

// newestEPSS reads the most recent dated feed left on disk. The filenames sort
// lexically into date order, which is the one thing an ISO date is for.
func (c cache) newestEPSS(want map[string]bool) (map[string]Score, string, error) {
	names := c.datedEPSS()
	if len(names) == 0 {
		return nil, "", errors.New("no cached EPSS feed")
	}
	name := names[len(names)-1]
	body, err := c.read(name)
	if err != nil {
		return nil, "", err
	}
	scores, date, err := parseEPSS(body, want)
	if err != nil {
		return nil, "", err
	}
	if date == "" {
		date = epssName.FindStringSubmatch(name)[1]
	}
	return scores, date, nil
}

// datedEPSS lists the cached feeds, oldest first.
func (c cache) datedEPSS() []string {
	if c.dir == "" {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if epssName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// pruneEPSS keeps the newest keep feeds and deletes the rest.
func (c cache) pruneEPSS(keep int) {
	names := c.datedEPSS()
	for i := 0; i < len(names)-keep; i++ {
		os.Remove(c.path(names[i]))
	}
}

// resolve replaces the last segment of a URL, which is what a relative
// Location header amounts to here.
func resolve(base, name string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	ref, err := url.Parse(name)
	if err != nil {
		return base
	}
	return u.ResolveReference(ref).String()
}

// lastSegment is the final component of a URL or path.
func lastSegment(loc string) string {
	if u, err := url.Parse(loc); err == nil && u.Path != "" {
		loc = u.Path
	}
	return filepath.Base(loc)
}

func orElse(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}
