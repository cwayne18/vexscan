package triage

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The real feed opens with a comment line carrying the score date, then a
// column header, then the rows.
const epssHeader = "#model_version:v2026.06.15,score_date:2026-08-04T12:00:14Z\ncve,epss,percentile\n"

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const kevJSON = `{
  "catalogVersion": "2026.08.03",
  "vulnerabilities": [
    {"cveID":"CVE-2020-8559","dateAdded":"2021-11-03","dueDate":"2022-05-03","knownRansomwareCampaignUse":"Unknown"},
    {"cveID":"CVE-2017-5638","dateAdded":"2021-11-03","dueDate":"2021-11-17","knownRansomwareCampaignUse":"Known"}
  ]
}`

// feeds is a stand-in for both upstreams, counting what was actually fetched so
// a test can prove the cache did its job.
type feeds struct {
	srv      *httptest.Server
	epssHits int32
	kevHits  int32
	epssBody []byte
	kevBody  string
	kevETag  string
	dated    string
}

func newFeeds(t *testing.T, rows string) *feeds {
	t.Helper()
	f := &feeds{
		epssBody: gzipped(t, epssHeader+rows),
		kevBody:  kevJSON,
		kevETag:  `"kev-v1"`,
		dated:    "epss_scores-2026-08-04.csv.gz",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/epss_scores-current.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, f.dated, http.StatusFound)
	})
	mux.HandleFunc("/"+f.dated, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.epssHits, 1)
		w.Write(f.epssBody)
	})
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.kevHits, 1)
		w.Header().Set("ETag", f.kevETag)
		if r.Header.Get("If-None-Match") == f.kevETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fmt.Fprint(w, f.kevBody)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *feeds) loader(dir string) *Loader {
	l := New()
	l.Dir = dir
	l.EPSSURL = f.srv.URL + "/epss_scores-current.csv.gz"
	l.KEVURL = f.srv.URL + "/kev.json"
	return l
}

const rows = "CVE-2011-3389,0.73327,0.99408\nCVE-2020-8559,0.00234,0.45000\nCVE-2026-99999,0.00001,0.00100\n"

func TestBothFeedsLoad(t *testing.T) {
	f := newFeeds(t, rows)
	d := f.loader(t.TempDir()).Load(context.Background(), nil)

	if d.EPSSError != "" || d.KEVError != "" {
		t.Fatalf("errors: epss=%q kev=%q", d.EPSSError, d.KEVError)
	}
	if got := len(d.EPSS); got != 3 {
		t.Errorf("loaded %d scores, want 3", got)
	}
	if got := len(d.KEV); got != 2 {
		t.Errorf("loaded %d KEV entries, want 2", got)
	}
}

// The date is a fact about the data, not about when it was read. A run in
// October against an August feed must say August.
func TestTheScoreDateComesFromTheFeedAndNotTheClock(t *testing.T) {
	f := newFeeds(t, rows)
	d := f.loader(t.TempDir()).Load(context.Background(), nil)

	if d.EPSSDate != "2026-08-04" {
		t.Errorf("EPSSDate = %q, want 2026-08-04", d.EPSSDate)
	}
	if d.KEVDate != "2026.08.03" {
		t.Errorf("KEVDate = %q, want 2026.08.03", d.KEVDate)
	}
}

// One bad line in 355,000 must not cost the other 354,999.
func TestAMalformedRowDoesNotCostTheRest(t *testing.T) {
	bad := "CVE-2011-3389,0.73327,0.99408\nnot a row at all\nCVE-2020-8559,broken,0.45\nCVE-2017-5638,0.5,0.9\n"
	scores, date, err := parseEPSS(gzipped(t, epssHeader+bad), nil)
	if err != nil {
		t.Fatal(err)
	}
	if date != "2026-08-04" {
		t.Errorf("date = %q", date)
	}
	if len(scores) != 2 {
		t.Errorf("kept %d rows, want 2 (the two parseable ones): %v", len(scores), scores)
	}
	if _, ok := scores["CVE-2020-8559"]; ok {
		t.Error("kept a row whose score did not parse; a garbled number must not become a percentile")
	}
}

// The column header is not a CVE and must not become one.
func TestTheColumnHeaderIsNotAFinding(t *testing.T) {
	scores, _, err := parseEPSS(gzipped(t, epssHeader+rows), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scores["cve"]; ok {
		t.Error("parsed the column header as a row")
	}
}

func TestOnlyTheWantedScoresAreKept(t *testing.T) {
	want := map[string]bool{"CVE-2011-3389": true}
	scores, _, err := parseEPSS(gzipped(t, epssHeader+rows), want)
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 1 {
		t.Fatalf("kept %d scores, want 1: %v", len(scores), scores)
	}
	if scores["CVE-2011-3389"].Percentile != 0.99408 {
		t.Errorf("percentile = %v, want 0.99408", scores["CVE-2011-3389"].Percentile)
	}
}

// A dated feed cannot change, so a second run the same day must not download
// it again. This is the whole reason the loader reads the redirect.
func TestTheDatedFeedIsNotDownloadedTwice(t *testing.T) {
	f := newFeeds(t, rows)
	dir := t.TempDir()

	f.loader(dir).Load(context.Background(), nil)
	if got := atomic.LoadInt32(&f.epssHits); got != 1 {
		t.Fatalf("first run made %d EPSS downloads, want 1", got)
	}
	d := f.loader(dir).Load(context.Background(), nil)
	if got := atomic.LoadInt32(&f.epssHits); got != 1 {
		t.Errorf("second run made %d EPSS downloads total, want 1 -- the cache did not answer", got)
	}
	if len(d.EPSS) != 3 || d.EPSSDate != "2026-08-04" {
		t.Errorf("the cached read lost data: %d scores, date %q", len(d.EPSS), d.EPSSDate)
	}
	if d.EPSSStale {
		t.Error("a fresh cache hit was reported as stale")
	}
}

// Yesterday's percentiles beat none -- as long as the reader is told they are
// yesterday's.
func TestAnUnreachableEPSSFeedFallsBackToTheCachedCopy(t *testing.T) {
	f := newFeeds(t, rows)
	dir := t.TempDir()
	f.loader(dir).Load(context.Background(), nil)

	l := f.loader(dir)
	l.EPSSURL = "http://127.0.0.1:1/epss_scores-current.csv.gz" // nothing listening
	d := l.Load(context.Background(), nil)

	if d.EPSSError != "" {
		t.Fatalf("EPSSError = %q, want the cached copy to be used instead", d.EPSSError)
	}
	if !d.EPSSStale {
		t.Error("used the cache without saying it was stale")
	}
	if d.EPSSDate != "2026-08-04" || len(d.EPSS) != 3 {
		t.Errorf("stale load gave date %q and %d scores", d.EPSSDate, len(d.EPSS))
	}
}

// No feed and no cache must be an error the report can print, never an empty
// map that reads as "nothing is being exploited".
func TestNoFeedAndNoCacheIsAnErrorNotASilence(t *testing.T) {
	f := newFeeds(t, rows)
	l := f.loader(t.TempDir())
	l.EPSSURL = "http://127.0.0.1:1/epss_scores-current.csv.gz"
	l.KEVURL = "http://127.0.0.1:1/kev.json"
	d := l.Load(context.Background(), nil)

	if d.EPSSError == "" {
		t.Error("an unreachable EPSS feed with no cache reported no error")
	}
	if d.KEVError == "" {
		t.Error("an unreachable KEV feed with no cache reported no error")
	}
	if d.EPSS == nil || d.KEV == nil {
		t.Error("Load returned nil maps; a caller must be able to look up into a failed load")
	}
}

func TestKEVIsRevalidatedRatherThanRedownloaded(t *testing.T) {
	f := newFeeds(t, rows)
	dir := t.TempDir()

	first := f.loader(dir).Load(context.Background(), nil)
	if len(first.KEV) != 2 {
		t.Fatalf("first load got %d KEV entries", len(first.KEV))
	}
	second := f.loader(dir).Load(context.Background(), nil)
	if len(second.KEV) != 2 || second.KEVDate != "2026.08.03" {
		t.Errorf("the 304 path lost the catalog: %d entries, version %q", len(second.KEV), second.KEVDate)
	}
	if second.KEVStale {
		t.Error("a 304 is the server confirming the copy is current, not a stale read")
	}
	if got := atomic.LoadInt32(&f.kevHits); got != 2 {
		t.Errorf("KEV was requested %d times, want 2 (the second a conditional GET)", got)
	}
}

// A 304 for a payload that is no longer on disk must re-fetch, not fail.
func TestA304WithoutThePayloadRefetches(t *testing.T) {
	f := newFeeds(t, rows)
	dir := t.TempDir()
	f.loader(dir).Load(context.Background(), nil)

	if err := os.Remove(filepath.Join(dir, kevFile)); err != nil {
		t.Fatal(err)
	}
	d := f.loader(dir).Load(context.Background(), nil)
	if d.KEVError != "" || len(d.KEV) != 2 {
		t.Errorf("KEVError = %q, %d entries; want a clean re-fetch", d.KEVError, len(d.KEV))
	}
}

func TestAnUnreachableKEVFallsBackToTheCachedCatalog(t *testing.T) {
	f := newFeeds(t, rows)
	dir := t.TempDir()
	f.loader(dir).Load(context.Background(), nil)

	l := f.loader(dir)
	l.KEVURL = "http://127.0.0.1:1/kev.json"
	d := l.Load(context.Background(), nil)

	if d.KEVError != "" {
		t.Fatalf("KEVError = %q, want the cached catalog to be used", d.KEVError)
	}
	if !d.KEVStale {
		t.Error("used the cached catalog without saying it was stale")
	}
	if len(d.KEV) != 2 {
		t.Errorf("stale load gave %d entries, want 2", len(d.KEV))
	}
}

// The field is a string with three states, and only one of them is a yes.
func TestRansomwareIsOnlyTheAffirmative(t *testing.T) {
	entries, version, err := parseKEV([]byte(kevJSON))
	if err != nil {
		t.Fatal(err)
	}
	if version != "2026.08.03" {
		t.Errorf("version = %q", version)
	}
	if entries["CVE-2020-8559"].Ransomware {
		t.Error(`"Unknown" was read as a ransomware campaign; it means nobody has established it either way`)
	}
	if !entries["CVE-2017-5638"].Ransomware {
		t.Error(`"Known" was not read as a ransomware campaign`)
	}
	if entries["CVE-2017-5638"].DueDate != "2021-11-17" {
		t.Errorf("DueDate = %q", entries["CVE-2017-5638"].DueDate)
	}
}

// A 2.5 MB file a day would otherwise accumulate forever.
func TestPruningKeepsTheNewestFeeds(t *testing.T) {
	dir := t.TempDir()
	c := cache{dir: dir}
	for _, day := range []string{"01", "02", "03", "04"} {
		if err := c.write("epss_scores-2026-08-"+day+".csv.gz", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	c.pruneEPSS(2)

	left := c.datedEPSS()
	if len(left) != 2 {
		t.Fatalf("kept %v, want 2 files", left)
	}
	if left[0] != "epss_scores-2026-08-03.csv.gz" || left[1] != "epss_scores-2026-08-04.csv.gz" {
		t.Errorf("kept %v, want the two newest", left)
	}
}

// Scored is not a synonym for a nonzero score. "0.00004 probability" and "no
// CVE, so no probability exists" must not render the same way.
func TestLookupDistinguishesUnscoredFromZero(t *testing.T) {
	d := &Data{
		EPSS: map[string]Score{"CVE-2020-0001": {EPSS: 0, Percentile: 0}},
		KEV:  map[string]KEVEntry{},
	}
	if p := d.Lookup("CVE-2020-0001"); !p.Scored {
		t.Error("a genuine zero score was reported as unscored")
	}
	p := d.Lookup("CVE-2020-9999")
	if p.Scored {
		t.Error("an absent CVE was reported as scored")
	}
	if p.Known() {
		t.Error("an absent CVE was reported as known")
	}
}

// The KEV entry handed out must be a copy, or a caller could edit the catalog
// through it.
func TestLookupDoesNotHandOutTheCatalog(t *testing.T) {
	d := &Data{
		EPSS: map[string]Score{},
		KEV:  map[string]KEVEntry{"CVE-2017-5638": {DateAdded: "2021-11-03"}},
	}
	p := d.Lookup("CVE-2017-5638")
	p.KEV.DateAdded = "tampered"
	if d.KEV["CVE-2017-5638"].DateAdded != "2021-11-03" {
		t.Error("Lookup let a caller mutate the catalog")
	}
}

// A mirror serving an HTML error page must not be parsed as a feed.
func TestANonSuccessStatusIsAFailureNotAFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>go away</html>", http.StatusForbidden)
	}))
	defer srv.Close()

	l := New()
	l.Dir = t.TempDir()
	l.EPSSURL = srv.URL + "/epss_scores-current.csv.gz"
	l.KEVURL = srv.URL + "/kev.json"
	d := l.Load(context.Background(), nil)

	if d.KEVError == "" || !strings.Contains(d.KEVError, "403") {
		t.Errorf("KEVError = %q, want it to name the status", d.KEVError)
	}
	if d.EPSSError == "" {
		t.Error("a 403 EPSS feed reported no error")
	}
}
