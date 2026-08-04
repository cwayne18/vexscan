// Package triage answers a question a severity rating cannot: is anyone
// actually exploiting this?
//
// A CVSS score describes how bad a vulnerability would be if it were exploited.
// It is computed once, from the shape of the flaw, and it never moves. EPSS
// estimates the probability that exploitation will be observed somewhere in the
// next thirty days, and it moves daily. CISA's KEV catalog is narrower and
// harder: a list of vulnerabilities exploitation of which has actually been
// seen. The three disagree constantly -- on debian:12 the finding most likely
// to be exploited is one nobody ever assigned a severity to -- which is the
// whole reason this package exists.
//
// Two things it deliberately does not do. It does not combine the numbers into
// a single priority score: internal/cvss already documents its Rank as a
// display order and not a comparison order, and inventing f(cvss, epss, kev)
// here would be this tool asserting a risk model it has no basis for. And it
// does not treat a missing score as a low one. Both feeds are keyed by CVE,
// vexscan's findings frequently are not, and an advisory that never got a CVE
// is unscoreable rather than safe.
package triage

import (
	"context"
	"net/http"
	"time"
)

// Feed URLs. Both are public, unauthenticated static files.
const (
	// EPSSURL redirects to a dated filename, which is load-bearing: see epss.go.
	EPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Score is one row of the EPSS feed.
//
// Percentile is the number worth showing a human. A raw EPSS of 0.03 reads as
// "negligible" and is in fact the 87th percentile of every scored CVE in
// existence, because the distribution is extremely skewed.
type Score struct {
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// KEVEntry is one entry of CISA's catalog, reduced to the fields that change
// what a reader does.
type KEVEntry struct {
	DateAdded string `json:"date_added,omitempty"`
	// DueDate is the remediation deadline the directive sets for US federal
	// civilian agencies. It binds nobody else, and is here because it is a
	// useful sense of how urgently CISA views it.
	DueDate    string `json:"due_date,omitempty"`
	Ransomware bool   `json:"ransomware,omitempty"`
}

// Priority is what triage learned about a single finding.
//
// Scored is separate from a zero EPSS on purpose. "This CVE has a 0.00004
// probability" and "this advisory has no CVE, so no probability exists" are
// different statements, and only one of them is reassuring.
type Priority struct {
	// CVE is the id the lookup matched on, which for a Go finding is usually
	// not the id printed in the row -- GO-2025-3547 is scored as CVE-2024-7598.
	// Recorded so the reader can check the join rather than trust it.
	CVE        string    `json:"cve,omitempty"`
	Scored     bool      `json:"scored"`
	EPSS       float64   `json:"epss,omitempty"`
	Percentile float64   `json:"percentile,omitempty"`
	KEV        *KEVEntry `json:"kev,omitempty"`
}

// Known reports whether triage found anything at all about this finding. A
// Priority that is neither scored nor in KEV is a record of having looked.
func (p *Priority) Known() bool {
	return p != nil && (p.Scored || p.KEV != nil)
}

// Data is both feeds, and an account of any part of them that could not be
// read.
//
// A failed feed is reported rather than returned as an error, because the
// caller's response to it is not to abort: an unreachable EPSS mirror leaves
// the findings in the order they were already in. What it must never do is
// leave the report looking triaged when it is not, which is what the Error and
// Stale fields are for.
type Data struct {
	EPSS map[string]Score
	KEV  map[string]KEVEntry

	// EPSSDate is the feed's own score_date and KEVDate its catalogVersion --
	// read out of the payload, never from the clock. A cached score is a claim
	// about a day, and a CI log read next month must not be able to pretend
	// otherwise.
	EPSSDate string
	KEVDate  string

	// Stale means the network could not be reached and a previously downloaded
	// copy was used. Not an error: a yesterday-old percentile is vastly more
	// useful than none. It is still said out loud.
	EPSSStale bool
	KEVStale  bool

	EPSSError string
	KEVError  string
}

// Lookup returns what is known about one bare CVE id.
func (d *Data) Lookup(cve string) Priority {
	p := Priority{CVE: cve}
	if s, ok := d.EPSS[cve]; ok {
		p.Scored = true
		p.EPSS = s.EPSS
		p.Percentile = s.Percentile
	}
	if k, ok := d.KEV[cve]; ok {
		entry := k
		p.KEV = &entry
	}
	return p
}

// Loader fetches and caches the feeds. The zero value is not usable; call New.
type Loader struct {
	// Dir is where downloaded feeds live. Empty means the default cache
	// location, resolved by cacheDir.
	Dir     string
	HTTP    *http.Client
	EPSSURL string
	KEVURL  string
	Logf    func(string, ...any)
}

// New returns a Loader with the real feeds and the tree's usual timeout.
func New() *Loader {
	return &Loader{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		EPSSURL: EPSSURL,
		KEVURL:  KEVURL,
	}
}

func (l *Loader) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
	}
}

func (l *Loader) client() *http.Client {
	if l.HTTP != nil {
		return l.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Load reads both feeds, keeping only the CVEs in want. A nil want keeps
// everything, which is for tests; a real scan cares about a few dozen ids out
// of 355,000 and there is no reason to hold the rest.
//
// It never returns nil, and never returns an error: a feed that could not be
// read leaves an empty map and a filled-in Error, and the caller carries on.
func (l *Loader) Load(ctx context.Context, want map[string]bool) *Data {
	d := &Data{EPSS: map[string]Score{}, KEV: map[string]KEVEntry{}}
	c := cache{dir: l.dir()}

	scores, date, stale, err := l.loadEPSS(ctx, c, want)
	if err != nil {
		d.EPSSError = err.Error()
		l.logf("triage: EPSS unavailable: %v", err)
	} else {
		d.EPSS, d.EPSSDate, d.EPSSStale = scores, date, stale
		if stale {
			l.logf("triage: EPSS feed unreachable; using the cached copy from %s", date)
		}
	}

	entries, kevDate, kevStale, err := l.loadKEV(ctx, c)
	if err != nil {
		d.KEVError = err.Error()
		l.logf("triage: KEV unavailable: %v", err)
	} else {
		d.KEV, d.KEVDate, d.KEVStale = entries, kevDate, kevStale
		if kevStale {
			l.logf("triage: KEV feed unreachable; using the cached catalog %s", kevDate)
		}
	}
	return d
}
