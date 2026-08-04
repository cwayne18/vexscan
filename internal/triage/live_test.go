package triage

import (
	"context"
	"os"
	"testing"
)

// TestLiveFeeds checks the real EPSS mirror and the real KEV catalog. Set
// VEXSCAN_LIVE_TRIAGE=1 to run it.
//
// It is opt-in because it needs the network, and it exists because the two
// assumptions this package is built on are assumptions about somebody else's
// server. EPSS's -current URL redirecting to a dated filename is what makes a
// cache hit free; KEV serving an ETag is what makes revalidation free. If
// either changes, every unit test here still passes -- they are served by an
// httptest.Server that does what this code expects -- and the tool quietly
// starts downloading 4 MB on every scan. Only asking the real hosts notices.
//
//	VEXSCAN_LIVE_TRIAGE=1 go test ./internal/triage/ -run TestLive -v
func TestLiveFeeds(t *testing.T) {
	if os.Getenv("VEXSCAN_LIVE_TRIAGE") == "" {
		t.Skip("set VEXSCAN_LIVE_TRIAGE=1 to query the real EPSS and KEV feeds")
	}
	l := New()
	l.Dir = t.TempDir()
	l.Logf = t.Logf

	// CVE-2011-3389 is BEAST: ancient, universally present, and certain to be
	// scored. CVE-2017-5638 is Struts, which has been in KEV since the day the
	// catalog was published.
	want := map[string]bool{"CVE-2011-3389": true, "CVE-2017-5638": true}
	d := l.Load(context.Background(), want)

	if d.EPSSError != "" {
		t.Errorf("EPSS: %s", d.EPSSError)
	}
	if d.KEVError != "" {
		t.Errorf("KEV: %s", d.KEVError)
	}
	if d.EPSSStale || d.KEVStale {
		t.Errorf("a first load into an empty directory reported stale data: epss=%v kev=%v", d.EPSSStale, d.KEVStale)
	}
	if d.EPSSDate == "" {
		t.Error("no score date; the feed's header comment or the dated redirect has changed shape")
	}
	if d.KEVDate == "" {
		t.Error("no catalog version")
	}

	p := d.Lookup("CVE-2011-3389")
	if !p.Scored {
		t.Error("CVE-2011-3389 is not scored; the CSV columns have changed")
	}
	t.Logf("EPSS %s: CVE-2011-3389 epss=%v percentile=%v", d.EPSSDate, p.EPSS, p.Percentile)

	if k := d.Lookup("CVE-2017-5638"); k.KEV == nil {
		t.Error("CVE-2017-5638 is not in KEV; the catalog's field names have changed")
	} else {
		t.Logf("KEV %s: CVE-2017-5638 added %s, due %s", d.KEVDate, k.KEV.DateAdded, k.KEV.DueDate)
	}

	// The second load must answer entirely from disk for EPSS and with a 304
	// for KEV. Nothing here can see the byte count, but a stale flag or a lost
	// date would mean the cache round-trip is broken.
	again := New()
	again.Dir = l.Dir
	again.Logf = t.Logf
	d2 := again.Load(context.Background(), want)
	if d2.EPSSDate != d.EPSSDate || d2.KEVDate != d.KEVDate {
		t.Errorf("second load disagreed with the first: epss %q vs %q, kev %q vs %q",
			d2.EPSSDate, d.EPSSDate, d2.KEVDate, d.KEVDate)
	}
	if !d2.Lookup("CVE-2011-3389").Scored {
		t.Error("the cached feed lost its scores")
	}
}
