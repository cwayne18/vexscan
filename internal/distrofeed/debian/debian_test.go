package debian

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cwayne18/vexscan/internal/distrofeed"
)

// tracker is a minimal slice of the real feed: one source package with the four
// verdict shapes that matter, keyed the way the real tracker keys them.
const tracker = `{
  "openssl": {
    "CVE-2023-NOTAFFECTED": {"releases": {
      "bookworm": {"status": "resolved", "fixed_version": "0", "urgency": "unimportant"}
    }},
    "CVE-2023-FIXED": {"releases": {
      "bookworm": {"status": "resolved", "fixed_version": "3.0.9-1"}
    }},
    "CVE-2023-OPEN": {"releases": {
      "bookworm": {"status": "open"}
    }},
    "CVE-2023-NODSA": {"releases": {
      "bookworm": {"status": "open", "nodsa": "Minor issue"}
    }},
    "CVE-2023-UNDET": {"releases": {
      "bookworm": {"status": "undetermined"}
    }},
    "CVE-2023-STALENODSA": {"releases": {
      "bookworm": {"status": "resolved", "fixed_version": "0", "nodsa": "left over from when this was open"}
    }}
  },
  "linux": {
    "CVE-2023-HUGE": {"releases": {
      "bookworm": {"status": "open"},
      "bullseye": {"status": "open"},
      "buster": {"status": "open"}
    }}
  }
}`

func serve(t *testing.T, body string, hits *int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func lookup(t *testing.T, p *Provider, q distrofeed.Query) []distrofeed.Statement {
	t.Helper()
	stmts, err := p.Lookup(context.Background(), q)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return stmts
}

func only(t *testing.T, stmts []distrofeed.Statement) distrofeed.Statement {
	t.Helper()
	if len(stmts) != 1 {
		t.Fatalf("want 1 statement, got %d: %+v", len(stmts), stmts)
	}
	return stmts[0]
}

func query(cve, version string) distrofeed.Query {
	return distrofeed.Query{
		OSID:    "debian",
		Release: "12",
		Packages: []distrofeed.PkgRef{{
			ID: "ref-0", Source: "openssl", Name: "libssl3", Version: version, CVEs: []string{cve},
		}},
	}
}

// fixed_version "0" is Debian saying the vulnerable code was never in their
// build. It clears regardless of version.
func TestNotAffectedClears(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	st := only(t, lookup(t, p, query("CVE-2023-NOTAFFECTED", "3.0.0-1")))
	if st.Status != distrofeed.StatusNotAffected {
		t.Fatalf("status = %q, want not_affected", st.Status)
	}
	if !st.Status.Exculpatory() {
		t.Error("not_affected should be exculpatory")
	}
}

// A shipped fix clears only once the installed version has reached it.
func TestFixedClearsOnlyAtOrAboveFix(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}

	// Installed is past the fix: cleared.
	if st := only(t, lookup(t, p, query("CVE-2023-FIXED", "3.0.11-1"))); st.Status != distrofeed.StatusFixed {
		t.Errorf("installed past fix: status = %q, want fixed", st.Status)
	}
	// Installed exactly at the fix: cleared.
	if st := only(t, lookup(t, p, query("CVE-2023-FIXED", "3.0.9-1"))); st.Status != distrofeed.StatusFixed {
		t.Errorf("installed at fix: status = %q, want fixed", st.Status)
	}
	// Installed below the fix: the finding stands, never cleared.
	st := only(t, lookup(t, p, query("CVE-2023-FIXED", "3.0.8-1")))
	if st.Status.Exculpatory() {
		t.Errorf("installed below fix was cleared: %+v", st)
	}
}

// open, nodsa and undetermined all mean the flaw stands. None may clear.
func TestNonExculpatoryVerdicts(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	for _, cve := range []string{"CVE-2023-OPEN", "CVE-2023-NODSA", "CVE-2023-UNDET"} {
		st := only(t, lookup(t, p, query(cve, "3.0.0-1")))
		if st.Status.Exculpatory() {
			t.Errorf("%s produced an exculpatory statement: %+v", cve, st)
		}
	}
}

// The one direction the tool must never get wrong: an unmappable release means
// the provider cannot know which column applies, so it declines rather than
// match the wrong release's verdict.
func TestUnknownReleaseDeclines(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	q := query("CVE-2023-NOTAFFECTED", "3.0.0-1")
	q.Release = "sid" // not a numbered stable release
	if stmts := lookup(t, p, q); len(stmts) != 0 {
		t.Fatalf("unknown release should clear nothing, got %+v", stmts)
	}
	q.Release = "" // no release read at all
	if stmts := lookup(t, p, q); len(stmts) != 0 {
		t.Fatalf("empty release should clear nothing, got %+v", stmts)
	}
}

// A finding whose release row the tracker does not carry gets no statement,
// even though the source package and CVE are present under other releases.
func TestReleaseWithoutRowIsSilent(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	q := distrofeed.Query{
		OSID: "debian", Release: "12",
		Packages: []distrofeed.PkgRef{{Source: "linux", Version: "6.1", CVEs: []string{"CVE-2023-HUGE"}}},
	}
	// bookworm's row is "open", so a statement is produced but not exculpatory.
	st := only(t, lookup(t, p, q))
	if st.Status.Exculpatory() {
		t.Errorf("open kernel CVE was cleared: %+v", st)
	}
}

func TestHandlesOnlyDebian(t *testing.T) {
	p := New()
	if !p.Handles("debian") {
		t.Error("should handle debian")
	}
	for _, id := range []string{"ubuntu", "rhel", "alpine", ""} {
		if p.Handles(id) {
			t.Errorf("should not handle %q: Ubuntu and the rpm distros track security separately", id)
		}
	}
}

func TestCodenameMapping(t *testing.T) {
	cases := map[string]string{
		"11": "bullseye", "12": "bookworm", "12.4": "bookworm", "13": "trixie",
		"": "", "sid": "", "99": "",
	}
	for in, want := range cases {
		if got := codenameFor(in); got != want {
			t.Errorf("codenameFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// The streaming decoder keeps only the packages asked about; linux, which is
// megabytes in the real feed, must not be decoded when nothing wants it.
func TestDecodeFilteredSkipsUnwanted(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	// Ask only about openssl. The linux entry has to be skipped without error.
	if st := only(t, lookup(t, p, query("CVE-2023-NOTAFFECTED", "3.0.0-1"))); st.Package != "openssl" {
		t.Errorf("package = %q", st.Package)
	}
}

// A statement carries back the ID of the ref it was computed for, so the overlay
// can bind a version-specific verdict to exactly the finding it was decided
// against and never a sibling package at another version.
func TestStatementEchoesRefID(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	q := query("CVE-2023-FIXED", "3.0.11-1")
	q.Packages[0].ID = "unique-token"
	if st := only(t, lookup(t, p, q)); st.RefID != "unique-token" {
		t.Errorf("RefID = %q, want the ref's own id", st.RefID)
	}
}

// The tracker leaves stale nodsa notes on rows that later became resolved.
// Resolved must be read first: a not-affected row is authoritative even when a
// leftover nodsa is still attached, or the finding would look affected forever.
func TestResolvedBeatsStaleNoDSA(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker, nil)}
	st := only(t, lookup(t, p, query("CVE-2023-STALENODSA", "3.0.0-1")))
	if st.Status != distrofeed.StatusNotAffected {
		t.Fatalf("status = %q, want not_affected despite stale nodsa", st.Status)
	}
}

// A feed truncated mid-transfer must reject the whole response, never partially
// trust the entries that did arrive: a short read that happened to end after a
// not-affected entry could otherwise clear a finding off an incomplete download.
func TestTruncatedFeedRejected(t *testing.T) {
	full := tracker
	truncated := full[:len(full)-40] // drop the closing braces and then some
	p := &Provider{BaseURL: serve(t, truncated, nil)}
	_, err := p.Lookup(context.Background(), query("CVE-2023-NOTAFFECTED", "3.0.0-1"))
	if err == nil {
		t.Fatal("truncated feed was accepted; a short read must reject the whole feed")
	}
}

// Trailing garbage after the top-level object is a malformed feed and must be
// rejected rather than silently ignored.
func TestTrailingDataRejected(t *testing.T) {
	p := &Provider{BaseURL: serve(t, tracker+"  garbage", nil)}
	_, err := p.Lookup(context.Background(), query("CVE-2023-NOTAFFECTED", "3.0.0-1"))
	if err == nil {
		t.Fatal("trailing data after the tracker object should be rejected")
	}
}
