package analyze

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/distrofeed/debian"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// debianTracker is the slice of the security tracker these overlay tests run
// against: openssl not-affected in bookworm, a bash CVE that is merely open.
const debianTracker = `{
  "openssl": {
    "CVE-2023-0464": {"releases": {
      "bookworm": {"status": "resolved", "fixed_version": "0"}
    }}
  },
  "bash": {
    "CVE-2023-1111": {"releases": {
      "bookworm": {"status": "open"}
    }}
  }
}`

func debianServer(t *testing.T, body string) *debian.Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &debian.Provider{BaseURL: srv.URL}
}

// debFinding is a linked Debian OS finding as the OS plugin emits it: Package is
// the source package, the purl carries the binary name.
func debFinding(id, source, binary, version string) Finding {
	return Finding{
		Ecosystem: "os", ID: id, CVE: id,
		Package: source, Module: source, Version: version,
		PURL:   "pkg:deb/debian/" + binary + "@" + version + "?arch=amd64",
		Status: StatusLinked, Method: "elf-needed-closure",
	}
}

func bookworm() *OSInfo { return &OSInfo{ID: "debian", VersionID: "12"} }

// The headline case: Debian marking a source package not-affected moves a
// locally-linked finding to the vexed bucket, and leaves its Status untouched.
func TestDistroOverlayClearsNotAffected(t *testing.T) {
	findings := []Finding{debFinding("CVE-2023-0464", "openssl", "libssl3", "3.0.11-1")}
	p := debianServer(t, debianTracker)

	res := distroOverlay(context.Background(), []distrofeed.Provider{p}, bookworm(), findings, nil, quiet)

	f := findings[0]
	if f.VEX == nil {
		t.Fatal("no statement attached")
	}
	if f.VEX.Status != "not_affected" {
		t.Errorf("vex status = %q", f.VEX.Status)
	}
	if f.VEX.Author != "Debian Security Tracker" {
		t.Errorf("author = %q", f.VEX.Author)
	}
	// The invariant: the local verdict is never rewritten. A run with a feed
	// and one without agree on every Status.
	if f.Status != StatusLinked {
		t.Errorf("status = %q, want the local verdict unchanged", f.Status)
	}

	var found bool
	for _, e := range f.Evidence {
		if e.Origin != OriginDistroFeed {
			continue
		}
		found = true
		if e.Blocking {
			t.Error("a feed statement was recorded as a blocking taint")
		}
		if !strings.Contains(e.Detail, "Debian Security Tracker") || !strings.Contains(e.Detail, "not_affected") {
			t.Errorf("evidence detail = %q", e.Detail)
		}
	}
	if !found {
		t.Error("no distro-feed evidence was recorded")
	}
	if len(res) != 1 || res[0].Cleared != 1 {
		t.Errorf("feed result = %+v", res)
	}
}

// An open advisory clears nothing: the finding stays affected, with no VEX.
func TestDistroOverlayLeavesOpenAdvisoryAffected(t *testing.T) {
	findings := []Finding{debFinding("CVE-2023-1111", "bash", "bash", "5.2-1")}
	p := debianServer(t, debianTracker)

	res := distroOverlay(context.Background(), []distrofeed.Provider{p}, bookworm(), findings, nil, quiet)

	if findings[0].VEX != nil {
		t.Errorf("an open advisory was treated as exculpatory: %+v", findings[0].VEX)
	}
	if len(res) != 1 || res[0].Cleared != 0 {
		t.Errorf("feed result = %+v", res)
	}
}

// A user's --vexhub outranks the automatic feed: a finding vexOverlay already
// spoke to keeps that statement.
func TestDistroOverlayYieldsToExistingVEX(t *testing.T) {
	findings := []Finding{debFinding("CVE-2023-0464", "openssl", "libssl3", "3.0.11-1")}
	findings[0].VEX = &ecosystem.VEXStatement{Status: "not_affected", Author: "Internal Hub"}
	p := debianServer(t, debianTracker)

	distroOverlay(context.Background(), []distrofeed.Provider{p}, bookworm(), findings, nil, quiet)

	if findings[0].VEX.Author != "Internal Hub" {
		t.Errorf("the feed overwrote a higher-precedence statement: author = %q", findings[0].VEX.Author)
	}
}

// A finding matched by an OSV alias rather than its own id still meets the feed
// statement, because the overlay indexes under every alias.
func TestDistroOverlayMatchesThroughAlias(t *testing.T) {
	f := debFinding("GHSA-xxxx", "openssl", "libssl3", "3.0.11-1")
	findings := []Finding{f}
	aliases := map[string][]string{"GHSA-xxxx": {"CVE-2023-0464"}}
	p := debianServer(t, debianTracker)

	distroOverlay(context.Background(), []distrofeed.Provider{p}, bookworm(), findings, aliases, quiet)

	if findings[0].VEX == nil || findings[0].VEX.Status != "not_affected" {
		t.Errorf("alias match failed: %+v", findings[0].VEX)
	}
}

// A non-Debian image is never asked, so a Debian statement can never land on an
// Ubuntu or Red Hat finding.
func TestDistroOverlaySkipsUnhandledDistro(t *testing.T) {
	findings := []Finding{debFinding("CVE-2023-0464", "openssl", "libssl3", "3.0.11-1")}
	p := debianServer(t, debianTracker)

	res := distroOverlay(context.Background(), []distrofeed.Provider{p}, &OSInfo{ID: "ubuntu", VersionID: "22.04"}, findings, nil, quiet)

	if findings[0].VEX != nil {
		t.Errorf("a Debian statement landed on an Ubuntu image: %+v", findings[0].VEX)
	}
	if len(res) != 0 {
		t.Errorf("an unhandled distro produced a result: %+v", res)
	}
}

// The invariant-critical case. One source package (openssl) fans out into two
// binary packages filed under the same CVE at different versions: one past the
// fix, one below it. The verdict for the fixed binary must never leak onto the
// still-vulnerable one, or a real CVE would be hidden. Binding each statement to
// the finding it was computed for -- not to (package, CVE) -- is what prevents
// it.
func TestDistroOverlayDoesNotCrossContaminateVersions(t *testing.T) {
	const tracker = `{
  "openssl": {
    "CVE-2023-9999": {"releases": {
      "bookworm": {"status": "resolved", "fixed_version": "3.0.9-1"}
    }}
  }
}`
	findings := []Finding{
		debFinding("CVE-2023-9999", "openssl", "libssl3", "3.0.11-1"),   // past the fix: cleared
		debFinding("CVE-2023-9999", "openssl", "libcrypto3", "3.0.8-1"), // below the fix: must stand
	}
	p := debianServer(t, tracker)

	distroOverlay(context.Background(), []distrofeed.Provider{p}, bookworm(), findings, nil, quiet)

	if findings[0].VEX == nil || findings[0].VEX.Status != "fixed" {
		t.Errorf("the fixed binary should have been cleared: %+v", findings[0].VEX)
	}
	if findings[1].VEX != nil {
		t.Errorf("a real CVE was hidden: the below-fix binary was cleared by the sibling's verdict: %+v", findings[1].VEX)
	}
}
func TestDistroOverlayIgnoresNonOSFindings(t *testing.T) {
	findings := []Finding{{Ecosystem: "golang", ID: "CVE-2023-0464", CVE: "CVE-2023-0464", Package: "openssl", Version: "3.0.11-1", Status: StatusLinked}}
	p := debianServer(t, debianTracker)

	distroOverlay(context.Background(), []distrofeed.Provider{p}, bookworm(), findings, nil, quiet)

	if findings[0].VEX != nil {
		t.Errorf("a non-OS finding was annotated: %+v", findings[0].VEX)
	}
}
