package analyze

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/distrofeed"
)

// The other distro-feed tests call distroOverlay directly and hand it findings
// whose id is a bare "CVE-2023-0464". Real OSV never produces that shape for a
// distro ecosystem, and the gap is exactly where a whole release of --distro-feeds
// went out matching nothing at all:
//
//	Debian:12 openssl -> DEBIAN-CVE-2023-0464
//	SLES      openssl -> SUSE-SU-2026:0885-1
//
// Neither carries a CVE in its own id, and neither carries one in aliases: OSV
// puts the CVEs a distro advisory fixes in "upstream", which advisoryResolver
// deliberately keeps out of aliases() so a bundle addressing eight CVEs is not
// filed as eight names for one thing. Every distro feed joins on CVE, so handed
// aliases() they all match nothing -- silently, because a feed that matched
// nothing is indistinguishable in the report from a feed with nothing to say.
//
// These run the whole of runTree, so they pin the wiring (which id set Run hands
// the overlay) rather than the overlay's own behaviour. A unit test on
// distroOverlay cannot catch this: it is the caller that was wrong.

// osvUpstreamServer serves one Debian OSV record in the shape the real API uses
// -- advisory id DEBIAN-CVE-x, no aliases, the CVE it fixes in upstream.
func osvUpstreamServer(t *testing.T, pkg, advisoryID, upstream string) string {
	t.Helper()
	record := map[string]any{
		"id":       advisoryID,
		"aliases":  []string{},
		"upstream": []string{upstream},
		"summary":  advisoryID + " (wiring test)",
	}
	type query struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/querybatch"):
			var req struct {
				Queries []query `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			results := make([]map[string]any, 0, len(req.Queries))
			for _, q := range req.Queries {
				vulns := []map[string]any{}
				if q.Package.Name == pkg {
					vulns = append(vulns, map[string]any{"id": advisoryID})
				}
				results = append(results, map[string]any{"vulns": vulns})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})

		case strings.HasSuffix(r.URL.Path, "/query"):
			var q query
			_ = json.NewDecoder(r.Body).Decode(&q)
			recs := []map[string]any{}
			if q.Package.Name == pkg {
				recs = append(recs, record)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"vulns": recs})

		default: // /vulns/{id}
			if path.Base(r.URL.Path) == advisoryID {
				_ = json.NewEncoder(w).Encode(record)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": path.Base(r.URL.Path)})
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// askedFeed records the ids it was handed and clears anything it is asked about
// by a real CVE, so a test can assert on the join without standing up a vendor.
type askedFeed struct{ asked []distrofeed.PkgRef }

func (f *askedFeed) Name() string { return "Asked Feed" }

func (f *askedFeed) Handles(osID string) bool { return strings.EqualFold(osID, "debian") }

func (f *askedFeed) Lookup(_ context.Context, q distrofeed.Query) ([]distrofeed.Statement, error) {
	f.asked = append(f.asked, q.Packages...)
	var out []distrofeed.Statement
	for _, p := range q.Packages {
		for _, id := range p.CVEs {
			if !strings.HasPrefix(id, "CVE-") {
				continue
			}
			out = append(out, distrofeed.Statement{
				RefID:         p.ID,
				Distro:        "debian",
				Package:       p.Name,
				CVE:           id,
				Status:        distrofeed.StatusNotAffected,
				Justification: "not affected in this release",
				Author:        "Asked Feed",
			})
			break
		}
	}
	return out, nil
}

// debianTree is a rootfs the OS plugin can inventory: an os-release that names
// the release a feed keys on, and one installed package.
func debianTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"/etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n" +
			"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
		"/var/lib/dpkg/status": "Package: openssl\nVersion: 3.0.11-1\nArchitecture: amd64\n\n",
	})
}

// runWithFeed scans the tree with the given feeds, or with none when feeds is
// empty -- the no-feed run is the baseline the with-feed run must agree with.
func runWithFeed(t *testing.T, feeds ...distrofeed.Provider) *Result {
	t.Helper()
	res, err := Run(context.Background(), Options{
		RootFS:      debianTree(t),
		All:         true,
		Ecosystems:  []string{"os"},
		OSVBaseURL:  osvUpstreamServer(t, "openssl", "DEBIAN-CVE-2023-0464", "CVE-2023-0464"),
		DistroFeeds: feeds,
		Logf:        func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res[0]
}

// The contract: a feed must be handed the CVE the advisory fixes, not only the
// distro's own id for it. Asserting on the ids the provider actually received is
// what makes the failure legible -- "the feed was never told about any CVE" --
// rather than a bare matched=0 that reads like the vendor had nothing to say.
func TestDistroFeedIsAskedAboutUpstreamCVEs(t *testing.T) {
	feed := &askedFeed{}
	runWithFeed(t, feed)

	if len(feed.asked) == 0 {
		t.Fatal("the feed was handed no packages at all")
	}
	var got []string
	for _, p := range feed.asked {
		got = append(got, p.CVEs...)
	}
	if !contains(got, "CVE-2023-0464") {
		t.Errorf("the feed was never told the CVE the advisory fixes; it got %v.\n"+
			"Run must pass cveSets().All (which folds in Upstream), not aliases(): "+
			"a distro advisory names its CVEs in neither its id nor its aliases, so "+
			"every CVE-keyed feed matches nothing.", got)
	}
}

// And the consequence, end to end: with the right id set the statement reaches
// its finding and clears it. This is the assertion that fails loudly if the
// overlay is ever handed the narrow set again.
func TestDistroFeedClearsThroughUpstreamCVE(t *testing.T) {
	res := runWithFeed(t, &askedFeed{})

	if len(res.DistroFeeds) != 1 {
		t.Fatalf("DistroFeeds = %+v, want one entry", res.DistroFeeds)
	}
	d := res.DistroFeeds[0]
	if d.Matched == 0 {
		t.Fatalf("feed matched nothing (%+v); the finding's ids never carried a CVE", d)
	}
	if d.Cleared == 0 {
		t.Errorf("feed matched %d finding(s) but cleared none: %+v", d.Matched, d)
	}

	var vexed int
	for _, f := range res.Findings {
		if f.VEX != nil {
			vexed++
		}
	}
	if vexed == 0 {
		t.Error("the feed reported a clear but no finding carries its statement")
	}

	// The invariant the whole feature rests on, checked the only way that
	// actually proves it: a run with a feed and a run without agree on every
	// Status. A feed adds a vendor's reason to relax attention; the verdict
	// stays whatever the local closure concluded.
	base := runWithFeed(t)
	if len(base.Findings) != len(res.Findings) {
		t.Fatalf("the feed changed the finding count: %d with, %d without", len(res.Findings), len(base.Findings))
	}
	for i := range base.Findings {
		if got, want := res.Findings[i].Status, base.Findings[i].Status; got != want {
			t.Errorf("%s: Status is %q with the feed and %q without", base.Findings[i].ID, got, want)
		}
	}
}
