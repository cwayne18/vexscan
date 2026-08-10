package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// record builds one OSV JSON record. The shape is the export's, which is the
// API's: these tests are only worth anything if the fixture is the real schema.
func record(id, ecosystem, pkg string, ranges []map[string]any, extra map[string]any) map[string]any {
	aff := map[string]any{
		"package": map[string]any{"name": pkg, "ecosystem": ecosystem},
	}
	if ranges != nil {
		aff["ranges"] = ranges
	}
	for k, v := range extra {
		aff[k] = v
	}
	return map[string]any{
		"id":       id,
		"summary":  id + " (fixture)",
		"affected": []any{aff},
	}
}

// ecosystemRange is the shape a distro record uses: affected from the beginning
// of time, fixed in one version.
func ecosystemRange(introduced, fixed string) []map[string]any {
	ev := []map[string]any{{"introduced": introduced}}
	if fixed != "" {
		ev = append(ev, map[string]any{"fixed": fixed})
	}
	return []map[string]any{{"type": "ECOSYSTEM", "events": ev}}
}

func semverRange(introduced, fixed string) []map[string]any {
	ev := []map[string]any{{"introduced": introduced}}
	if fixed != "" {
		ev = append(ev, map[string]any{"fixed": fixed})
	}
	return []map[string]any{{"type": "SEMVER", "events": ev}}
}

// exportDir writes records into a tree laid out the way gs://osv-vulnerabilities
// is: <ECOSYSTEM>/<ID>.json.
func exportDir(t *testing.T, recs map[string][]map[string]any) string {
	t.Helper()
	root := t.TempDir()
	for eco, list := range recs {
		dir := filepath.Join(root, eco)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, r := range list {
			data, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, r["id"].(string)+".json")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// serveVulns stands in for osv.dev on the /query endpoint: byPkg is what the
// server has already decided applies to the queried package, which is exactly
// the decision the local reader has to reproduce.
func serveVulns(t *testing.T, byPkg map[string][]map[string]any) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/query") {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]any{"vulns": byPkg[req.Package.Name]}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func openLocal(t *testing.T, root string) *Local {
	t.Helper()
	l, err := OpenLocal(root, nil, nil)
	if err != nil {
		t.Fatalf("OpenLocal: %v", err)
	}
	return l
}

func ids(advs map[string]*Advisory) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range advs {
		if !seen[a.ID] {
			seen[a.ID] = true
			out = append(out, a.ID)
		}
	}
	return out
}

func hasID(advs map[string]*Advisory, id string) bool {
	for _, got := range ids(advs) {
		if got == id {
			return true
		}
	}
	return false
}

// TestVersionMatching is the heart of it: offline, this package decides which
// records apply, and the two directions of that decision are not symmetric in
// cost. A version past the fix must not match; a version below it must.
func TestVersionMatching(t *testing.T) {
	root := exportDir(t, map[string][]map[string]any{
		"Debian": {
			record("DEBIAN-CVE-2023-0464", "Debian:12", "openssl", ecosystemRange("0", "3.0.11-1~deb12u2"), nil),
		},
		"Alpine": {
			record("CVE-2024-ALPINE", "Alpine:v3.19", "busybox", ecosystemRange("0", "1.36.1-r16"), nil),
		},
		"Go": {
			record("GO-2024-0001", "Go", "golang.org/x/net", semverRange("0", "0.23.0"), nil),
		},
	})
	l := openLocal(t, root)

	cases := []struct {
		name string
		ref  Ref
		want bool
	}{
		// dpkg ordering, including the ~ that sorts below everything.
		{"debian below fix", Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.9-1"}, true},
		{"debian at fix", Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1~deb12u2"}, false},
		{"debian past fix", Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.14-1~deb12u2"}, false},
		{"debian tilde sorts below", Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1~deb12u1"}, true},
		// The release lives in the ecosystem string, and a Debian:13 query must
		// not be answered by the bookworm entry.
		{"wrong release", Ref{Ecosystem: "Debian:13", Name: "openssl", Version: "3.0.9-1"}, false},
		{"unknown package", Ref{Ecosystem: "Debian:12", Name: "nosuchpkg", Version: "1.0"}, false},

		// apk ordering, where the -rN revision is the whole difference.
		{"alpine below fix", Ref{Ecosystem: "Alpine:v3.19", Name: "busybox", Version: "1.36.1-r15"}, true},
		{"alpine at fix", Ref{Ecosystem: "Alpine:v3.19", Name: "busybox", Version: "1.36.1-r16"}, false},
		{"alpine past fix", Ref{Ecosystem: "Alpine:v3.19", Name: "busybox", Version: "1.36.1-r17"}, false},

		// semver, including the "v" and "go" prefixes normalizeVersion strips.
		{"go below fix", Ref{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"}, true},
		{"go at fix", Ref{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.23.0"}, false},
		{"go past fix", Ref{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.24.0"}, false},

		// A ref with no version asks for everything about the package.
		{"no version asks for all", Ref{Ecosystem: "Debian:12", Name: "openssl"}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			advs, err := l.Query(context.Background(), c.ref)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(advs) > 0; got != c.want {
				t.Errorf("matched = %v, want %v (got %v)", got, c.want, ids(advs))
			}
		})
	}
}

// TestUnorderableVersionKeepsTheFinding pins the direction the whole offline
// path is bent in. RubyGems has no comparator here, so the version cannot be
// placed in the range -- and the advisory has to survive that, because a
// dropped finding is the one failure mode this tool must not produce quietly.
//
// RubyGems and not PyPI: every ecosystem vexscan has a plugin for is orderable
// now, so demonstrating the fallback needs one of the ecosystems only an SBOM
// or an --osv-ecosystem override can name.
func TestUnorderableVersionKeepsTheFinding(t *testing.T) {
	root := exportDir(t, map[string][]map[string]any{
		"RubyGems": {
			record("GHSA-gems-0001", "RubyGems", "rack", ecosystemRange("0", "2.2.6.4"), nil),
		},
	})
	l := openLocal(t, root)

	// 3.0.0 is past 2.2.6.4 on any reading, but the point is that this package
	// does not know how to read it and says so instead of guessing.
	advs, err := l.Query(context.Background(), Ref{Ecosystem: "RubyGems", Name: "rack", Version: "3.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(advs, "GHSA-gems-0001") {
		t.Fatalf("advisory was dropped for a version this package cannot order; got %v", ids(advs))
	}

	notes := l.Notes()
	if len(notes) == 0 {
		t.Fatal("the match was kept but not reported; a silent over-match is how an offline report stops being checkable")
	}
	if !strings.Contains(notes[0], "RubyGems") || !strings.Contains(notes[0], "GHSA-gems-0001") {
		t.Errorf("note names neither the ecosystem nor an example: %q", notes[0])
	}
}

// The counterpart, and the reason the note above should now be rare: PyPI and
// Maven are ordered on their own rules rather than kept unchecked. Both are
// spelled the way a naive port gets wrong -- a post-release, which semver has
// no notion of, and an unknown Maven qualifier, which sorts above the known
// ones -- so a regression to a semver fallback fails here rather than quietly
// widening every offline report.
func TestPyPIAndMavenAreOrderedOnTheirOwnRules(t *testing.T) {
	root := exportDir(t, map[string][]map[string]any{
		"PyPI":  {record("GHSA-pypi-0003", "PyPI", "pip", ecosystemRange("0", "21.1"), nil)},
		"Maven": {record("GHSA-mvn-0001", "Maven", "org.apache.logging.log4j:log4j-core", ecosystemRange("2.0", "2.15.0"), nil)},
	})
	l := openLocal(t, root)

	for _, c := range []struct {
		eco, name, version string
		want               bool
	}{
		{"PyPI", "pip", "20.0", true},        // inside the range
		{"PyPI", "pip", "25.0.1", false},     // past the fix, and the case a real export got wrong
		{"PyPI", "pip", "21.1.post1", false}, // a post-release of the fix is still fixed
		{"PyPI", "pip", "21.1rc1", true},     // ... and its release candidate is not
		{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", true},
		{"Maven", "org.apache.logging.log4j:log4j-core", "2.17.1", false},
		{"Maven", "org.apache.logging.log4j:log4j-core", "2.15.0-SNAPSHOT", true},
	} {
		advs, err := l.Query(context.Background(), Ref{Ecosystem: c.eco, Name: c.name, Version: c.version})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(advs) > 0; got != c.want {
			t.Errorf("%s %s@%s: matched = %v, want %v", c.eco, c.name, c.version, got, c.want)
		}
	}
	if notes := l.Notes(); len(notes) != 0 {
		t.Errorf("neither ecosystem should need the fallback now: %v", notes)
	}
}

// TestExplicitVersionsNeedNoComparator is why the gap above is narrower than it
// looks: the ecosystems without a comparator are largely the ones that publish
// an enumeration, and matching an enumeration is exact.
func TestExplicitVersionsNeedNoComparator(t *testing.T) {
	root := exportDir(t, map[string][]map[string]any{
		"PyPI": {
			record("GHSA-pypi-0002", "PyPI", "requests", nil, map[string]any{
				"versions": []string{"2.30.0", "2.31.0"},
			}),
		},
	})
	l := openLocal(t, root)

	for _, c := range []struct {
		version string
		want    bool
	}{
		{"2.31.0", true},
		{"2.32.0", false},
	} {
		advs, err := l.Query(context.Background(), Ref{Ecosystem: "PyPI", Name: "requests", Version: c.version})
		if err != nil {
			t.Fatal(err)
		}
		if got := hasID(advs, "GHSA-pypi-0002"); got != c.want {
			t.Errorf("requests %s: matched = %v, want %v", c.version, got, c.want)
		}
	}
	if notes := l.Notes(); len(notes) != 0 {
		t.Errorf("an enumeration needs no comparator, so nothing should have been noted: %v", notes)
	}
}

// TestUpstreamSurvives is the field the distro-feed join reads, and the reason
// OSV's own export is the right offline source rather than a translation of
// someone else's database. A distro advisory names its CVEs only here.
func TestUpstreamSurvives(t *testing.T) {
	rec := record("DEBIAN-CVE-2023-0464", "Debian:12", "openssl", ecosystemRange("0", "3.0.11-1"), nil)
	rec["upstream"] = []string{"CVE-2023-0464"}
	root := exportDir(t, map[string][]map[string]any{"Debian": {rec}})
	l := openLocal(t, root)

	advs, err := l.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.9-1"})
	if err != nil {
		t.Fatal(err)
	}
	adv, ok := advs["DEBIAN-CVE-2023-0464"]
	if !ok {
		t.Fatalf("advisory not found; got %v", ids(advs))
	}
	if len(adv.Upstream) != 1 || adv.Upstream[0] != "CVE-2023-0464" {
		t.Errorf("Upstream = %v, want [CVE-2023-0464]", adv.Upstream)
	}
	// indexUpstream is what makes --cves CVE-2023-0464 reach a distro bundle,
	// and it runs inside buildMap -- which is shared with the API path, so this
	// asserts the sharing as much as the field.
	if _, ok := advs["CVE-2023-0464"]; !ok {
		t.Error("the advisory is not reachable by the CVE it fixes")
	}
	if got := adv.Fixed["openssl"]; len(got) != 1 || got[0] != "3.0.11-1" {
		t.Errorf("Fixed = %v, want [3.0.11-1]", got)
	}
}

// TestMatchesTheAPI is the strongest claim available without a network: given
// the same records, the local reader answers what a server returning those
// records would have. Both sides run buildMap, so what is really under test is
// the matching that replaces osv.dev's.
func TestMatchesTheAPI(t *testing.T) {
	recs := []map[string]any{
		record("DEBIAN-CVE-2023-0464", "Debian:12", "openssl", ecosystemRange("0", "3.0.11-1~deb12u2"), nil),
		record("DEBIAN-CVE-2023-5678", "Debian:12", "openssl", ecosystemRange("0", "3.0.9-1"), nil),
	}
	root := exportDir(t, map[string][]map[string]any{"Debian": recs})
	l := openLocal(t, root)

	ref := Ref{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.10-1"}

	// What the API would have answered: it applies the ranges itself and hands
	// back only the matching records, which for 3.0.10-1 is the first alone.
	srv := serveVulns(t, map[string][]map[string]any{"openssl": {recs[0]}})
	c := NewClient()
	c.BaseURL = srv

	fromAPI, err := c.Query(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	fromLocal, err := l.Query(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}

	wantIDs := ids(fromAPI)
	gotIDs := ids(fromLocal)
	if len(wantIDs) != 1 || len(gotIDs) != 1 || wantIDs[0] != gotIDs[0] {
		t.Fatalf("local returned %v, API returned %v", gotIDs, wantIDs)
	}
	if len(fromLocal) != len(fromAPI) {
		t.Errorf("local keyed %d identifiers, API keyed %d", len(fromLocal), len(fromAPI))
	}
}

// TestZipAndDedup covers the export as it actually arrives: a bucket rsync
// brings all.zip down alongside the loose per-record copies of the same
// advisories, and reading both must not double-count anything.
func TestZipAndDedup(t *testing.T) {
	rec := record("GO-2024-0001", "Go", "golang.org/x/net", semverRange("0", "0.23.0"), nil)

	root := t.TempDir()
	dir := filepath.Join(root, "Go")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GO-2024-0001.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	// The same record again, inside a zip beside it.
	zf, err := os.Create(filepath.Join(dir, "all.zip"))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create("GO-2024-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zf.Close()

	l := openLocal(t, root)
	if len(l.recs) != 1 {
		t.Errorf("read %d records from one advisory shipped twice, want 1", len(l.recs))
	}

	// And the zip on its own is a valid source.
	l2, err := OpenLocal(filepath.Join(dir, "all.zip"), nil, nil)
	if err != nil {
		t.Fatalf("OpenLocal on a zip: %v", err)
	}
	advs, err := l2.Query(context.Background(), Ref{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(advs, "GO-2024-0001") {
		t.Errorf("zip-only source did not answer; got %v", ids(advs))
	}
}

// A withdrawn record is one the publisher retracted. The API stops serving it;
// the bucket keeps shipping it. Found the hard way: every one of the ten rows a
// real debian:12.0 export produced that the API did not was a withdrawn record.
func TestWithdrawnRecordsAreNotServed(t *testing.T) {
	live := record("DEBIAN-CVE-2024-0001", "Debian:12", "mawk", ecosystemRange("0", ""), nil)
	dead := record("DEBIAN-CVE-2017-20229", "Debian:12", "mawk", ecosystemRange("0", ""), nil)
	dead["withdrawn"] = "2026-04-01T01:02:28.156824Z"

	root := exportDir(t, map[string][]map[string]any{"Debian": {live, dead}})
	l := openLocal(t, root)

	advs, err := l.Query(context.Background(), Ref{Ecosystem: "Debian:12", Name: "mawk", Version: "1.3.4.20200120-3.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(advs, "DEBIAN-CVE-2024-0001") {
		t.Errorf("the live advisory went missing; got %v", ids(advs))
	}
	if hasID(advs, "DEBIAN-CVE-2017-20229") {
		t.Errorf("a withdrawn advisory was reported; the API would not have served it: %v", ids(advs))
	}
	// Withdrawn records are dropped at load, so nothing downstream can see one
	// even by another route.
	if got := len(l.recs); got != 1 {
		t.Errorf("indexed %d record(s), want 1: a withdrawn record was kept in memory", got)
	}
}

// An export of nothing but retracted records leaves an index that answers every
// query "no advisories" -- the same silence an empty export produces, and it
// must fail the same way rather than scan.
func TestAnExportOfOnlyWithdrawnRecordsIsAnError(t *testing.T) {
	dead := record("DEBIAN-CVE-2017-20229", "Debian:12", "mawk", ecosystemRange("0", ""), nil)
	dead["withdrawn"] = "2026-04-01T01:02:28.156824Z"
	root := exportDir(t, map[string][]map[string]any{"Debian": {dead}})
	if _, err := OpenLocal(root, nil, nil); err == nil {
		t.Fatal("an export holding only withdrawn records was accepted")
	}
}

// TestEmptyExportIsAnError is the invariant in its most direct form. An index
// with nothing in it answers every question "no advisories", which reads
// exactly like a clean image, so it must not be possible to start a scan with
// one.
func TestEmptyExportIsAnError(t *testing.T) {
	if _, err := OpenLocal(t.TempDir(), nil, nil); err == nil {
		t.Fatal("an empty export was accepted; a scan against it would report every image clean")
	}
	if _, err := OpenLocal(filepath.Join(t.TempDir(), "nope"), nil, nil); err == nil {
		t.Fatal("a missing path was accepted")
	}
}

func TestDescribeNamesTheSource(t *testing.T) {
	root := exportDir(t, map[string][]map[string]any{
		"Go": {record("GO-2024-0001", "Go", "example.com/m", semverRange("0", "1.0.0"), nil)},
	})
	got := openLocal(t, root).Describe()
	if !strings.Contains(got, root) || !strings.Contains(got, "local") {
		t.Errorf("Describe() = %q; a report has to be able to say the advisories did not come from osv.dev", got)
	}
}
