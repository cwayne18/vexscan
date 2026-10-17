package suse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cwayne18/vexscan/internal/csaf"
	"github.com/cwayne18/vexscan/internal/distrofeed"
)

// csafFixture is a compact CSAF-VEX document with the exact shape the real feed uses:
// a product tree mapping two products to CPEs, and one vulnerability whose
// product_status splits openssl into a not-affected 1.1 line, an affected 1.0
// line, and a recommended (fixed) version for each. The Desktop product carries
// a deliberately different verdict for libopenssl1_1 so a wrong-product match
// would be caught.
const csafFixture = `{
  "product_tree": {
    "branches": [
      { "category": "vendor", "name": "SUSE", "branches": [
        { "category": "product_family", "name": "SUSE Linux Enterprise", "branches": [
          { "category": "product_name", "name": "SUSE Linux Enterprise Server 15 SP5",
            "product": { "product_id": "SUSE Linux Enterprise Server 15 SP5",
              "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } },
          { "category": "product_name", "name": "SUSE Linux Enterprise Desktop 15 SP5",
            "product": { "product_id": "SUSE Linux Enterprise Desktop 15 SP5",
              "product_identification_helper": { "cpe": "cpe:/o:suse:sled:15:sp5" } } }
        ] }
      ] }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2023-0464",
      "product_status": {
        "known_not_affected": [
          "SUSE Linux Enterprise Server 15 SP5:libopenssl1_1",
          "SUSE Linux Enterprise Server 15 SP5:openssl-1_1",
          "SUSE Linux Enterprise Desktop 15 SP5:libopenssl1_0_0"
        ],
        "known_affected": [
          "SUSE Linux Enterprise Server 15 SP5:libopenssl1_0_0",
          "SUSE Linux Enterprise Server 15 SP5:libopenssl-1_0_0-devel"
        ],
        "recommended": [
          "SUSE Linux Enterprise Server 15 SP5:libopenssl1_0_0-1.1.1l-150500.15.4",
          "SUSE Linux Enterprise Server 15 SP5:libopenssl1_0_0-32bit-1.1.1l-150500.15.4"
        ]
      }
    }
  ]
}`

// serveDir is the directory the test feed files its documents under. It is
// deliberately not any fixture CVE's own year: the real feed keys the
// directory on when SUSE first published the document, so cve-2023-0464.json
// living under 2099/ is what proves the path is read from the index rather
// than guessed from the id.
const serveDir = "2099"

// serve publishes docs under serveDir, along with the index.txt the real feed
// carries, so every test exercises the indexed lookup. Document fetches are
// counted so a test can assert only the CVEs it asked about were fetched; the
// one index request is not, since it is not a per-CVE cost.
func serve(t *testing.T, docs map[string]string, hits *int32) string {
	t.Helper()
	paths := make(map[string]string, len(docs))
	index := make([]string, 0, len(docs))
	for name, body := range docs {
		rel := serveDir + "/" + name
		paths[rel] = body
		index = append(index, rel)
	}
	sort.Strings(index)
	listing := strings.Join(index, "\n") + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == indexFile {
			w.Write([]byte(listing))
			return
		}
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		body, ok := paths[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// serveFlat publishes docs at the flat top-level layout the feed used before
// 2026-10-15, with no index at all: a mirror, or an offline copy. The index
// request 404s, which is how the provider knows to fall back; it is not
// counted, for the same reason it is not counted in serve.
func serveFlat(t *testing.T, docs map[string]string, hits *int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == indexFile {
			http.NotFound(w, r)
			return
		}
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		body, ok := docs[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func bookwormCPE() string { return "cpe:/o:suse:sles:15:sp5" }

func pkgQuery(cpe, name, version string, cves ...string) distrofeed.Query {
	return distrofeed.Query{
		OSID: "sles", Release: "15.5", CPE: cpe,
		Packages: []distrofeed.PkgRef{{
			ID: "ref-0", Source: "openssl-1_1", Name: name, Version: version, CVEs: cves,
		}},
	}
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

func docs() map[string]string {
	return map[string]string{"cve-2023-0464.json": csafFixture}
}

// A package SUSE marks not-affected clears regardless of version: the CVE is in
// the 1.0 code, and libopenssl1_1 does not carry it.
func TestNotAffectedClears(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl1_1", "1.1.1k-150500.15.1", "CVE-2023-0464")))
	if st.Status != distrofeed.StatusNotAffected {
		t.Fatalf("status = %q, want not_affected", st.Status)
	}
	if !st.Status.Exculpatory() {
		t.Error("not_affected must be exculpatory")
	}
}

// The affected 1.0 line stands until the installed version reaches SUSE's fix.
func TestFixedClearsOnlyAtOrAboveFix(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	// Below the fix: affected, never cleared.
	if st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl1_0_0", "1.0.2p-150000.3.70.1", "CVE-2023-0464"))); st.Status.Exculpatory() {
		t.Errorf("below-fix package was cleared: %+v", st)
	}
	// At the fix: cleared.
	if st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl1_0_0", "1.1.1l-150500.15.4", "CVE-2023-0464"))); st.Status != distrofeed.StatusFixed {
		t.Errorf("at-fix package: status = %q, want fixed", st.Status)
	}
	// Past the fix: cleared.
	if st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl1_0_0", "1.1.1w-150500.17.1", "CVE-2023-0464"))); st.Status != distrofeed.StatusFixed {
		t.Errorf("past-fix package: status = %q, want fixed", st.Status)
	}
}

// A package SUSE lists as affected with no fix threshold reached stays affected.
func TestKnownAffectedStands(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	// libopenssl-1_0_0-devel is in known_affected but not recommended: affected.
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl-1_0_0-devel", "1.0.2p-150000.3.70.1", "CVE-2023-0464")))
	if st.Status.Exculpatory() {
		t.Errorf("known-affected package was cleared: %+v", st)
	}
}

// The invariant-critical product join: a Desktop image must never pick up the
// Server verdict, and vice versa. libopenssl1_1 is not-affected on Server but
// not mentioned on Desktop, while libopenssl1_0_0 is not-affected on Desktop but
// affected on Server. A CPE that names Desktop must read Desktop's column.
func TestProductMatchByCPE(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	desktop := "cpe:/o:suse:sled:15:sp5"
	// On Desktop, libopenssl1_0_0 is explicitly not-affected -- opposite of
	// Server, where it is affected. Reading the right product flips the verdict.
	st := only(t, lookup(t, p, pkgQuery(desktop, "libopenssl1_0_0", "1.0.2p-150000.3.70.1", "CVE-2023-0464")))
	if st.Status != distrofeed.StatusNotAffected {
		t.Fatalf("desktop status = %q, want not_affected (must not read Server's affected verdict)", st.Status)
	}
}

// An image whose CPE names no product in the document gets nothing: the provider
// declines rather than guess a product, the same fail-closed rule the Debian
// provider uses for an unmappable release.
func TestUnknownCPEDeclines(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	// A real but absent product.
	if stmts := lookup(t, p, pkgQuery("cpe:/o:suse:sles:12:sp5", "libopenssl1_1", "1.1.1k", "CVE-2023-0464")); len(stmts) != 0 {
		t.Fatalf("unknown CPE should clear nothing, got %+v", stmts)
	}
	// No CPE at all.
	if stmts := lookup(t, p, pkgQuery("", "libopenssl1_1", "1.1.1k", "CVE-2023-0464")); len(stmts) != 0 {
		t.Fatalf("empty CPE should clear nothing, got %+v", stmts)
	}
}

// A CVE SUSE has no document for is a silent decline, not an error: a 404 means
// no record, and the finding simply stands.
func TestMissingCVEIsSilent(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	stmts, err := p.Lookup(context.Background(), pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2099-9999"))
	if err != nil {
		t.Fatalf("a 404 must not be an error: %v", err)
	}
	if len(stmts) != 0 {
		t.Fatalf("a missing CVE should clear nothing, got %+v", stmts)
	}
}

// Only real CVE ids are fetched; OSV aliases like GHSA ids would 404 for certain
// and are dropped before any request.
func TestOnlyCVEsAreFetched(t *testing.T) {
	var hits int32
	p := &Provider{BaseURL: serve(t, docs(), &hits)}
	q := pkgQuery(bookwormCPE(), "libopenssl1_1", "1.1.1k-150500.15.1", "GHSA-xxxx-yyyy-zzzz", "CVE-2023-0464")
	only(t, lookup(t, p, q))
	if hits != 1 {
		t.Errorf("fetched %d docs, want exactly 1 (the CVE, not the GHSA alias)", hits)
	}
}

// A malformed or truncated document is rejected rather than half-trusted, so a
// short read can never clear a finding.
func TestMalformedDocumentRejected(t *testing.T) {
	truncated := csafFixture[:len(csafFixture)-40]
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": truncated}, nil)}
	_, err := p.Lookup(context.Background(), pkgQuery(bookwormCPE(), "libopenssl1_1", "1.1.1k", "CVE-2023-0464"))
	if err == nil {
		t.Fatal("a truncated document must produce an error, not a silent clear")
	}
}

// Trailing data after the JSON object is malformed and must be rejected.
func TestTrailingDataRejected(t *testing.T) {
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": csafFixture + "  garbage"}, nil)}
	_, err := p.Lookup(context.Background(), pkgQuery(bookwormCPE(), "libopenssl1_1", "1.1.1k", "CVE-2023-0464"))
	if err == nil {
		t.Fatal("trailing data after the document should be rejected")
	}
}

// scoredCSAF carries a CVSS v3 score alongside the product status, the shape a
// real SUSE document has and the one --prefer-vendor reads.
const scoredCSAF = `{
  "product_tree": { "branches": [
    { "category": "product_name", "name": "SUSE Linux Enterprise Server 15 SP5",
      "product": { "product_id": "SUSE Linux Enterprise Server 15 SP5",
        "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } } ] },
  "vulnerabilities": [ { "cve": "CVE-2023-0464",
    "scores": [ { "cvss_v3": {
      "baseScore": 7.5,
      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      "version": "3.1" }, "products": [ "SUSE Linux Enterprise Server 15 SP5" ] } ],
    "product_status": {
      "known_affected": [ "SUSE Linux Enterprise Server 15 SP5:bash" ] } } ] }`

// Scores returns SUSE's own CVSS vector for a CVE it has a document for, keyed
// by uppercase CVE and needing no CPE or product join -- the product-independent
// score --prefer-vendor favours for a finding in any ecosystem.
func TestScoresReturnsVendorVector(t *testing.T) {
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": scoredCSAF}, nil)}
	got, err := p.Scores(context.Background(), []string{"CVE-2023-0464"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if got["CVE-2023-0464"] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Fatalf("score = %q, want SUSE's v3.1 vector", got["CVE-2023-0464"])
	}
}

// Scores filters its input to real CVE ids and is silent about a CVE with no
// score: a GO/GHSA alias is dropped rather than fetched to a 404, and a document
// with no scores array leaves the CVE absent so --prefer-vendor falls back to the
// OSV-derived rating.
func TestScoresIgnoresNonCVEAndUnscored(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	got, err := p.Scores(context.Background(), []string{"GO-2023-1751", "CVE-2023-0464"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("scores = %v, want none (the GO id is not a CVE and the document carries no score)", got)
	}
}

// The regression this file exists to pin. SUSE moved every document into a
// directory named for the year it first published the document -- not the year
// in the CVE id -- so a path built from the id 404s. A 404 is a legitimate "no
// record", so the whole feed went quiet without a single error, and
// --prefer-vendor suse silently stopped rating anything.
//
// serve files the 2023 fixture under 2099/, so this passes only if the path
// came out of the index.
func TestDocumentPathComesFromIndex(t *testing.T) {
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": scoredCSAF}, nil)}
	got, err := p.Scores(context.Background(), []string{"CVE-2023-0464"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if got["CVE-2023-0464"] == "" {
		t.Fatal("no score: the document path was not read from the index")
	}
}

// The index is fetched once however many CVEs are asked about, and a CVE the
// index does not list costs no request at all.
func TestIndexFetchedOnceAndUnlistedCVECostsNoRequest(t *testing.T) {
	var hits int32
	p := &Provider{BaseURL: serve(t, docs(), &hits)}
	_, err := p.Scores(context.Background(), []string{"CVE-2023-0464", "CVE-2099-9999", "CVE-2099-9998"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if hits != 1 {
		t.Errorf("fetched %d documents, want 1 (only the listed CVE; the index is not a document fetch)", hits)
	}
}

// A feed with no index is a mirror or an offline copy of the pre-2026-10-15
// flat layout, and still works.
func TestFlatFeedWithoutIndexStillWorks(t *testing.T) {
	p := &Provider{BaseURL: serveFlat(t, map[string]string{"cve-2023-0464.json": scoredCSAF}, nil)}
	got, err := p.Scores(context.Background(), []string{"CVE-2023-0464"})
	if err != nil {
		t.Fatalf("Scores: %v", err)
	}
	if got["CVE-2023-0464"] == "" {
		t.Fatal("a feed with no index should fall back to the flat layout")
	}
}

// An index that cannot be read is an error, never an empty feed. This is the
// distinction the outage turned on: declining every CVE in the scan without a
// word is the one answer that must not be possible.
func TestUnreadableIndexIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"server error", http.StatusInternalServerError, "nope"},
		{"unparseable", http.StatusOK, "<html>not an index</html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, indexFile) {
					w.WriteHeader(tc.code)
					w.Write([]byte(tc.body))
					return
				}
				http.NotFound(w, r)
			}))
			t.Cleanup(srv.Close)
			if _, err := (&Provider{BaseURL: srv.URL}).Scores(context.Background(), []string{"CVE-2023-0464"}); err == nil {
				t.Fatal("an unreadable index must be an error, not a feed with nothing in it")
			}
		})
	}
}

func TestParseIndex(t *testing.T) {
	in := strings.Join([]string{
		"2023/cve-1999-0003.json",
		"2024/cve-2024-5535.json",
		"",
		"changes.csv",            // a sibling file, not a document
		"../escape/cve-1-1.json", // must never steer a fetch out of the base
		"/abs/cve-2023-1.json",
		"2026/not-a-cve.json",
	}, "\n")
	got, junk, err := parseIndex(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseIndex: %v", err)
	}
	if junk != 4 {
		t.Errorf("junk = %d, want 4 (the sibling file, the two unsafe paths and the non-CVE)", junk)
	}
	want := map[string]string{
		"CVE-1999-0003": "2023/cve-1999-0003.json",
		"CVE-2024-5535": "2024/cve-2024-5535.json",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// bestVector takes the highest base score and ignores anything that is not a
// CVSS v3 vector, matching how the rest of the tool rates a vulnerability.
func TestBestVector(t *testing.T) {
	cases := []struct {
		name   string
		scores []csaf.Score
		want   string
	}{
		{"none", nil, ""},
		{"single", scoresOf(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
		{"highest wins", scoresOf(4.0, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"v4 used when there is no v3", scoresOf(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{"v3 preferred over v4", scoresOf(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"unrecognized version ignored", scoresOf(9.9, "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"), ""},
	}
	for _, c := range cases {
		if got := bestVector(c.scores); got != c.want {
			t.Errorf("%s: bestVector = %q, want %q", c.name, got, c.want)
		}
	}
}

// A document fetched for its score is not fetched a second time when its verdict
// is applied: the two passes --prefer-vendor and distroOverlay make share one
// download, so a run does not double its network.
func TestDocumentIsCached(t *testing.T) {
	var hits int32
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": scoredCSAF}, &hits)}
	q := pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2023-0464")
	only(t, lookup(t, p, q))
	only(t, lookup(t, p, q))
	if hits != 1 {
		t.Errorf("fetched %d times, want 1 (the second Lookup should hit the cache)", hits)
	}
}

// On a flat feed a 404 is still the only way to learn there is no record, and
// it is cached: a CVE SUSE has no document for is not re-requested on a second
// pass.
func TestMissingDocumentIsCachedOnFlatFeed(t *testing.T) {
	var hits int32
	p := &Provider{BaseURL: serveFlat(t, map[string]string{}, &hits)}
	q := pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2099-9999")
	lookup(t, p, q)
	lookup(t, p, q)
	if hits != 1 {
		t.Errorf("fetched %d times, want 1 (a cached 404 should not be re-requested)", hits)
	}
}

// On an indexed feed the same CVE costs no request at all, on either pass: the
// index already said the feed does not carry it.
func TestMissingDocumentCostsNoRequestWhenIndexed(t *testing.T) {
	var hits int32
	p := &Provider{BaseURL: serve(t, docs(), &hits)}
	q := pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2099-9999")
	lookup(t, p, q)
	lookup(t, p, q)
	if hits != 0 {
		t.Errorf("fetched %d times, want 0 (the index already declined it)", hits)
	}
}

// scoresOf builds a scores slice from alternating (baseScore, vector) pairs, for
// the table test above. The vector's prefix decides which of CVSSV3/CVSSV4 it
// goes into, same as a real CSAF document only ever populates one of the two.
func scoresOf(pairs ...any) []csaf.Score {
	var out []csaf.Score
	for i := 0; i+1 < len(pairs); i += 2 {
		var s csaf.Score
		score, vec := pairs[i].(float64), pairs[i+1].(string)
		if strings.HasPrefix(vec, "CVSS:4.0/") {
			s.CVSSV4.BaseScore, s.CVSSV4.VectorString = score, vec
		} else {
			s.CVSSV3.BaseScore, s.CVSSV3.VectorString = score, vec
		}
		out = append(out, s)
	}
	return out
}

func TestHandlesSUSEFamily(t *testing.T) {
	p := New()
	for _, id := range []string{"sles", "sled", "sles_sap", "sle_hpc", "sle-micro"} {
		if !p.Handles(id) {
			t.Errorf("should handle %q", id)
		}
	}
	for _, id := range []string{"debian", "ubuntu", "rhel", "opensuse-leap", "opensuse-tumbleweed", ""} {
		if p.Handles(id) {
			t.Errorf("should not handle %q", id)
		}
	}
}

func TestStatementEchoesRefID(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	q := pkgQuery(bookwormCPE(), "libopenssl1_1", "1.1.1k-150500.15.1", "CVE-2023-0464")
	q.Packages[0].ID = "unique-token"
	if st := only(t, lookup(t, p, q)); st.RefID != "unique-token" {
		t.Errorf("RefID = %q, want the ref's own id", st.RefID)
	}
}

// splitNVR must keep a dashed package name whole while peeling off the rpm
// version-release, or a 32bit subpackage would be mistaken for a version.
func TestSplitNVR(t *testing.T) {
	cases := []struct{ in, name, evr string }{
		{"libopenssl1_1-1.1.1l-150500.15.4", "libopenssl1_1", "1.1.1l-150500.15.4"},
		{"libopenssl1_0_0-32bit-1.0.2p-150000.3.70.1", "libopenssl1_0_0-32bit", "1.0.2p-150000.3.70.1"},
		{"libopenssl-1_0_0-devel-1.0.2p-150000.3.70.1", "libopenssl-1_0_0-devel", "1.0.2p-150000.3.70.1"},
	}
	for _, c := range cases {
		name, evr := splitNVR(c.in)
		if name != c.name || evr != c.evr {
			t.Errorf("splitNVR(%q) = (%q, %q), want (%q, %q)", c.in, name, evr, c.name, c.evr)
		}
	}
}

// An installed package's version always carries an epoch from the rpm database;
// SUSE's recommended fix quotes none. A non-zero installed epoch must not clear a
// package whose version is plainly below the fix -- the exact false clean the
// mixed-epoch rule guards against.
func TestEpochDoesNotClearBelowFix(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	// libopenssl1_0_0 fix is 1.1.1l-150500.15.4; installed 1:1.0.2p is below it
	// on version even though its epoch is 1.
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl1_0_0", "1:1.0.2p-150000.3.60.1", "CVE-2023-0464")))
	if st.Status.Exculpatory() {
		t.Fatalf("epoch-1 install below the fix was cleared: %+v", st)
	}
}

// collideCSAF maps one OS CPE to two products with opposite verdicts for the same
// package, the rare shape a single CPE naming several products can take. The
// provider must fail closed: the affected product wins over the not-affected one.
const collideCSAF = `{
  "product_tree": {
    "branches": [
      { "category": "vendor", "name": "SUSE", "branches": [
        { "category": "product_name", "name": "Product A",
          "product": { "product_id": "Product A",
            "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } },
        { "category": "product_name", "name": "Product B",
          "product": { "product_id": "Product B",
            "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } }
      ] }
    ]
  },
  "vulnerabilities": [
    { "cve": "CVE-2023-0464",
      "product_status": {
        "known_not_affected": [ "Product A:bash" ],
        "known_affected": [ "Product B:bash" ]
      } }
  ]
}`

func TestCPECollisionFailsClosed(t *testing.T) {
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": collideCSAF}, nil)}
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2023-0464")))
	if st.Status.Exculpatory() {
		t.Fatalf("a package affected in one colliding product was cleared: %+v", st)
	}
}

// A finding carries a vulnerability under several alias ids. If SUSE clears it
// under one alias but lists it affected under another, the affected verdict must
// win: the finding is not cleared.
func TestAffectedAliasVetoesClear(t *testing.T) {
	clearDoc := `{
      "product_tree": { "branches": [
        { "category": "product_name", "name": "SUSE Linux Enterprise Server 15 SP5",
          "product": { "product_id": "SUSE Linux Enterprise Server 15 SP5",
            "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } } ] },
      "vulnerabilities": [ { "cve": "CVE-2023-0001",
        "product_status": { "known_not_affected": [ "SUSE Linux Enterprise Server 15 SP5:bash" ] } } ] }`
	affectedDoc := `{
      "product_tree": { "branches": [
        { "category": "product_name", "name": "SUSE Linux Enterprise Server 15 SP5",
          "product": { "product_id": "SUSE Linux Enterprise Server 15 SP5",
            "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } } ] },
      "vulnerabilities": [ { "cve": "CVE-2023-0002",
        "product_status": { "known_affected": [ "SUSE Linux Enterprise Server 15 SP5:bash" ] } } ] }`
	p := &Provider{BaseURL: serve(t, map[string]string{
		"cve-2023-0001.json": clearDoc,
		"cve-2023-0002.json": affectedDoc,
	}, nil)}
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2023-0001", "CVE-2023-0002")))
	if st.Status.Exculpatory() {
		t.Fatalf("an affected alias did not veto the clear: %+v", st)
	}
}

// When a product lists more than one fixed version for a package, the highest is
// the threshold. An installed version above the lower fix but below the higher
// one must not clear.
func TestHighestFixIsTheThreshold(t *testing.T) {
	multiFix := `{
      "product_tree": { "branches": [
        { "category": "product_name", "name": "SUSE Linux Enterprise Server 15 SP5",
          "product": { "product_id": "SUSE Linux Enterprise Server 15 SP5",
            "product_identification_helper": { "cpe": "cpe:/o:suse:sles:15:sp5" } } } ] },
      "vulnerabilities": [ { "cve": "CVE-2023-0464",
        "product_status": {
          "known_affected": [ "SUSE Linux Enterprise Server 15 SP5:bash" ],
          "recommended": [
            "SUSE Linux Enterprise Server 15 SP5:bash-5.2-1.1",
            "SUSE Linux Enterprise Server 15 SP5:bash-5.2-3.1"
          ] } } ] }`
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": multiFix}, nil)}
	// Installed 5.2-2.1 is above the lower fix (5.2-1.1) but below the higher
	// (5.2-3.1); it must stay affected.
	if st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "bash", "5.2-2.1", "CVE-2023-0464"))); st.Status.Exculpatory() {
		t.Fatalf("install below the highest fix was cleared: %+v", st)
	}
	// At the higher fix it clears.
	if st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "bash", "5.2-3.1", "CVE-2023-0464"))); st.Status != distrofeed.StatusFixed {
		t.Fatalf("install at the highest fix: status = %q, want fixed", st.Status)
	}
}
