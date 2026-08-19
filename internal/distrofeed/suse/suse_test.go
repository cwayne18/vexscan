package suse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cwayne18/vexscan/internal/distrofeed"
)

// csaf is a compact CSAF-VEX document with the exact shape the real feed uses:
// a product tree mapping two products to CPEs, and one vulnerability whose
// product_status splits openssl into a not-affected 1.1 line, an affected 1.0
// line, and a recommended (fixed) version for each. The Desktop product carries
// a deliberately different verdict for libopenssl1_1 so a wrong-product match
// would be caught.
const csaf = `{
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

// serve maps /cve-xxxx-yyyy.json to a body, and counts hits so a test can assert
// only the CVEs it asked about were fetched.
func serve(t *testing.T, docs map[string]string, hits *int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
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
	return map[string]string{"cve-2023-0464.json": csaf}
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
	truncated := csaf[:len(csaf)-40]
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": truncated}, nil)}
	_, err := p.Lookup(context.Background(), pkgQuery(bookwormCPE(), "libopenssl1_1", "1.1.1k", "CVE-2023-0464"))
	if err == nil {
		t.Fatal("a truncated document must produce an error, not a silent clear")
	}
}

// Trailing data after the JSON object is malformed and must be rejected.
func TestTrailingDataRejected(t *testing.T) {
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": csaf + "  garbage"}, nil)}
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

// A document that publishes a CVSS score exposes it on every statement it
// produces for that CVE, so --prefer-vendor can favour SUSE's own rating.
func TestScoreOnStatement(t *testing.T) {
	p := &Provider{BaseURL: serve(t, map[string]string{"cve-2023-0464.json": scoredCSAF}, nil)}
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2023-0464")))
	if st.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Fatalf("CVSSVector = %q, want SUSE's v3.1 vector", st.CVSSVector)
	}
}

// A document with no scores array leaves the vector empty, which is the signal
// for --prefer-vendor to fall back to the OSV-derived rating.
func TestNoScoreLeavesVectorEmpty(t *testing.T) {
	p := &Provider{BaseURL: serve(t, docs(), nil)}
	st := only(t, lookup(t, p, pkgQuery(bookwormCPE(), "libopenssl-1_0_0-devel", "1.0.2p-150000.3.70.1", "CVE-2023-0464")))
	if st.CVSSVector != "" {
		t.Fatalf("CVSSVector = %q, want empty for a document with no scores", st.CVSSVector)
	}
}

// bestVector takes the highest base score and ignores anything that is not a
// CVSS v3 vector, matching how the rest of the tool rates a vulnerability.
func TestBestVector(t *testing.T) {
	cases := []struct {
		name   string
		scores []csafScore
		want   string
	}{
		{"none", nil, ""},
		{"single", scoresOf(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
		{"highest wins", scoresOf(4.0, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"non-v3 ignored", scoresOf(9.9, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), ""},
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

// A 404 is cached too: a CVE SUSE has no record for is not re-requested on a
// second pass.
func TestMissingDocumentIsCached(t *testing.T) {
	var hits int32
	p := &Provider{BaseURL: serve(t, map[string]string{}, &hits)}
	q := pkgQuery(bookwormCPE(), "bash", "5.2-1", "CVE-2099-9999")
	lookup(t, p, q)
	lookup(t, p, q)
	if hits != 1 {
		t.Errorf("fetched %d times, want 1 (a cached 404 should not be re-requested)", hits)
	}
}

// scoresOf builds a scores slice from alternating (baseScore, vector) pairs, for
// the table test above.
func scoresOf(pairs ...any) []csafScore {
	var out []csafScore
	for i := 0; i+1 < len(pairs); i += 2 {
		var s csafScore
		s.CVSSV3.BaseScore = pairs[i].(float64)
		s.CVSSV3.VectorString = pairs[i+1].(string)
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
