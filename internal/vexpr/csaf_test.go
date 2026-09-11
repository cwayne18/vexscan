package vexpr

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/csaf"
	"github.com/cwayne18/vexscan/internal/vex"
)

const csafLoc = "pkg/oci/index.docker.io/example/synthetic/scan.csaf.json"

func csafOptions(hub HubReader) Options {
	return Options{
		Hub:                hub,
		Format:             FormatCSAF,
		Author:             "Acme Security",
		Timestamp:          testTime,
		PublisherNamespace: "https://acme.example",
	}
}

func proposeCSAF(t *testing.T, hub HubReader, res *analyze.Result) *Plan {
	t.Helper()
	plan, err := Propose(context.Background(), res, csafOptions(hub))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// hubFromPlan turns a proposal's output back into a hub, which is what copying
// the output over a clone and re-running amounts to.
func hubFromPlan(plan *Plan) *fakeHub {
	h := &fakeHub{files: map[string]string{}}
	for _, ch := range plan.Changes {
		if ch.Path == "index.json" {
			h.index = string(ch.Content)
			continue
		}
		h.files[ch.Path] = string(ch.Content)
	}
	return h
}

// docFrom returns the one product document a plan wrote.
func docFrom(t *testing.T, plan *Plan, path string) []byte {
	t.Helper()
	for _, ch := range plan.Changes {
		if ch.Path == path {
			return ch.Content
		}
	}
	t.Fatalf("plan wrote no %s; it wrote %v", path, pathsOf(plan))
	return nil
}

// TestCSAFBootstrapsAHub is --vex-format csaf with no --vexhub: the output has
// to be a hub in its own right, and the document in it a CSAF advisory that
// says everything the profile makes mandatory.
func TestCSAFBootstrapsAHub(t *testing.T) {
	plan := proposeCSAF(t, nil, ruledOutResult("CVE-NEW"))
	if got, want := pathsOf(plan), []string{csafLoc, "index.json"}; !equalStrings(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}
	// The index has to point at the CSAF file, not at a name it never wrote.
	if idx := string(docFrom(t, plan, "index.json")); !strings.Contains(idx, csafLoc) {
		t.Errorf("index.json does not point at the document:\n%s", idx)
	}

	doc, err := csaf.Parse(docFrom(t, plan, csafLoc))
	if err != nil {
		t.Fatalf("vexscan wrote a CSAF document it cannot read back: %v", err)
	}
	if doc.Document.Category != csaf.Category || doc.Document.CSAFVersion != csaf.Version {
		t.Errorf("document = %+v, want the VEX profile's category and version", doc.Document)
	}
	pub := doc.Document.Publisher
	if pub.Name != "Acme Security" || pub.Namespace != "https://acme.example" || pub.Category != "other" {
		t.Errorf("publisher = %+v", pub)
	}
	tr := doc.Document.Tracking
	if tr.ID != "VEXSCAN-OCI-INDEX-DOCKER-IO-EXAMPLE-SYNTHETIC" {
		t.Errorf("tracking id = %q", tr.ID)
	}
	if tr.Version != "1" || len(tr.RevisionHistory) != 1 {
		t.Errorf("tracking = %+v, want version 1 with one revision", tr)
	}
	if tr.InitialReleaseDate != testTime || tr.CurrentReleaseDate != testTime {
		t.Errorf("tracking dates = %q / %q, want the scan time", tr.InitialReleaseDate, tr.CurrentReleaseDate)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].CVE != "CVE-NEW" {
		t.Fatalf("vulnerabilities = %+v", doc.Vulnerabilities)
	}
}

// TestCSAFRoundTripsThroughTheReader is the property that makes the whole
// exercise worth anything: what this writes, internal/vex reads back as the
// same claim about the same component of the same image. A document that
// validates but does not match is a document nobody's scanner will act on.
func TestCSAFRoundTripsThroughTheReader(t *testing.T) {
	plan := proposeCSAF(t, nil, ruledOutResult("CVE-NEW"))

	doc, err := vex.ParseDoc(docFrom(t, plan, csafLoc))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := vex.Match(doc, testProduct, []string{"CVE-NEW"}, "pkg:deb/debian/pkga@1")
	if st == nil {
		t.Fatalf("the reader matched nothing in what the writer produced: %+v", doc)
	}
	if st.Status != vex.StatusNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if st.Justification != "component_not_present" {
		t.Errorf("justification = %q, want the finding's own", st.Justification)
	}
	if !strings.Contains(st.ImpactStatement, "Ruled out by vexscan") {
		t.Errorf("impact statement = %q", st.ImpactStatement)
	}
	if doc.Author != "Acme Security" {
		t.Errorf("author = %q", doc.Author)
	}
	// The claim is scoped to the component, not to the whole image: a different
	// component of the same image must not come back cleared.
	if other, _ := vex.Match(doc, testProduct, []string{"CVE-NEW"}, "pkg:deb/debian/unrelated@1"); other != nil {
		t.Errorf("a component-scoped claim cleared an unrelated component: %+v", other)
	}
}

// TestCSAFReRunChangesNothing is what the derived tracking id and the
// coverage-before-allocation rule are for. Scanning the same image twice must
// produce no diff at all -- not a new advisory beside the old one, not a
// version bump, not a product tree that grew a duplicate entry.
func TestCSAFReRunChangesNothing(t *testing.T) {
	first := proposeCSAF(t, nil, ruledOutResult("CVE-NEW"))
	second := proposeCSAF(t, hubFromPlan(first), ruledOutResult("CVE-NEW"))
	if !second.Empty() {
		t.Fatalf("a re-run of an unchanged scan rewrote %v", pathsOf(second))
	}
	if len(second.Unparsable) != 0 || len(second.Untouched) != 0 {
		t.Fatalf("a re-run declined its own document: %v / %+v", second.Unparsable, second.Untouched)
	}
}

// TestCSAFAmendsItsOwnAdvisory covers the other half: a second scan that found
// something new must publish a new version of the advisory rather than a
// silently edited one, because a CSAF document that gains a statement and keeps
// its version lies to every consumer caching it.
func TestCSAFAmendsItsOwnAdvisory(t *testing.T) {
	first := proposeCSAF(t, nil, ruledOutResult("CVE-ONE"))
	second := proposeCSAF(t, hubFromPlan(first), ruledOutResult("CVE-ONE", "CVE-TWO"))
	if second.Statements != 1 {
		t.Fatalf("statements = %d, want only the new one", second.Statements)
	}

	doc, err := csaf.Parse(docFrom(t, second, csafLoc))
	if err != nil {
		t.Fatal(err)
	}
	tr := doc.Document.Tracking
	if tr.Version != "2" {
		t.Errorf("version = %q, want 2", tr.Version)
	}
	if len(tr.RevisionHistory) != 2 || tr.RevisionHistory[1].Number != "2" {
		t.Errorf("revision history = %+v, want a second entry", tr.RevisionHistory)
	}
	if tr.InitialReleaseDate != testTime {
		t.Errorf("initial release date moved to %q; only the current one may", tr.InitialReleaseDate)
	}
	if len(doc.Vulnerabilities) != 2 {
		t.Errorf("vulnerabilities = %d, want both", len(doc.Vulnerabilities))
	}
	// The first CVE's statement survives the amendment untouched.
	if v := doc.Vulnerabilities[0]; v.CVE != "CVE-ONE" || len(v.ProductStatus.KnownNotAffected) != 1 {
		t.Errorf("the original entry changed: %+v", v)
	}
}

// TestCSAFDeclinesSomebodyElsesAdvisory is the rule that keeps this from
// forging a vendor's signature. Amending a CSAF document means issuing a new
// version of it under its publisher's tracking id, so a document vexscan did
// not write is left exactly as published.
func TestCSAFDeclinesSomebodyElsesAdvisory(t *testing.T) {
	vendor := `{"document":{"category":"csaf_vex","csaf_version":"2.0",
		"publisher":{"category":"vendor","name":"Example Corp","namespace":"https://example.com"},
		"title":"Example advisory",
		"tracking":{"id":"EXAMPLE-SA-2026-0001","initial_release_date":"2026-01-01T00:00:00Z",
		  "current_release_date":"2026-01-01T00:00:00Z",
		  "revision_history":[{"number":"1","date":"2026-01-01T00:00:00Z","summary":"Initial release."}],
		  "status":"final","version":"1"}},
		"product_tree":{},"vulnerabilities":[]}`
	hub := &fakeHub{
		index: `{"version":1,"packages":[{"id":"pkg:oci/synthetic?repository_url=index.docker.io%2Fexample%2Fsynthetic","location":"` + csafLoc + `"}]}`,
		files: map[string]string{csafLoc: vendor},
	}

	plan := proposeCSAF(t, hub, ruledOutResult("CVE-NEW"))
	if !plan.Empty() {
		t.Fatalf("plan rewrites a vendor's advisory: %v", pathsOf(plan))
	}
	if len(plan.Untouched) != 1 {
		t.Fatalf("Untouched = %+v, want the vendor's document reported", plan.Untouched)
	}
	if got := plan.Untouched[0]; got.Location != csafLoc || !strings.Contains(got.Reason, "EXAMPLE-SA-2026-0001") {
		t.Errorf("Untouched[0] = %+v, want it to name the advisory it left alone", got)
	}
}

// TestCSAFDeclinesAnOpenVEXDocument is the format half of the same guard. A
// hub's index points a product at one document, so a product already published
// as OpenVEX has no room for a competing CSAF one -- and overwriting it would
// throw away whatever it says.
func TestCSAFDeclinesAnOpenVEXDocument(t *testing.T) {
	hub := &fakeHub{index: syntheticIndex(), files: map[string]string{
		syntheticLoc: `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Vendor","version":1,
			"timestamp":"2026-01-01T00:00:00Z","statements":[]}`,
	}}

	plan := proposeCSAF(t, hub, ruledOutResult("CVE-NEW"))
	if !plan.Empty() {
		t.Fatalf("plan wrote %v over an OpenVEX hub", pathsOf(plan))
	}
	if len(plan.Untouched) != 1 || !strings.Contains(plan.Untouched[0].Reason, "--vex-format openvex") {
		t.Fatalf("Untouched = %+v, want a refusal naming the flag that would work", plan.Untouched)
	}
}

// TestCSAFGroupsProductsUnderOneFlag is what keeps a real document readable. A
// scan that rules one CVE out across forty components should say the reason
// once and list forty products, not repeat itself forty times.
func TestCSAFGroupsProductsUnderOneFlag(t *testing.T) {
	res := &analyze.Result{Target: "example/synthetic:latest"}
	for _, pkg := range []string{"a", "b", "c"} {
		res.Findings = append(res.Findings, analyze.Finding{
			ID: "CVE-SHARED", CVE: "CVE-SHARED", Product: testProduct,
			PURL:          "pkg:deb/debian/" + pkg + "@1",
			Status:        analyze.StatusNotPresent,
			Justification: "component_not_present", Method: "pkgdb",
		})
	}

	plan := proposeCSAF(t, nil, res)
	doc, err := csaf.Parse(docFrom(t, plan, csafLoc))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want the three components under one CVE", len(doc.Vulnerabilities))
	}
	v := doc.Vulnerabilities[0]
	if len(v.ProductStatus.KnownNotAffected) != 3 {
		t.Errorf("known_not_affected = %v, want all three components", v.ProductStatus.KnownNotAffected)
	}
	if len(v.Flags) != 1 || len(v.Flags[0].ProductIDs) != 3 {
		t.Errorf("flags = %+v, want one flag naming three products", v.Flags)
	}
	if len(v.Threats) != 1 || len(v.Threats[0].ProductIDs) != 3 {
		t.Errorf("threats = %+v, want one impact statement naming three products", v.Threats)
	}
	// One relationship per component, and the image itself defined once.
	if len(doc.ProductTree.Relationships) != 3 {
		t.Errorf("relationships = %d, want one per component", len(doc.ProductTree.Relationships))
	}
	images := 0
	for _, p := range doc.ProductTree.FullProductNames {
		if p.ProductID == testProduct {
			images++
		}
	}
	if images != 1 {
		t.Errorf("the image is defined %d times, want once", images)
	}
}

// TestCSAFFilesNonCVEIdsUnderIDs covers the one place the two formats disagree
// about vulnerability naming: OpenVEX takes any string as the name, while
// CSAF's cve member accepts a CVE and nothing else, so a Go advisory has to go
// into ids with the database that issued it.
func TestCSAFFilesNonCVEIdsUnderIDs(t *testing.T) {
	res := &analyze.Result{Findings: []analyze.Finding{{
		ID: "GO-2025-1234", GoID: "GO-2025-1234", Product: testProduct,
		PURL: "pkg:golang/golang.org/x/net@v0.1.0", Status: analyze.StatusNotInPath,
		Justification: "vulnerable_code_not_in_execute_path",
	}}}

	plan := proposeCSAF(t, nil, res)
	doc, err := csaf.Parse(docFrom(t, plan, csafLoc))
	if err != nil {
		t.Fatal(err)
	}
	v := doc.Vulnerabilities[0]
	if v.CVE != "" {
		t.Errorf("cve = %q, want it left out: GO-2025-1234 is not a CVE", v.CVE)
	}
	if len(v.IDs) != 1 || v.IDs[0].Text != "GO-2025-1234" {
		t.Fatalf("ids = %+v", v.IDs)
	}
	if v.IDs[0].SystemName != "Go Vulnerability Database" {
		t.Errorf("system_name = %q, want the database that issued the id", v.IDs[0].SystemName)
	}
	// And the reader still finds it by that id.
	read, err := vex.ParseDoc(docFrom(t, plan, csafLoc))
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := vex.Match(read, testProduct, []string{"GO-2025-1234"}, "pkg:golang/golang.org/x/net@v0.1.0"); st == nil {
		t.Error("the reader cannot find a statement filed only under a Go id")
	}
}

// TestCSAFNeedsAPublisherIdentity pins that the CSAF-only flags are required
// when they apply and rejected when they do not, both before any work happens.
func TestCSAFNeedsAPublisherIdentity(t *testing.T) {
	res := ruledOutResult("CVE-NEW")
	base := csafOptions(nil)

	noNamespace := base
	noNamespace.PublisherNamespace = ""
	if _, err := Propose(context.Background(), res, noNamespace); err == nil {
		t.Error("CSAF with no publisher namespace = nil error; the profile makes it mandatory")
	}

	badCategory := base
	badCategory.PublisherCategory = "maintainer"
	if _, err := Propose(context.Background(), res, badCategory); err == nil {
		t.Error(`PublisherCategory "maintainer" = nil error; CSAF has a closed vocabulary`)
	}

	openvexWithPublisher := Options{
		Author: "Acme Security", Timestamp: testTime, PublisherNamespace: "https://acme.example",
	}
	if _, err := Propose(context.Background(), res, openvexWithPublisher); err == nil {
		t.Error("a publisher namespace on an OpenVEX run = nil error; it would go nowhere")
	}
}

func TestTrackingID(t *testing.T) {
	cases := []struct{ product, want string }{
		{testProduct, "VEXSCAN-OCI-INDEX-DOCKER-IO-EXAMPLE-SYNTHETIC"},
		{"pkg:golang/github.com/Altinity/clickhouse-backup/v2", "VEXSCAN-GOLANG-GITHUB-COM-ALTINITY-CLICKHOUSE-BACKUP-V2"},
	}
	for _, tc := range cases {
		got, err := trackingID(tc.product)
		if err != nil {
			t.Errorf("trackingID(%q): %v", tc.product, err)
			continue
		}
		if got != tc.want {
			t.Errorf("trackingID(%q) = %q, want %q", tc.product, got, tc.want)
		}
	}
	if _, err := trackingID("pkg:deb/debian/openssl@3"); err == nil {
		t.Error("trackingID accepted a product type that is not a scanned artifact")
	}
}

// TestPurlName pins that CSAF's mandatory name member reads as prose. The
// product_id keeps the purl verbatim, escapes and all, because re-runs have to
// match it byte for byte; the name is what a reviewer reads, so the escapes
// come out of it.
func TestPurlName(t *testing.T) {
	cases := []struct{ purl, want string }{
		{"pkg:golang/golang.org%2Fx%2Fmod@v0.38.0", "golang.org/x/mod@v0.38.0"},
		{"pkg:golang/stdlib@v1.26.5", "stdlib@v1.26.5"},
		{testProduct, "index.docker.io/example/synthetic"},
		{"pkg:deb/debian/openssl@3.0.11-1", "debian/openssl@3.0.11-1"},
		{"not-a-purl", "not-a-purl"},
	}
	for _, tc := range cases {
		if got := purlName(tc.purl); got != tc.want {
			t.Errorf("purlName(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

// TestCSAFDeclinesAVersionItCannotAdvance covers the conservative half of the
// same-tracking-id rule: a document that is ours by id but carries a version
// scheme this did not write is not one to guess the successor of.
func TestCSAFDeclinesAVersionItCannotAdvance(t *testing.T) {
	first := proposeCSAF(t, nil, ruledOutResult("CVE-ONE"))
	hub := hubFromPlan(first)
	hub.files[csafLoc] = strings.Replace(hub.files[csafLoc], `"version": "1"`, `"version": "1.2.0"`, 1)
	if !strings.Contains(hub.files[csafLoc], `"version": "1.2.0"`) {
		t.Fatal("the fixture edit did not apply; the test would prove nothing")
	}

	plan := proposeCSAF(t, hub, ruledOutResult("CVE-ONE", "CVE-TWO"))
	if !plan.Empty() {
		t.Fatalf("plan rewrote a document whose version it cannot advance: %v", pathsOf(plan))
	}
	if len(plan.Untouched) != 1 || !strings.Contains(plan.Untouched[0].Reason, "1.2.0") {
		t.Fatalf("Untouched = %+v, want the version reported", plan.Untouched)
	}
}

func TestNextVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"1", "2", true},
		{"9", "10", true},
		{"1.2.0", "", false},
		{"", "", false},
		{"-1", "", false},
	} {
		got, ok := nextVersion(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("nextVersion(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestCSAFEncoderReportsAnUnreadableDocumentAsUnreadable keeps the two refusals
// apart: bytes that claim to be CSAF and are not parseable are a broken file,
// not somebody else's advisory, and the operator needs to be told which.
func TestCSAFEncoderReportsAnUnreadableDocumentAsUnreadable(t *testing.T) {
	broken := []byte(`{"document":{"csaf_version":"2.0","category":"csaf_vex"` + "\n\nNOT JSON")
	prop := ProductProposal{Product: testProduct, Claims: []Claim{claim("CVE-1", "pkg:deb/debian/a@1")}}

	_, _, err := csafEncoder{}.merge(broken, prop, Meta{
		Author: "A", Timestamp: testTime, PublisherNamespace: "https://a.example",
	})
	if !errors.Is(err, errUnreadable) {
		t.Fatalf("err = %v, want errUnreadable", err)
	}
}
