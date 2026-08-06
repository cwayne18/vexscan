package vexpr

import (
	"strings"
	"testing"
)

func TestMergeStatementsDedupesAgainstExistingDoc(t *testing.T) {
	doc := NewDoc("Someone", testTime)
	doc.Statements = []Statement{{
		Vulnerability: Vulnerability{Name: "CVE-1", Aliases: []string{"GHSA-x"}},
		Products:      []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:deb/debian/a@1"}}}},
		Status:        StatusNotAffected,
	}}
	prop := ProductProposal{Product: testProduct, Statements: []Statement{
		// Same vuln (by alias) + same subcomponent -> already covered.
		{Vulnerability: Vulnerability{Name: "GHSA-x"}, Products: []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:deb/debian/a@1"}}}}, Status: StatusNotAffected},
		// New vuln -> added.
		{Vulnerability: Vulnerability{Name: "CVE-2"}, Products: []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:deb/debian/b@1"}}}}, Status: StatusNotAffected},
	}}
	added := mergeStatements(doc, prop, "Author", "2026-08-06T11:00:00Z")
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("doc has %d statements, want 2", len(doc.Statements))
	}
	if doc.Timestamp != "2026-08-06T11:00:00Z" {
		t.Errorf("timestamp not advanced: %q", doc.Timestamp)
	}
}

func TestMergeStatementsProductWideCovers(t *testing.T) {
	doc := NewDoc("Someone", testTime)
	doc.Statements = []Statement{{
		Vulnerability: Vulnerability{Name: "CVE-1"},
		Products:      []Product{{ID: testProduct}}, // no subcomponents -> whole product
		Status:        StatusNotAffected,
	}}
	prop := ProductProposal{Product: testProduct, Statements: []Statement{
		{Vulnerability: Vulnerability{Name: "CVE-1"}, Products: []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:deb/debian/a@1"}}}}, Status: StatusNotAffected},
	}}
	if added := mergeStatements(doc, prop, "A", testTime); added != 0 {
		t.Fatalf("added = %d, want 0 (product-wide statement covers it)", added)
	}
}

func TestMergeStatementsNoChangeNoTimestampBump(t *testing.T) {
	doc := NewDoc("Someone", testTime)
	prop := ProductProposal{Product: testProduct} // no statements
	if added := mergeStatements(doc, prop, "A", "2026-09-09T09:09:09Z"); added != 0 {
		t.Fatalf("added = %d, want 0", added)
	}
	if doc.Timestamp != testTime {
		t.Errorf("timestamp changed with no additions: %q", doc.Timestamp)
	}
}

func TestIndexEnsure(t *testing.T) {
	idx, err := parseIndex([]byte(`{"version":1,"packages":[
		{"id":"pkg:oci/synthetic?repository_url=index.docker.io%2Fexample%2Fsynthetic","location":"pkg/oci/index.docker.io/example/synthetic/scan.openvex.json"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	// Existing product (given as the decoded purl) resolves without a change.
	loc, changed, err := idx.ensure(testProduct)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("ensure changed the index for a product it already had")
	}
	if loc != "pkg/oci/index.docker.io/example/synthetic/scan.openvex.json" {
		t.Errorf("location = %q", loc)
	}

	// New product gets an entry and reports the change.
	newProd := "pkg:golang/github.com/foo/bar"
	loc, changed, err = idx.ensure(newProd)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("ensure did not report the new product as a change")
	}
	if loc != "pkg/golang/github.com/foo/bar/scan.openvex.json" {
		t.Errorf("new location = %q", loc)
	}
	out, err := idx.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "pkg:golang/github.com/foo/bar") {
		t.Errorf("marshaled index missing new key:\n%s", out)
	}
}

func TestParseDocRoundTrip(t *testing.T) {
	doc := NewDoc("Author", testTime)
	doc.Statements = []Statement{{
		Vulnerability:   Vulnerability{Name: "CVE-1", Aliases: []string{"GHSA-x"}},
		Products:        []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:deb/debian/a@1"}}}},
		Status:          StatusNotAffected,
		Justification:   "component_not_present",
		ImpactStatement: "Ruled out by vexscan",
	}}
	b, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ParseDoc(b)
	if !ok {
		t.Fatal("ParseDoc returned ok=false on our own output")
	}
	if len(got.Statements) != 1 || got.Statements[0].Vulnerability.Name != "CVE-1" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if _, ok := ParseDoc([]byte("  ")); ok {
		t.Error("ParseDoc(empty) = ok, want false")
	}
}

// TestMergePreservesExistingDocumentFields guards the hazard that appending a
// statement to a vendor-authored document must not strip OpenVEX fields this
// package does not model off the statements it already holds.
func TestMergePreservesExistingDocumentFields(t *testing.T) {
	existing := []byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/original",
  "author": "Acme Vendor",
  "role": "Document Creator",
  "timestamp": "2025-01-01T00:00:00Z",
  "last_updated": "2025-01-02T00:00:00Z",
  "version": 7,
  "tooling": "acme-vexctl 1.0",
  "statements": [
    {
      "@id": "https://example.com/vex/original/stmt-1",
      "version": 2,
      "vulnerability": {
        "name": "CVE-1",
        "description": "an important vendor description",
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-1"
      },
      "products": [
        {"@id": "` + testProduct + `", "identifiers": {"purl": "` + testProduct + `"}}
      ],
      "status": "affected",
      "action_statement": "Upgrade to 2.0",
      "status_notes": "vendor is still investigating scope",
      "references": ["https://nvd.example/detail?vulnId=CVE-1&source=nvd<mirror>"]
    }
  ]
}`)

	doc, ok := ParseDoc(existing)
	if !ok {
		t.Fatal("ParseDoc returned ok=false on a valid document")
	}
	prop := ProductProposal{Product: testProduct, Statements: []Statement{
		{Vulnerability: Vulnerability{Name: "CVE-2"}, Products: []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:deb/debian/b@1"}}}}, Status: StatusNotAffected},
	}}
	if added := mergeStatements(doc, prop, "vexscan", "2026-08-06T11:00:00Z"); added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}

	out, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	// Every field the typed model does not carry must survive verbatim.
	for _, want := range []string{
		`"role": "Document Creator"`,
		`"last_updated": "2025-01-02T00:00:00Z"`,
		`"version": 7`,
		`"tooling": "acme-vexctl 1.0"`,
		`"@id": "https://example.com/vex/original"`,
		`"@id": "https://example.com/vex/original/stmt-1"`,
		`"description": "an important vendor description"`,
		`"status_notes": "vendor is still investigating scope"`,
		`"identifiers"`,
		`"status": "affected"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("merged document dropped preserved content %s\n---\n%s", want, got)
		}
	}
	// The merge advances only the top-level timestamp and appends the new vuln.
	if !strings.Contains(got, `"timestamp": "2026-08-06T11:00:00Z"`) {
		t.Errorf("top-level timestamp not advanced:\n%s", got)
	}
	if !strings.Contains(got, `"name": "CVE-2"`) {
		t.Errorf("new statement not added:\n%s", got)
	}
	// Preserved bytes must not be HTML-escaped: an untouched vendor reference
	// URL with & and <> stays byte-for-byte so it does not show as a diff.
	if !strings.Contains(got, `https://nvd.example/detail?vulnId=CVE-1&source=nvd<mirror>`) {
		t.Errorf("preserved reference URL was escaped:\n%s", got)
	}
	if strings.Contains(got, `\u0026`) || strings.Contains(got, `\u003c`) {
		t.Errorf("output contains HTML escapes:\n%s", got)
	}
}
