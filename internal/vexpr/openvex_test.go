package vexpr

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseDocPreservesTrailingNewline is a regression test for a bug that made
// every merge into an existing hub document noisier than it had to be.
//
// ParseDoc trimmed the document's whitespace and then read the layout off the
// trimmed bytes, so lastNL was never true and every re-marshaled document lost
// its final newline. Every hub document rancher/vexhub publishes ends with one,
// so every pull request this tool produced carried a "\ No newline at end of
// file" that nothing else in the diff justified -- and on a merged report stored
// in Git LFS it changes the object's oid as well.
func TestParseDocPreservesTrailingNewline(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"pretty with trailing newline", "{\n  \"@context\": \"" + openVEXContext + "\",\n" +
			"  \"author\": \"A\",\n  \"version\": 1,\n" +
			"  \"timestamp\": \"2026-01-01T00:00:00Z\",\n  \"statements\": []\n}\n"},
		{"minified with trailing newline", `{"@context":"` + openVEXContext +
			`","author":"A","version":1,"timestamp":"2026-01-01T00:00:00Z","statements":[]}` + "\n"},
		{"minified without one", `{"@context":"` + openVEXContext +
			`","author":"A","version":1,"timestamp":"2026-01-01T00:00:00Z","statements":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, ok := ParseDoc([]byte(tc.raw))
			if !ok {
				t.Fatal("ParseDoc reported failure")
			}
			out, err := doc.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !bytes.Equal(out, []byte(tc.raw)) {
				t.Errorf("round trip changed the bytes:\n got %q\nwant %q", out, tc.raw)
			}
		})
	}
}

// TestMergePreservesTrailingNewline is the same bug seen where it did damage:
// through a merge, which is the only way these bytes ever reach a hub.
func TestMergePreservesTrailingNewline(t *testing.T) {
	raw := "{\n  \"@context\": \"" + openVEXContext + "\",\n  \"author\": \"Hub\",\n" +
		"  \"version\": 1,\n  \"timestamp\": \"2026-01-01T00:00:00Z\",\n  \"statements\": []\n}\n"
	prop := ProductProposal{Product: testProduct, Claims: []Claim{claim("CVE-1", "pkg:deb/debian/a@1")}}
	out, added, err := openvexEncoder{}.merge([]byte(raw), prop, testMeta(testTime))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("added = %v, want one statement", added)
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("merge dropped the document's trailing newline")
	}
	if bytes.HasSuffix(out, []byte("\n\n")) {
		t.Error("merge added a second trailing newline")
	}
	// The rest of the file's formatting survives too, which is the reason the
	// layout is detected at all.
	if !strings.Contains(string(out), "\n  \"author\": \"Hub\"") {
		t.Errorf("merge reflowed the document:\n%s", out)
	}
}

// TestCoverIndexMatchesAcrossAliases pins the dedupe the index replaced a linear
// scan with: an id is an id whichever field it appears in, and case is not part
// of it.
func TestCoverIndexMatchesAcrossAliases(t *testing.T) {
	doc := NewDoc("A", testTime)
	doc.Statements = []Statement{{
		Vulnerability: Vulnerability{Name: "GO-2026-1234", ID: "https://x/GHSA-aaaa", Aliases: []string{"CVE-2026-1"}},
		Products:      []Product{{ID: testProduct, Subcomponents: []Subcomponent{{ID: "pkg:golang/x@v1"}}}},
		Status:        StatusNotAffected,
	}}
	ci := newCoverIndex(doc)

	covered := []Claim{
		claim("CVE-2026-1", "pkg:golang/x@v1"),                 // via alias
		claim("cve-2026-1", "pkg:golang/x@v1"),                 // via alias, lowercased
		claim("GO-2026-1234", "pkg:golang/x@v1"),               // via name
		claim("https://x/GHSA-aaaa", "pkg:golang/x@v1"),        // via @id
		claim("GO-2026-9999", "pkg:golang/x@v1", "CVE-2026-1"), // via the claim's own alias
	}
	for _, c := range covered {
		if !ci.covers(testProduct, c) {
			t.Errorf("%q not recognised as already covered", c.Vuln)
		}
	}

	uncovered := []Claim{
		claim("CVE-2026-1", "pkg:golang/other@v1"), // same vuln, different subcomponent
		claim("CVE-2026-2", "pkg:golang/x@v1"),     // different vuln
	}
	for _, c := range uncovered {
		if ci.covers(testProduct, c) {
			t.Errorf("%q/%s wrongly treated as covered", c.Vuln, c.Subcomponent)
		}
	}
	if ci.covers(otherProduct, claim("CVE-2026-1", "pkg:golang/x@v1")) {
		t.Error("a statement about one product was treated as covering another")
	}
}
