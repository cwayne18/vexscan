package vex

import (
	"strings"
	"testing"
)

// csafHeader is the document-level metadata the VEX profile makes mandatory,
// factored out so each case below is only the product tree and the
// vulnerability it is actually about.
const csafHeader = `"document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "publisher": {"category": "vendor", "name": "Rancher Security team", "namespace": "https://rancher.com"},
    "title": "VEX statements",
    "tracking": {
      "id": "RANCHER-VEX-0001",
      "initial_release_date": "2026-06-19T00:00:00Z",
      "current_release_date": "2026-06-19T00:00:00Z",
      "revision_history": [{"number": "1", "date": "2026-06-19T00:00:00Z", "summary": "Initial release."}],
      "status": "final",
      "version": "1"
    }
  }`

// csafDoc is a CSAF-VEX document in the shape a hub would publish one: a
// product tree naming the image and a component inside it, a relationship
// joining the two, and a vulnerability whose known_not_affected entry points at
// the pair. It says in CSAF exactly what the OpenVEX fixtures under testdata/
// say, so both readers can be held to the same answer.
const csafDoc = `{
  ` + csafHeader + `,
  "product_tree": {
    "full_product_names": [
      {
        "product_id": "IMG",
        "name": "hardened-kubernetes",
        "product_identification_helper": {
          "purl": "pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes"
        }
      },
      {
        "product_id": "SELINUX",
        "name": "selinux",
        "product_identification_helper": {"purl": "pkg:golang/github.com/opencontainers/selinux@v1.11.0"}
      },
      {
        "product_id": "UNRELATED",
        "name": "some other image",
        "product_identification_helper": {"purl": "pkg:oci/other?repository_url=index.docker.io/x/other"}
      }
    ],
    "relationships": [
      {
        "category": "default_component_of",
        "full_product_name": {
          "product_id": "SELINUX-IMG",
          "name": "selinux as a component of hardened-kubernetes"
        },
        "product_reference": "SELINUX",
        "relates_to_product_reference": "IMG"
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-7598",
      "ids": [{"system_name": "GitHub Security Advisory", "text": "GHSA-cgrx-mc8f-2prm"}],
      "release_date": "2026-06-19T00:00:00Z",
      "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["SELINUX-IMG"]}],
      "product_status": {
        "known_not_affected": ["SELINUX-IMG"],
        "known_affected": ["UNRELATED"]
      },
      "remediations": [
        {"category": "vendor_fix", "details": "Upgrade to 1.2.3.", "product_ids": ["UNRELATED"]}
      ],
      "threats": [
        {
          "category": "impact",
          "details": "Manually confirmed, only exploitable when running runc directly.",
          "product_ids": ["SELINUX-IMG"]
        }
      ]
    }
  ]
}`

// csafWith builds a minimal document around a product tree and a vulnerability.
func csafWith(productTree, vulns string) string {
	return `{` + csafHeader + `,"product_tree":` + productTree + `,"vulnerabilities":` + vulns + `}`
}

func parseCSAFDoc(t *testing.T, s string) *Doc {
	t.Helper()
	doc, err := ParseDoc([]byte(s))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	return doc
}

// The point of sniffing is that no caller says which format it holds, so
// ParseDoc has to reach the right reader from the bytes alone.
func TestParseDocSniffsTheFormat(t *testing.T) {
	if doc := parseCSAFDoc(t, csafDoc); doc.Author != "Rancher Security team" {
		t.Errorf("author = %q, want the CSAF publisher name", doc.Author)
	}

	openvex := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"Someone","statements":[
		{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/x"}],"status":"not_affected"}]}`
	od, err := ParseDoc([]byte(openvex))
	if err != nil {
		t.Fatalf("ParseDoc(openvex): %v", err)
	}
	if od.Author != "Someone" || len(od.Statements) != 1 {
		t.Errorf("OpenVEX document decoded as %+v", od)
	}
}

// A CSAF statement has to arrive at Match looking exactly like an OpenVEX one:
// the resolved product purl, the resolved subcomponent purl, the flag as the
// justification and the impact threat as the impact statement.
func TestCSAFResolvesRelationshipsIntoSubcomponents(t *testing.T) {
	doc := parseCSAFDoc(t, csafDoc)

	st, note := Match(doc, k8sProduct,
		[]string{"GHSA-cgrx-mc8f-2prm"},
		"pkg:golang/github.com%2Fopencontainers%2Fselinux@v1.11.0")
	if st == nil {
		t.Fatalf("no statement matched; document has %d", len(doc.Statements))
	}
	if st.Status != StatusNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification = %q, want the CSAF flag label", st.Justification)
	}
	if !strings.Contains(st.ImpactStatement, "running runc directly") {
		t.Errorf("impact statement = %q, want the impact threat's prose", st.ImpactStatement)
	}
	if st.Timestamp != "2026-06-19T00:00:00Z" {
		t.Errorf("timestamp = %q, want the vulnerability's release date", st.Timestamp)
	}
	// The component matched across an encoding disagreement -- the hub writes
	// the module path decoded, the scanner percent-encodes it -- which is the
	// tolerance the reader still applies once versions agree, and it must be
	// recorded the same way.
	if note == "" {
		t.Error("a loose spelling match recorded no disagreement note")
	}
}

// A statement scoped to a subcomponent must not clear a different component of
// the same image. This is the check that would fail if the relationship were
// flattened to a product-wide claim.
func TestCSAFSubcomponentScopeIsNotProductWide(t *testing.T) {
	doc := parseCSAFDoc(t, csafDoc)
	if st, _ := Match(doc, k8sProduct, []string{"CVE-2024-7598"}, "pkg:golang/github.com/other/thing@v1"); st != nil {
		t.Errorf("a subcomponent-scoped statement cleared an unrelated component: %+v", st)
	}
}

// The alias in ids[] is what actually bridges the two sides: vexscan holds a
// GHSA id and the document is filed under a CVE.
func TestCSAFMatchesThroughVulnerabilityIDs(t *testing.T) {
	doc := parseCSAFDoc(t, csafDoc)
	for _, id := range []string{"CVE-2024-7598", "GHSA-cgrx-mc8f-2prm", "cve-2024-7598"} {
		if st, _ := Match(doc, k8sProduct, []string{id},
			"pkg:golang/github.com/opencontainers/selinux@v1.11.0"); st == nil {
			t.Errorf("%s matched nothing", id)
		}
	}
}

// known_affected must come through as affected rather than be dropped or folded
// into the not_affected statement: a vendor confirming a finding is a different
// fact from one clearing it, and Exculpatory has to tell them apart.
func TestCSAFCarriesEveryStatusItStates(t *testing.T) {
	doc := parseCSAFDoc(t, csafDoc)

	st, _ := Match(doc, "pkg:oci/other?repository_url=index.docker.io/x/other",
		[]string{"CVE-2024-7598"}, "pkg:oci/other")
	if st == nil {
		t.Fatal("the known_affected product matched nothing")
	}
	if st.Status != StatusAffected {
		t.Fatalf("status = %q, want affected", st.Status)
	}
	if Exculpatory(st.Status) {
		t.Error("an affected statement was treated as exculpatory")
	}
	if st.ActionStatement != "Upgrade to 1.2.3." {
		t.Errorf("action statement = %q, want the remediation details", st.ActionStatement)
	}
}

// A product_status id the tree never defines cannot be matched against
// anything, and a product identified only by a CPE has no purl to join on. Both
// are dropped rather than carried as statements that would silently never fire.
func TestCSAFDropsUnresolvableProducts(t *testing.T) {
	doc := parseCSAFDoc(t, csafWith(
		`{"full_product_names":[{"product_id":"CPE-ONLY","name":"sles",
		   "product_identification_helper":{"cpe":"cpe:/o:suse:sles:15:sp5"}}]}`,
		`[{"cve":"CVE-2026-1","product_status":{"known_not_affected":["CPE-ONLY","NEVER-DEFINED"]}}]`))
	if len(doc.Statements) != 0 {
		t.Errorf("statements = %+v, want none: neither product can be matched on a purl", doc.Statements)
	}
}

// One flag over two hundred products is how a real document is written, so the
// grouping has to keep each reason attached to its own products rather than
// spreading the first one across all of them.
func TestCSAFGroupsProductsByTheirOwnReason(t *testing.T) {
	doc := parseCSAFDoc(t, csafWith(
		`{"full_product_names":[
		   {"product_id":"A","name":"a","product_identification_helper":{"purl":"pkg:oci/a"}},
		   {"product_id":"B","name":"b","product_identification_helper":{"purl":"pkg:oci/b"}}]}`,
		`[{"cve":"CVE-2026-1",
		   "flags":[{"label":"component_not_present","product_ids":["A"]},
		            {"label":"vulnerable_code_not_present","product_ids":["B"]}],
		   "product_status":{"known_not_affected":["A","B"]}}]`))
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want one per distinct reason", len(doc.Statements))
	}
	want := map[string]string{"pkg:oci/a": "component_not_present", "pkg:oci/b": "vulnerable_code_not_present"}
	for _, st := range doc.Statements {
		if len(st.Products) != 1 {
			t.Fatalf("statement covers %d products, want 1", len(st.Products))
		}
		if got := st.Justification; got != want[st.Products[0].ID] {
			t.Errorf("%s: justification = %q, want %q", st.Products[0].ID, got, want[st.Products[0].ID])
		}
	}
}

// A flag with no product_ids is document-wide scope, not empty scope. Reading
// it as empty would strip the justification off every statement in a document
// written the concise way.
func TestCSAFUnscopedFlagAppliesToEveryProduct(t *testing.T) {
	doc := parseCSAFDoc(t, csafWith(
		`{"full_product_names":[
		   {"product_id":"A","name":"a","product_identification_helper":{"purl":"pkg:oci/a"}},
		   {"product_id":"B","name":"b","product_identification_helper":{"purl":"pkg:oci/b"}}]}`,
		`[{"cve":"CVE-2026-1","flags":[{"label":"component_not_present"}],
		   "product_status":{"known_not_affected":["A","B"]}}]`))
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want the two products grouped under one reason", len(doc.Statements))
	}
	if doc.Statements[0].Justification != "component_not_present" {
		t.Errorf("justification = %q", doc.Statements[0].Justification)
	}
	if len(doc.Statements[0].Products) != 2 {
		t.Errorf("products = %d, want 2", len(doc.Statements[0].Products))
	}
}

// SUSE nests every product in branches rather than declaring
// full_product_names, so a reader that only handles one of the two sees nothing
// in half the documents published.
func TestCSAFReadsProductsDefinedInBranches(t *testing.T) {
	doc := parseCSAFDoc(t, csafWith(
		`{"branches":[{"category":"vendor","name":"Acme","branches":[
		   {"category":"product_name","name":"thing","product":{
		     "product_id":"P","name":"thing",
		     "product_identification_helper":{"purl":"pkg:oci/thing"}}}]}]}`,
		`[{"cve":"CVE-2026-1","flags":[{"label":"component_not_present"}],
		   "product_status":{"known_not_affected":["P"]}}]`))
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want the branch-defined product to resolve", len(doc.Statements))
	}
	if doc.Statements[0].Products[0].ID != "pkg:oci/thing" {
		t.Errorf("product = %q", doc.Statements[0].Products[0].ID)
	}
}

// Truncated JSON must fail rather than decode to a document with no statements,
// which would be indistinguishable from a hub that has nothing to say.
func TestCSAFRejectsTruncatedDocuments(t *testing.T) {
	if _, err := ParseDoc([]byte(csafDoc[:len(csafDoc)-40])); err == nil {
		t.Error("a truncated CSAF document parsed without error")
	}
}
