package vexpr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// The other half of the golang-purl regression, at the layer that matters:
// what actually lands in a published document's subcomponent "@id".
//
// internal/ecosystem/golang/purl_test.go pins the string the plugin mints.
// This pins that nothing between a finding and the serialised statement
// re-encodes it, because the encoded form was invisible until Trivy failed to
// match it -- the document parsed, the statement was there, and the CVE came
// back anyway.

// ruledOutFinding is the shape a pclntab verdict has by the time vexpr sees it.
func ruledOutFinding(product, purl, cve, method string) analyze.Finding {
	return analyze.Finding{
		Product: product,
		PURL:    purl,
		CVE:     cve,
		Status:  analyze.StatusNotPresent,
		Method:  method,
	}
}

func TestSubcomponentIDKeepsNamespaceSlashesLiteral(t *testing.T) {
	const product = "pkg:golang/github.com/containerd/containerd/v2"
	tests := []struct {
		name, purl, method string
	}{{
		name:   "the case that regressed CVE-2026-56855",
		purl:   "pkg:golang/golang.org/x/crypto@v0.55.0",
		method: "pclntab",
	}, {
		name:   "a +incompatible version",
		purl:   "pkg:golang/github.com/docker/docker@v27.3.1+incompatible",
		method: "pclntab-module",
	}, {
		name:   "a four-segment namespace",
		purl:   "pkg:golang/go.etcd.io/etcd/client/pkg/v3@v3.7.0",
		method: "pclntab",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := claimFor(ruledOutFinding(product, tt.purl, "CVE-2026-56855", tt.method), "2026-09-16T00:00:00Z", nil)
			if !ok {
				t.Fatal("claimFor declined a ruled-out finding")
			}
			// The impact statement is the fingerprint the malformed statements
			// in the hub were found by, so the test is demonstrably aimed at
			// the path that produced them.
			if want := "Ruled out by vexscan (" + tt.method + ")"; c.Impact != want {
				t.Errorf("impact = %q, want %q", c.Impact, want)
			}

			b, err := json.Marshal(claimStatement(c))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := string(b)
			if !strings.Contains(got, `"subcomponents":[{"@id":"`+tt.purl+`"}]`) {
				t.Errorf("subcomponent @id is not the literal purl:\n%s", got)
			}
			if strings.Contains(got, "%2F") || strings.Contains(got, "%2f") {
				t.Errorf("a statement encodes a namespace separator:\n%s", got)
			}
			if strings.Contains(got, "%2B") || strings.Contains(got, "%2b") {
				t.Errorf("a statement encodes the '+' of a version:\n%s", got)
			}
			if !strings.Contains(got, `"@id":"`+product+`"`) {
				t.Errorf("product @id is not the literal purl:\n%s", got)
			}
		})
	}
}

// The encoding that is correct and must survive the fix. A qualifier value is
// not a path: the slashes inside repository_url are data, and index.json has
// always written them encoded -- see indexKey, and vex.canonicalProduct, which
// decodes them back. Sweeping %2F out of the codebase would have broken this.
func TestOCIQualifierKeepsItsEncodedSlashes(t *testing.T) {
	const plain = "pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes"
	const want = "pkg:oci/hardened-kubernetes?repository_url=index.docker.io%2Francher%2Fhardened-kubernetes"

	got, err := indexKey(plain)
	if err != nil {
		t.Fatalf("indexKey: %v", err)
	}
	if got != want {
		t.Errorf("indexKey = %q, want %q", got, want)
	}

	// And a golang product goes in verbatim, which is the other half of the
	// same rule: encode qualifier values, never a path.
	const mod = "pkg:golang/go.etcd.io/etcd/client/pkg/v3"
	if got, err := indexKey(mod); err != nil || got != mod {
		t.Errorf("indexKey(%q) = %q, %v; want it verbatim", mod, got, err)
	}
}
