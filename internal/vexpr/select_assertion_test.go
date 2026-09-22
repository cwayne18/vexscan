package vexpr

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// A conclusion reached under --roots and --exec-policy=assume-none is not a
// property of the image, it is a property of the image plus what the user said
// about how it runs. If the emitted statement does not carry the condition, it is
// byte-identical to one the scan derived unaided, and the reviewer it lands in
// front of has nothing to disagree with.
func TestExecutePathClaimCarriesTheRuntimeAssertion(t *testing.T) {
	rt := &analyze.RuntimeAssertion{
		Roots:          []string{"/usr/bin/calico-node"},
		Profile:        "calico",
		ExecAssumeNone: true,
	}
	f := analyze.Finding{
		Product:       "pkg:oci/hardened-calico",
		PURL:          "pkg:rpm/sles/libopenssl3",
		CVE:           "CVE-2026-1234",
		Status:        analyze.StatusNotInPath,
		Justification: "vulnerable_code_not_in_execute_path",
		Method:        "elf-needed-closure",
	}
	c, ok := claimFor(f, "2026-09-22T00:00:00Z", rt)
	if !ok {
		t.Fatal("claimFor declined a ruled-out finding")
	}
	for _, want := range []string{"Conditional", "calico", "/usr/bin/calico-node", "nothing else"} {
		if !strings.Contains(c.Impact, want) {
			t.Errorf("impact statement does not mention %q: %q", want, c.Impact)
		}
	}
}

// The other two justifications are read out of the image and the package's own
// symbol tables. No assertion about the entrypoint bears on either, and claiming
// one would both mislead and train the reader to skip the line where it is real.
func TestPresenceClaimsAreNotConditional(t *testing.T) {
	rt := &analyze.RuntimeAssertion{Roots: []string{"/usr/bin/calico-node"}, ExecAssumeNone: true}
	for _, just := range []string{"component_not_present", "vulnerable_code_not_present"} {
		t.Run(just, func(t *testing.T) {
			f := analyze.Finding{
				Product:       "pkg:oci/hardened-calico",
				PURL:          "pkg:rpm/sles/libopenssl3",
				CVE:           "CVE-2026-1234",
				Status:        analyze.StatusNotPresent,
				Justification: just,
			}
			c, ok := claimFor(f, "2026-09-22T00:00:00Z", rt)
			if !ok {
				t.Fatal("claimFor declined a ruled-out finding")
			}
			if strings.Contains(c.Impact, "Conditional") {
				t.Errorf("a presence claim was marked conditional: %q", c.Impact)
			}
		})
	}
}

// A run that asserted nothing must produce exactly what it did before: no
// condition, no empty clause where one would go.
func TestNoAssertionLeavesTheImpactStatementAlone(t *testing.T) {
	f := analyze.Finding{
		Product:       "pkg:oci/app",
		PURL:          "pkg:rpm/sles/libopenssl3",
		CVE:           "CVE-2026-1234",
		Status:        analyze.StatusNotInPath,
		Justification: "vulnerable_code_not_in_execute_path",
	}
	c, ok := claimFor(f, "2026-09-22T00:00:00Z", nil)
	if !ok {
		t.Fatal("claimFor declined a ruled-out finding")
	}
	if strings.Contains(c.Impact, "Conditional") {
		t.Errorf("an unasserted run produced a conditional statement: %q", c.Impact)
	}
}
