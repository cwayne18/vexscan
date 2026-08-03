package analyze

import (
	"testing"

	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/osv"
)

const criticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8

func resolverWith(cache map[string]map[string]*osv.Advisory) *advisoryResolver {
	r := newResolver()
	r.cache = cache
	return r
}

// TestSeveritiesReadsWhatWasAlreadyFetched covers the central claim: the
// severity comes out of the advisories the resolver cached to decide the
// findings existed, so it costs no extra request.
func TestSeveritiesReadsWhatWasAlreadyFetched(t *testing.T) {
	r := resolverWith(map[string]map[string]*osv.Advisory{
		"Debian:12/zlib1g@1:1.2.13.dfsg-1": {
			"DEBIAN-CVE-2023-45853": {
				ID:         "DEBIAN-CVE-2023-45853",
				Aliases:    []string{"CVE-2023-45853"},
				CVSSVector: criticalVector,
			},
		},
	})

	sev := r.severities()
	// Indexed under its own id and under the alias, because a finding names
	// the advisory by whichever id its plugin was working from.
	for _, key := range []string{"DEBIAN-CVE-2023-45853", "CVE-2023-45853"} {
		got, ok := sev[key]
		if !ok {
			t.Fatalf("%s missing from the severity map", key)
		}
		if got.label != cvss.Critical {
			t.Errorf("%s: label = %s, want %s", key, got.label, cvss.Critical)
		}
		if got.vector != criticalVector {
			t.Errorf("%s: vector = %q", key, got.vector)
		}
	}
}

// An advisory reachable from two components must not report a different
// severity depending on map iteration order.
func TestSeveritiesIsDeterministicAcrossComponents(t *testing.T) {
	r := resolverWith(map[string]map[string]*osv.Advisory{
		"Debian:12/a@1": {"CVE-1": {ID: "CVE-1", PublisherSeverity: "LOW"}},
		"Debian:12/b@1": {"CVE-1": {ID: "CVE-1", PublisherSeverity: "CRITICAL"}},
	})
	for i := 0; i < 50; i++ {
		if got := r.severities()["CVE-1"].label; got != cvss.Critical {
			t.Fatalf("iteration %d: label = %s, want the more severe %s", i, got, cvss.Critical)
		}
	}
}

func TestSeveritiesToleratesNilAdvisories(t *testing.T) {
	r := resolverWith(map[string]map[string]*osv.Advisory{
		"Debian:12/a@1": {"CVE-1": nil},
	})
	if got := len(r.severities()); got != 0 {
		t.Errorf("severities() = %d entries, want 0", got)
	}
}

func TestSeverityOverlay(t *testing.T) {
	sev := map[string]severity{
		"DEBIAN-CVE-2023-45853": {label: cvss.Critical, vector: criticalVector},
		"CVE-2023-45853":        {label: cvss.Critical, vector: criticalVector},
		"GO-2023-2102":          {label: cvss.High},
	}

	findings := []Finding{
		// Matched on CVE, which is what ospkg fills in.
		{CVE: "DEBIAN-CVE-2023-45853", ID: "DEBIAN-CVE-2023-45853"},
		// Matched on the neutral ID when CVE is spelled differently.
		{CVE: "", ID: "CVE-2023-45853"},
		// Matched on GoID, the Go plugin's own identifier.
		{CVE: "CVE-2023-39325", ID: "CVE-2023-39325", GoID: "GO-2023-2102"},
		// Nothing was resolved for this one.
		{CVE: "CVE-9999-0000", ID: "CVE-9999-0000"},
	}
	severityOverlay(findings, sev)

	if findings[0].Severity != cvss.Critical || findings[0].CVSS != criticalVector {
		t.Errorf("matched on CVE: %+v", findings[0])
	}
	if findings[1].Severity != cvss.Critical {
		t.Errorf("matched on ID: %+v", findings[1])
	}
	if findings[2].Severity != cvss.High {
		t.Errorf("matched on GoID: %+v", findings[2])
	}
	if findings[2].CVSS != "" {
		t.Errorf("CVSS = %q, the advisory published no vector", findings[2].CVSS)
	}
	// An unresolved advisory leaves Severity empty rather than claiming
	// UNKNOWN. The two are different facts: nothing was read, versus a record
	// was read and published no rating.
	if findings[3].Severity != "" {
		t.Errorf("Severity = %q, want empty for an advisory nothing resolved", findings[3].Severity)
	}
}

func TestSeverityOverlayWithAnEmptyMapChangesNothing(t *testing.T) {
	findings := []Finding{{CVE: "CVE-1", Severity: ""}}
	severityOverlay(findings, nil)
	if findings[0].Severity != "" {
		t.Errorf("Severity = %q", findings[0].Severity)
	}
}

// The Go repo-mode path resolves advisories inside govulncheck rather than
// through the resolver, so its findings arrive with no severity. That gap is
// documented in the README; this pins that it degrades to "unrated" rather
// than to a wrong rating.
func TestSeverityOverlayLeavesUnresolvableFindingsAlone(t *testing.T) {
	findings := []Finding{{CVE: "CVE-2023-39325", GoID: "GO-2023-2102"}}
	severityOverlay(findings, map[string]severity{"CVE-OTHER": {label: cvss.Critical}})
	if findings[0].Severity != "" || findings[0].CVSS != "" {
		t.Errorf("unresolved finding was labelled: %+v", findings[0])
	}
}
