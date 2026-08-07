package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// parseSARIF renders a result to SARIF and decodes it, failing on invalid JSON.
func parseSARIF(t *testing.T, findings ...analyze.Finding) map[string]any {
	t.Helper()
	res := []*analyze.Result{
		{
			SchemaVersion: analyze.SchemaVersion,
			Target:        "debian:12",
			Mode:          "image",
			Findings:      findings,
			Descriptor:    &analyze.Descriptor{Version: "v9.9.9"},
		},
	}
	out, err := renderSARIF(res)
	if err != nil {
		t.Fatalf("renderSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, out)
	}
	return doc
}

// firstRun returns the single run and its results/rules for convenience.
func firstRun(t *testing.T, doc map[string]any) (results []any, rules []any) {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("want exactly one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	results, _ = run["results"].([]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules, _ = driver["rules"].([]any)
	return results, rules
}

// The document must name the tool and version and declare SARIF 2.1.0, or a
// dashboard will reject it before reading a single result.
func TestSARIFHasToolAndVersion(t *testing.T) {
	doc := parseSARIF(t, gccTrio...)

	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	_, rules := firstRun(t, doc)
	if len(rules) == 0 {
		t.Fatal("no rules emitted")
	}
	runs := doc["runs"].([]any)
	driver := runs[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "vexscan" {
		t.Errorf("driver name = %v, want vexscan", driver["name"])
	}
	if driver["version"] != "v9.9.9" {
		t.Errorf("driver version = %v, want v9.9.9", driver["version"])
	}
}

// The whole point of SARIF from a VEX tool: a ruled-out finding is a suppressed
// result carrying its justification, and an affected finding is not suppressed.
func TestSARIFSuppressesRuledOutFindings(t *testing.T) {
	results, _ := firstRun(t, parseSARIF(t, gccTrio...))

	var suppressed, open int
	for _, r := range results {
		m := r.(map[string]any)
		props := m["properties"].(map[string]any)
		status := props["status"].(string)
		_, hasSup := m["suppressions"]
		switch status {
		case "not_present", "not_in_execute_path":
			if !hasSup {
				t.Errorf("ruled-out finding (%s) was not suppressed: %v", status, m)
			}
			suppressed++
			sup := m["suppressions"].([]any)[0].(map[string]any)
			if sup["kind"] != "external" {
				t.Errorf("suppression kind = %v, want external", sup["kind"])
			}
			if sup["justification"] == "" {
				t.Errorf("suppressed result carries no justification: %v", sup)
			}
		default:
			if hasSup {
				t.Errorf("affected finding (%s) was suppressed: %v", status, m)
			}
			open++
		}
	}
	// gccTrio is one not_present and two linked.
	if suppressed != 1 || open != 2 {
		t.Errorf("suppressed=%d open=%d, want 1 and 2", suppressed, open)
	}
}

// A single advisory across three packages must produce one rule referenced by
// three results, not three duplicate rules.
func TestSARIFDedupesRulesByAdvisory(t *testing.T) {
	results, rules := firstRun(t, parseSARIF(t, gccTrio...))

	if len(rules) != 1 {
		t.Fatalf("want 1 deduped rule, got %d", len(rules))
	}
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}
	rule := rules[0].(map[string]any)
	if rule["id"] != "DEBIAN-CVE-2022-27943" {
		t.Errorf("rule id = %v", rule["id"])
	}
	for _, r := range results {
		if r.(map[string]any)["ruleId"] != "DEBIAN-CVE-2022-27943" {
			t.Errorf("result ruleId = %v", r.(map[string]any)["ruleId"])
		}
	}
}

// GitHub code scanning colours an alert from the rule's security-severity, a
// CVSS number. It must be derived from the vector the finding carries.
func TestSARIFCarriesSecuritySeverity(t *testing.T) {
	_, rules := firstRun(t, parseSARIF(t, gccTrio...))
	rule := rules[0].(map[string]any)
	props := rule["properties"].(map[string]any)
	sev, ok := props["security-severity"].(string)
	if !ok || sev == "" {
		t.Fatalf("no security-severity on rule: %v", props)
	}
	// The gccTrio vector scores 5.5 (medium).
	if !strings.HasPrefix(sev, "5.") {
		t.Errorf("security-severity = %q, want the CVSS score of the vector", sev)
	}
}

// A finding with no location must still anchor to something, or the result is
// unplaceable and a dashboard drops it.
func TestSARIFAnchorsFindingsWithoutAPath(t *testing.T) {
	f := analyze.Finding{
		Ecosystem: "os", ID: "CVE-2024-0001", CVE: "CVE-2024-0001",
		Package: "openssl", Module: "openssl", Version: "3.0.0",
		PURL:   "pkg:deb/debian/openssl@3.0.0",
		Status: analyze.StatusLinked, Severity: "HIGH",
	}
	results, _ := firstRun(t, parseSARIF(t, f))
	locs, ok := results[0].(map[string]any)["locations"].([]any)
	if !ok || len(locs) == 0 {
		t.Fatalf("finding without a path got no location: %v", results[0])
	}
}
