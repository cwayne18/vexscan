package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// SARIF output.
//
// SARIF is the format GitHub code scanning, and most CI security dashboards,
// ingest. Emitting it lets a vexscan run land in the Security tab beside every
// other scanner -- but with the one thing this tool has that they do not: a
// finding the deterministic tests ruled out is emitted as a *suppressed*
// result, carrying its OpenVEX justification, so the dashboard shows it as
// dismissed-with-a-reason rather than as noise a human has to triage again.
//
// The mapping is deliberately narrow. Every finding becomes one result; the
// two RULED OUT statuses (not_present, not_in_execute_path) become suppressed
// results, and everything else stays an open result. Nothing here invents a
// severity or a location it did not already have.

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	sarifInfoURI = "https://github.com/cwayne18/vexscan"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
	Props   map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	DefaultConfig    *sarifConfig   `json:"defaultConfiguration,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string          `json:"ruleId"`
	RuleIndex    int             `json:"ruleIndex"`
	Level        string          `json:"level"`
	Message      sarifText       `json:"message"`
	Locations    []sarifLocation `json:"locations,omitempty"`
	Suppressions []sarifSuppress `json:"suppressions,omitempty"`
	Properties   map[string]any  `json:"properties,omitempty"`
}

type sarifSuppress struct {
	Kind          string `json:"kind"`          // "external" -- decided outside the review
	Justification string `json:"justification"` // the OpenVEX justification
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// renderSARIF turns a scan result into a SARIF 2.1.0 document.
func renderSARIF(r []*analyze.Result) (string, error) {
	var (
		version   string
		sarifRuns []sarifRun
	)
	for _, res := range r {
		if res.Descriptor != nil {
			version = res.Descriptor.Version
		}

		// One rule per advisory id, in first-seen order so the document is stable.
		ruleIndex := map[string]int{}
		var rules []sarifRule
		var results []sarifResult

		for _, f := range res.Findings {
			id := ruleID(f)
			idx, ok := ruleIndex[id]
			if !ok {
				idx = len(rules)
				ruleIndex[id] = idx
				rules = append(rules, ruleFor(f, id))
			}
			results = append(results, resultFor(f, id, idx))
		}

		sarifRuns = append(sarifRuns, sarifRun{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "vexscan",
				Version:        version,
				InformationURI: sarifInfoURI,
				Rules:          rules,
			}},
			Results: results,
			Props:   runProperties(res),
		})
	}

	doc := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: sarifRuns}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("sarif: %w", err)
	}
	return string(b) + "\n", nil
}

// ruleID is the advisory id a finding is reported under. It matches the id the
// text report prints, so a reader can join the two.
func ruleID(f analyze.Finding) string {
	if f.ID != "" {
		return f.ID
	}
	if f.CVE != "" {
		return f.CVE
	}
	if f.GoID != "" {
		return f.GoID
	}
	return "UNKNOWN"
}

func ruleFor(f analyze.Finding, id string) sarifRule {
	r := sarifRule{
		ID:               id,
		Name:             id,
		ShortDescription: sarifText{Text: fmt.Sprintf("%s in %s", id, f.Package)},
		HelpURI:          advisoryURL(id),
		Properties:       map[string]any{},
	}
	// GitHub code scanning reads security-severity off the rule to colour the
	// alert. It wants a CVSS number; derive it from the vector when present, or
	// map the label to the low end of its band so an unscored-but-rated finding
	// still lands in the right bucket.
	if sev := securitySeverity(f); sev != "" {
		r.Properties["security-severity"] = sev
	}
	if f.Severity != "" {
		r.Properties["severity"] = f.Severity
	}
	tags := []string{"security", "vulnerability"}
	if f.Ecosystem != "" {
		tags = append(tags, f.Ecosystem)
	}
	r.Properties["tags"] = tags
	r.DefaultConfig = &sarifConfig{Level: level(f)}
	return r
}

func resultFor(f analyze.Finding, id string, idx int) sarifResult {
	res := sarifResult{
		RuleID:     id,
		RuleIndex:  idx,
		Level:      level(f),
		Message:    sarifText{Text: message(f, id)},
		Locations:  locations(f),
		Properties: resultProperties(f),
	}
	// A ruled-out finding is a suppressed result: the vulnerable code is not
	// present or not reachable, and the OpenVEX justification says which. This
	// is the whole reason to emit SARIF from a VEX tool -- the dashboard shows
	// it dismissed-with-a-reason instead of asking a human to triage it again.
	if f.Status == ecosystem.StatusNotPresent || f.Status == ecosystem.StatusNotInPath {
		res.Suppressions = []sarifSuppress{{
			Kind:          "external",
			Justification: suppressionText(f),
		}}
	}
	return res
}

// level is the SARIF severity for a result. Critical and High are errors,
// Medium warns, everything below notes; an unrated finding warns, matching the
// tool's rule of ranking UNKNOWN above Medium rather than treating it as safe.
func level(f analyze.Finding) string {
	switch f.Severity {
	case cvss.Critical, cvss.High:
		return "error"
	case cvss.Medium:
		return "warning"
	case cvss.Low, cvss.None:
		return "note"
	default: // UNKNOWN or unresolved
		return "warning"
	}
}

// securitySeverity is the CVSS number GitHub code scanning wants, as a string.
func securitySeverity(f analyze.Finding) string {
	if score, ok := cvss.Score(f.CVSS); ok {
		return fmt.Sprintf("%.1f", score)
	}
	switch f.Severity {
	case cvss.Critical:
		return "9.0"
	case cvss.High:
		return "7.0"
	case cvss.Medium:
		return "4.0"
	case cvss.Low:
		return "0.1"
	case cvss.None:
		return "0.0"
	}
	return ""
}

func message(f analyze.Finding, id string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s affects %s", id, f.Package)
	if f.Version != "" {
		fmt.Fprintf(&b, " %s", f.Version)
	}
	fmt.Fprintf(&b, " (status: %s", f.Status)
	if f.Method != "" {
		fmt.Fprintf(&b, ", %s", f.Method)
	}
	b.WriteString(")")
	if f.FixedVersion != "" {
		fmt.Fprintf(&b, ". Fixed in %s", f.FixedVersion)
	}
	return b.String()
}

func locations(f analyze.Finding) []sarifLocation {
	uri := f.Location
	if uri == "" {
		// No path inside the target: point at the component itself, so the
		// result still anchors to something rather than to nothing.
		uri = f.PURL
	}
	if uri == "" {
		uri = f.Package
	}
	if uri == "" {
		return nil
	}
	return []sarifLocation{{PhysicalLocation: sarifPhysical{
		ArtifactLocation: sarifArtifact{URI: strings.TrimPrefix(uri, "/")},
	}}}
}

func resultProperties(f analyze.Finding) map[string]any {
	p := map[string]any{"status": string(f.Status)}
	if f.PURL != "" {
		p["purl"] = f.PURL
	}
	if f.Package != "" {
		p["package"] = f.Package
	}
	if f.Version != "" {
		p["version"] = f.Version
	}
	if f.FixedVersion != "" {
		p["fixed_version"] = f.FixedVersion
	}
	if f.Method != "" {
		p["method"] = f.Method
	}
	if f.Justification != "" {
		p["justification"] = f.Justification
	}
	if f.Reason != "" {
		p["reason"] = f.Reason
	}
	if f.Ecosystem != "" {
		p["ecosystem"] = f.Ecosystem
	}
	if f.Priority != nil {
		if f.Priority.Scored {
			p["epss"] = f.Priority.EPSS
			p["epss_percentile"] = f.Priority.Percentile
		}
		if f.Priority.KEV != nil {
			p["known_exploited"] = true
		}
	}
	return p
}

// suppressionText is the justification carried on a suppressed (ruled-out)
// result. It reuses the finding's OpenVEX justification, falling back to the
// status where a plugin recorded none.
func suppressionText(f analyze.Finding) string {
	if f.Justification != "" {
		return f.Justification
	}
	if f.Status == ecosystem.StatusNotInPath {
		return "vulnerable_code_not_in_execute_path"
	}
	return "vulnerable_code_not_present"
}

func runProperties(res *analyze.Result) map[string]any {
	p := map[string]any{}
	if res.Target != "" {
		p["target"] = res.Target
	}
	if res.Mode != "" {
		p["mode"] = res.Mode
	}
	if res.Descriptor != nil && !res.Descriptor.AdvisoriesAsOf.IsZero() {
		p["advisories_as_of"] = res.Descriptor.AdvisoriesAsOf
	}
	if len(p) == 0 {
		return nil
	}
	return p
}

// advisoryURL links a rule to a human-readable record. CVEs go to NVD, GHSAs to
// GitHub, everything else to OSV, which aliases them all.
func advisoryURL(id string) string {
	up := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(up, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(up, "GHSA-"):
		return "https://github.com/advisories/" + id
	case id == "" || id == "UNKNOWN":
		return ""
	default:
		return "https://osv.dev/vulnerability/" + id
	}
}
