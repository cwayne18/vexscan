package analyze

import (
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// Withheld records what --severity removed from the result.
//
// It exists because a filtered report and a clean one look identical, and that
// is the one confusion this tool must never cause. Every renderer prints this
// before the findings, so a short list is always accompanied by the reason it
// is short.
//
// It is deliberately not part of Failed(). The scan completed and read
// everything it meant to; the reader asked for a subset of what it found. That
// is the opposite of an ecosystem that could not be inventoried, where the tool
// does not know what it missed.
type Withheld struct {
	// Severities is what --severity asked to keep, so the banner can quote the
	// flag back rather than making the reader remember what they typed.
	Severities []string `json:"severities"`
	Count      int      `json:"count"`
	// BySeverity is what was dropped, keyed by label. UNKNOWN in here is the
	// entry that matters: those findings are unrated, not unimportant.
	BySeverity map[string]int `json:"by_severity"`
}

// severityFilter keeps only the findings whose severity was asked for, and
// reports what it dropped.
//
// An empty keep-list is a no-op returning a nil Withheld, which is how an
// unfiltered run produces neither a JSON field nor a banner.
//
// Matching is on cvss.Display, so a finding no advisory resolved for and one
// whose advisory published no rating are both UNKNOWN here -- the same fact
// they already are to a reader. UNKNOWN is therefore a severity you can ask
// for, and one you have to ask for: --severity CRITICAL,HIGH drops it. That is
// Trivy's behavior and it is what a reader of the flag expects, but it is worth
// being clear-eyed that on debian:12 it hides 36 findings whose only crime is
// that their record is CVSS v4-only, and on --repo it hides every Go finding
// there is. The banner exists because of that, not in spite of it.
func severityFilter(findings []Finding, keep []string) ([]Finding, *Withheld) {
	if len(keep) == 0 {
		return findings, nil
	}
	wanted := make(map[string]bool, len(keep))
	for _, s := range keep {
		wanted[cvss.Display(s)] = true
	}

	kept := make([]Finding, 0, len(findings))
	w := &Withheld{Severities: keep, BySeverity: map[string]int{}}
	for _, f := range findings {
		if wanted[cvss.Display(f.Severity)] || alwaysReport(f) {
			kept = append(kept, f)
			continue
		}
		w.Count++
		w.BySeverity[cvss.Display(f.Severity)]++
	}
	if w.Count == 0 {
		// Nothing was hidden, so there is nothing to warn about. A banner
		// saying "withheld 0 findings" is noise that trains a reader to skip
		// the line that will one day say something.
		return kept, nil
	}
	return kept, w
}

// alwaysReport is the one exemption from the filter: a finding that exists to
// account for an id the user named by hand.
//
// unmapped emits these so that a --cves id which matched no component anywhere
// still appears in the output, on the grounds that "a missing id reads as a
// clean one". They carry no severity, so a severity filter would delete every
// one of them and recreate exactly the silence unmapped was written to prevent
// -- and it would do it to the ids the reader was most explicitly asking about.
func alwaysReport(f Finding) bool {
	return f.Reason == "no_component_matched" && f.Status == ecosystem.StatusUndetermined
}
