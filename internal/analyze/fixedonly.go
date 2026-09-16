package analyze

import (
	"github.com/cwayne18/vexscan/internal/cvss"
)

// WithheldUnfixed records what --fixed-only removed from the result.
//
// It is Withheld's counterpart and exists for the same reason: a filtered
// report and a clean one look identical, and that is the one confusion this
// tool must never cause. It is a separate type rather than a second reason on
// Withheld because the two hide different populations for different reasons,
// and a reader who used both flags is owed both numbers.
//
// Like Withheld it is deliberately not part of Failed(). The scan read
// everything it meant to; the reader asked for a subset.
type WithheldUnfixed struct {
	Count int `json:"count"`
	// BySeverity is what was dropped, keyed by label.
	BySeverity map[string]int `json:"by_severity"`
	// Affected is how many of the dropped findings were AFFECTED: vulnerable,
	// with no published version to upgrade to. That is the number that makes
	// this filter dangerous, so it is reported separately rather than left to
	// be inferred from the severity spread. An unfixed AFFECTED finding is not
	// noise -- it is work this tool cannot tell you how to finish, and hiding
	// it is the whole point of the flag and the whole risk of it.
	Affected int `json:"affected"`
}

// fixedOnlyFilter keeps only the findings a published fix exists for, and
// reports what it dropped.
//
// off is a no-op returning a nil WithheldUnfixed, which is how an unfiltered
// run produces neither a JSON field nor a banner.
//
// This runs after fixedOverlay rather than beside severityFilter, and it has
// to: FixedVersion is empty on almost every finding until that overlay fills
// it in, so filtering earlier would hide the fixable rows -- the exact
// population the flag exists to show. It still runs before the VEX, distro,
// triage and LLM overlays, so nothing downstream is billed for or counts a row
// nobody will read.
//
// The question asked is only "did anyone publish a fix", not "is this finding
// affecting you". Those are separate axes and conflating them would make the
// flag mean something no reader of --ignore-unfixed expects: a not_present
// finding with a fix stays, and an AFFECTED one without a fix goes. The second
// half of that is why the banner says how many AFFECTED rows it took.
func fixedOnlyFilter(findings []Finding, on bool) ([]Finding, *WithheldUnfixed) {
	if !on {
		return findings, nil
	}

	kept := make([]Finding, 0, len(findings))
	w := &WithheldUnfixed{BySeverity: map[string]int{}}
	for _, f := range findings {
		if hasFix(f) || alwaysReport(f) {
			kept = append(kept, f)
			continue
		}
		w.Count++
		w.BySeverity[cvss.Display(f.Severity)]++
		if f.Affected() {
			w.Affected++
		}
	}
	if w.Count == 0 {
		// Nothing was hidden, so there is nothing to warn about. See
		// severityFilter: a banner saying "withheld 0" trains a reader to skip
		// the line that will one day say something.
		return kept, nil
	}
	return kept, w
}

// hasFix reports whether any version was published that closes this advisory
// for this package.
//
// Both fields are checked even though fixedOverlay sets FixedVersions only
// alongside FixedVersion. The list is the raw thing the advisory said and the
// singular is this tool's pick out of it, so a future pick that declines to
// choose would leave the list populated and the singular empty. Keeping the
// finding on that shape over-reports, which is the direction this tool errs in.
func hasFix(f Finding) bool {
	return f.FixedVersion != "" || len(f.FixedVersions) > 0
}
