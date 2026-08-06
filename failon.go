package main

import (
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
)

// exitGate is the status --fail-on uses when it trips.
//
// Three and not one, deliberately. Exit 1 means the scan did not complete --
// an ecosystem errored, a package database could not be read -- and a caller
// that cannot tell that apart from "the scan worked and found something" has
// lost the distinction the whole tool is built on. trivy overloads 1 for both;
// this does not.
const exitGate = 3

// severityAny is the --fail-on rung meaning "any counted finding, whatever it
// is rated". It sorts below every real label, including the two that have no
// number behind them.
const severityAny = "ANY"

// failOn is a parsed --fail-on / --fail-on-status pair.
//
// The gate is off unless --fail-on was given, so no existing pipeline changes
// behaviour by upgrading.
type failOn struct {
	// label is the threshold as this package spells it, or severityAny.
	label string
	// rank is the highest cvss.Rank a finding may have and still count.
	// Ordering follows cvss.Rank rather than a second table, so the gate and
	// the table agree about where an unrated finding sits: above MEDIUM, below
	// HIGH. One rule, not two.
	rank int
	// classes is the set of finding classes that are weighed at all.
	classes map[findingClass]bool
	// spelling is what the user typed, echoed back in the messages.
	spelling string
	on       bool
}

// findingClass is the coarse bucket --fail-on-status selects on. It is the same
// four-way split the report's sections use, named the same way, because a user
// choosing what to gate on is looking at that report.
type findingClass string

const (
	classAffected     findingClass = "affected"     // vulnerable code present and loadable
	classUndetermined findingClass = "undetermined" // no conclusion could be reached
	classVexed        findingClass = "vexed"        // a vendor statement rules it out
	classCleared      findingClass = "cleared"      // the presence test ruled it out
)

// failOnClasses is every name --fail-on-status accepts, plus the "all" that
// selects the lot.
var failOnClasses = []findingClass{classAffected, classUndetermined, classVexed, classCleared}

// classify puts a finding in exactly one bucket.
//
// Vexed is checked first and wins: a finding a vendor has ruled out is still
// linked, so without the precedence it would count as affected and a gate set
// to "affected" would fire on exactly the findings the VEX document exists to
// quiet.
func classify(f analyze.Finding) findingClass {
	switch {
	case alreadyVexed(f):
		return classVexed
	case f.Affected():
		return classAffected
	case f.Status == analyze.StatusUndetermined:
		return classUndetermined
	default:
		return classCleared
	}
}

// parseFailOn turns the two flags into a gate, or reports what was wrong with
// them.
//
// Both are strict, for the reason --severity is strict: a threshold that never
// matches because of a typo is a gate that silently passes everything, which is
// the one failure this must not have.
func parseFailOn(severity, statuses string) (failOn, error) {
	if strings.TrimSpace(severity) == "" {
		if strings.TrimSpace(statuses) != "" && statuses != string(classAffected) {
			return failOn{}, fmt.Errorf("--fail-on-status has no effect without --fail-on")
		}
		return failOn{}, nil
	}

	f := failOn{on: true, spelling: strings.TrimSpace(severity)}
	if strings.EqualFold(f.spelling, severityAny) {
		f.label, f.rank = severityAny, len(cvss.Labels)+1
	} else {
		label, ok := cvss.Parse(severity)
		if !ok {
			return failOn{}, fmt.Errorf("unknown --fail-on %q; want one of %s, or any",
				severity, strings.Join(cvss.Labels, ", "))
		}
		f.label, f.rank = label, cvss.Rank(label)
	}

	f.classes = map[findingClass]bool{}
	if strings.TrimSpace(statuses) == "" {
		statuses = string(classAffected)
	}
	for _, part := range strings.Split(statuses, ",") {
		name := findingClass(strings.ToLower(strings.TrimSpace(part)))
		switch {
		case name == "":
			continue
		case name == "all":
			for _, c := range failOnClasses {
				f.classes[c] = true
			}
		default:
			var known bool
			for _, c := range failOnClasses {
				if c == name {
					known = true
				}
			}
			if !known {
				return failOn{}, fmt.Errorf("unknown --fail-on-status %q; want all, or a comma-separated list of %s",
					part, joinClasses())
			}
			f.classes[name] = true
		}
	}
	if len(f.classes) == 0 {
		return failOn{}, fmt.Errorf("--fail-on-status selected nothing; want all, or a comma-separated list of %s", joinClasses())
	}
	return f, nil
}

func joinClasses() string {
	names := make([]string, len(failOnClasses))
	for i, c := range failOnClasses {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

// gateResult is what the gate saw.
type gateResult struct {
	// counted is how many findings were in the selected classes at all.
	counted int
	// tripped is how many of those met the severity threshold.
	tripped int
	// unweighable is how many counted findings carry no published severity and
	// so could not meet a threshold above UNKNOWN. Reported rather than
	// dropped: on SUSE, which publishes no CVSS at all, this is nearly every
	// finding, and a gate that passes because it could not read a number must
	// say so.
	unweighable int
}

// evaluate runs the gate over a completed scan.
func (f failOn) evaluate(res *analyze.Result) gateResult {
	var g gateResult
	unknownRank := cvss.Rank(cvss.Unknown)
	for _, finding := range res.Findings {
		if !f.classes[classify(finding)] {
			continue
		}
		g.counted++
		rank := cvss.Rank(cvss.Display(finding.Severity))
		if f.label == severityAny || rank <= f.rank {
			g.tripped++
			continue
		}
		// Only worth mentioning when the threshold sits above UNKNOWN, which
		// is the only case where a missing rating is what kept the finding
		// out. Below that, an unrated finding already counts.
		if rank == unknownRank && f.rank < unknownRank {
			g.unweighable++
		}
	}
	return g
}

// describe is the one-line reason the gate tripped.
func (f failOn) describe(g gateResult) string {
	classes := make([]string, 0, len(failOnClasses))
	for _, c := range failOnClasses {
		if f.classes[c] {
			classes = append(classes, string(c))
		}
	}
	at := "at or above " + f.label
	if f.label == severityAny {
		at = "at any severity"
	}
	return fmt.Sprintf("gate: %d %s finding(s) %s (--fail-on %s)",
		g.tripped, strings.Join(classes, "/"), at, f.spelling)
}
