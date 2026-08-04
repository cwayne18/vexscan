// Package cvss scores CVSS v3 base vectors.
//
// It exists so a report can be sorted by something other than package name. It
// is deliberately the smallest thing that does that job: base metrics only, no
// temporal or environmental score, and no attempt to be a general CVSS library.
//
// Only CVSS:3.0 and CVSS:3.1 are scored. v2 is long dead and appears in no
// record this tool queries; v4.0 does appear, and is not scored on purpose --
// its base score is not a formula but a 270-entry MacroVector lookup with an
// interpolation step over it, which is a great deal of transcribed table to get
// subtly wrong. An unscored vector reports no severity at all, which is true,
// rather than a number that looks authoritative and is not.
package cvss

import (
	"math"
	"strings"
)

// Severity labels, in the vocabulary the report prints.
const (
	Critical = "CRITICAL"
	High     = "HIGH"
	Medium   = "MEDIUM"
	Low      = "LOW"
	None     = "NONE"
	// Unknown is what an unscorable or absent vector produces. It is a
	// distinct value rather than an empty string because the difference
	// between "nobody published a severity" and "the severity is low" is
	// exactly the difference this tool exists to preserve.
	Unknown = "UNKNOWN"
)

// Labels is every severity in this package's vocabulary, in Rank order.
//
// Anything that walks the severities -- a summary line, a --severity flag's
// help text, the set of names that flag accepts -- walks this, so a seventh
// label cannot be taught to one of them and not the others.
var Labels = []string{Critical, High, Unknown, Medium, Low, None}

// metric weights, from the CVSS v3.1 specification, section 7.4. The v3.0
// weights are identical for every base metric; the two versions differ only in
// the roundup function and in some wording, which is why both are accepted.
var (
	attackVector = map[string]float64{
		"N": 0.85, // Network
		"A": 0.62, // Adjacent
		"L": 0.55, // Local
		"P": 0.2,  // Physical
	}
	attackComplexity = map[string]float64{
		"L": 0.77, // Low
		"H": 0.44, // High
	}
	// Privileges Required is scope-dependent: a scope change makes holding
	// privileges in the vulnerable component worth more to an attacker,
	// because the impact lands somewhere else.
	privilegesRequired = map[string]struct{ unchanged, changed float64 }{
		"N": {0.85, 0.85}, // None
		"L": {0.62, 0.68}, // Low
		"H": {0.27, 0.5},  // High
	}
	userInteraction = map[string]float64{
		"N": 0.85, // None
		"R": 0.62, // Required
	}
	impact = map[string]float64{
		"H": 0.56, // High
		"L": 0.22, // Low
		"N": 0.0,  // None
	}
)

// Score returns the CVSS base score for a v3 vector.
//
// The second return is false for anything it will not score: another CVSS
// version, a vector missing a base metric, or an unrecognized metric value.
// Callers must treat that as "no severity", never as zero -- a 0.0 base score
// is a real CVSS answer meaning no impact.
func Score(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, false
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		metrics[k] = v
	}

	// Scope is read first because Privileges Required depends on it.
	scopeChanged := false
	switch metrics["S"] {
	case "U":
	case "C":
		scopeChanged = true
	default:
		return 0, false
	}

	av, ok1 := attackVector[metrics["AV"]]
	ac, ok2 := attackComplexity[metrics["AC"]]
	pr, ok3 := privilegesRequired[metrics["PR"]]
	ui, ok4 := userInteraction[metrics["UI"]]
	c, ok5 := impact[metrics["C"]]
	i, ok6 := impact[metrics["I"]]
	a, ok7 := impact[metrics["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}
	prWeight := pr.unchanged
	if scopeChanged {
		prWeight = pr.changed
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))
	var isc float64
	if scopeChanged {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		isc = 6.42 * iscBase
	}
	// No impact means no score, whatever the exploitability metrics say. This
	// is checked before the exploitability arithmetic because the spec defines
	// the result as exactly zero rather than as something that rounds to it.
	if isc <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * prWeight * ui

	score := isc + exploitability
	if scopeChanged {
		score *= 1.08
	}
	if score > 10 {
		score = 10
	}
	return roundUp(score), true
}

// roundUp is the specification's Roundup: the smallest number to one decimal
// place that is greater than or equal to the input.
//
// It is done in integer arithmetic, as CVSS v3.1 spells out, rather than with
// math.Ceil(x*10)/10. The float version disagrees with the specification on
// values whose binary representation lands just below an exact tenth --
// 4.02 * 100 is 401.99999999999994, and ceil of that gives 4.1 where the
// answer is 4.0.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// Label maps a base score onto the qualitative rating scale from the CVSS v3.1
// specification, section 5.
func Label(score float64) string {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0.0:
		return Low
	default:
		return None
	}
}

// Rank orders severity labels for display, most urgent first.
//
// Unknown ranks above Medium rather than below Low, which is the one choice
// here that is not simply the scale. A severity nobody published is not
// evidence that the problem is small, and sorting it to the bottom of a
// several-hundred-row report is how it stops being read at all. Putting it
// above the ratings we know to be middling costs a little precision in the
// ordering and buys the property that no finding is quietly demoted for
// missing metadata.
func Rank(label string) int {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case Critical:
		return 0
	case High:
		return 1
	case Unknown, "":
		return 2
	case Medium:
		return 3
	case Low:
		return 4
	case None:
		return 5
	default:
		return 6
	}
}

// Display is the label to show a reader, and the one to filter on.
//
// An empty label means no advisory was resolved for the finding at all, which
// is not the same fact as an advisory that published no rating -- the resolver
// keeps them distinct on purpose. To a reader deciding what to look at they are
// the same fact, so both arrive here as UNKNOWN rather than one of them
// rendering as a blank cell or slipping through a severity filter.
func Display(label string) string {
	if strings.TrimSpace(label) == "" {
		return Unknown
	}
	return label
}

// Parse maps a severity a user typed onto this package's vocabulary, strictly.
//
// Unlike Normalize, an unrecognized name fails instead of becoming Unknown.
// That difference is the whole reason this exists: Normalize("CRITCAL") is
// UNKNOWN, so a typo in --severity would silently ask for exactly the unrated
// findings rather than the critical ones -- the worst available misreading of
// the intent. A caller with a typo gets an error and a list of the real names.
func Parse(s string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case Critical:
		return Critical, true
	case High:
		return High, true
	case Medium, "MODERATE":
		// MODERATE is accepted for the same reason Normalize accepts it: it is
		// what GitHub prints, so it is what someone copying a severity out of
		// an advisory page will type.
		return Medium, true
	case Low:
		return Low, true
	case None:
		return None, true
	case Unknown:
		return Unknown, true
	default:
		return "", false
	}
}

// Normalize maps a severity label published by a database onto this package's
// vocabulary.
//
// The one that matters is GitHub's, which says MODERATE where every other
// source says MEDIUM. Anything unrecognized becomes Unknown rather than being
// passed through, so a new spelling from some database cannot land in the
// report as a severity the sort order does not know about.
func Normalize(label string) string {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case Critical:
		return Critical
	case High:
		return High
	case Medium, "MODERATE":
		return Medium
	case Low:
		return Low
	case None:
		return None
	default:
		return Unknown
	}
}
