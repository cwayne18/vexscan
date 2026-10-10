package cvss

import (
	"math/big"
	"strings"
)

// This file scores CVSS:4.0 base (plus optional threat and environmental)
// vectors. Unlike v3, a v4.0 base score is not a closed-form formula: it is a
// 270-entry table of "MacroVector" scores -- one worst-case score per
// combination of six equivalence classes the metrics sort a vector into --
// plus an interpolation step that places a vector between its MacroVector and
// the next less severe one. v4Lookup, v4MaxComposed and v4MaxSeverity below
// are transcribed from the CVSS v4.0 specification's own reference
// calculator (https://github.com/FIRSTdotorg/cvss-calculator, BSD-2-Clause,
// copyright FIRST, Red Hat and contributors), not reconstructed from the
// prose spec, for the same reason the package doc gives for refusing to score
// v4.0 at all otherwise: this table is too easy to transcribe subtly wrong
// from scratch, so it is copied from the authors' own implementation instead
// and pinned against its published test vectors in v4_test.go.

// v4Lookup is the MacroVector score table: a six-digit key, one digit per
// equivalence class (EQ1..EQ6) in order, to the score of the single most
// severe vector in that class. Not every combination is reachable -- EQ3=2
// forces EQ6=1, for instance -- so this has exactly 270 entries, not 3*2*3*
// 3*3*2.
var v4Lookup = map[string]float64{
	"000000": 10.0,
	"000001": 9.9,
	"000010": 9.8,
	"000011": 9.5,
	"000020": 9.5,
	"000021": 9.2,
	"000100": 10.0,
	"000101": 9.6,
	"000110": 9.3,
	"000111": 8.7,
	"000120": 9.1,
	"000121": 8.1,
	"000200": 9.3,
	"000201": 9.0,
	"000210": 8.9,
	"000211": 8.0,
	"000220": 8.1,
	"000221": 6.8,
	"001000": 9.8,
	"001001": 9.5,
	"001010": 9.5,
	"001011": 9.2,
	"001020": 9.0,
	"001021": 8.4,
	"001100": 9.3,
	"001101": 9.2,
	"001110": 8.9,
	"001111": 8.1,
	"001120": 8.1,
	"001121": 6.5,
	"001200": 8.8,
	"001201": 8.0,
	"001210": 7.8,
	"001211": 7.0,
	"001220": 6.9,
	"001221": 4.8,
	"002001": 9.2,
	"002011": 8.2,
	"002021": 7.2,
	"002101": 7.9,
	"002111": 6.9,
	"002121": 5.0,
	"002201": 6.9,
	"002211": 5.5,
	"002221": 2.7,
	"010000": 9.9,
	"010001": 9.7,
	"010010": 9.5,
	"010011": 9.2,
	"010020": 9.2,
	"010021": 8.5,
	"010100": 9.5,
	"010101": 9.1,
	"010110": 9.0,
	"010111": 8.3,
	"010120": 8.4,
	"010121": 7.1,
	"010200": 9.2,
	"010201": 8.1,
	"010210": 8.2,
	"010211": 7.1,
	"010220": 7.2,
	"010221": 5.3,
	"011000": 9.5,
	"011001": 9.3,
	"011010": 9.2,
	"011011": 8.5,
	"011020": 8.5,
	"011021": 7.3,
	"011100": 9.2,
	"011101": 8.2,
	"011110": 8.0,
	"011111": 7.2,
	"011120": 7.0,
	"011121": 5.9,
	"011200": 8.4,
	"011201": 7.0,
	"011210": 7.1,
	"011211": 5.2,
	"011220": 5.0,
	"011221": 3.0,
	"012001": 8.6,
	"012011": 7.5,
	"012021": 5.2,
	"012101": 7.1,
	"012111": 5.2,
	"012121": 2.9,
	"012201": 6.3,
	"012211": 2.9,
	"012221": 1.7,
	"100000": 9.8,
	"100001": 9.5,
	"100010": 9.4,
	"100011": 8.7,
	"100020": 9.1,
	"100021": 8.1,
	"100100": 9.4,
	"100101": 8.9,
	"100110": 8.6,
	"100111": 7.4,
	"100120": 7.7,
	"100121": 6.4,
	"100200": 8.7,
	"100201": 7.5,
	"100210": 7.4,
	"100211": 6.3,
	"100220": 6.3,
	"100221": 4.9,
	"101000": 9.4,
	"101001": 8.9,
	"101010": 8.8,
	"101011": 7.7,
	"101020": 7.6,
	"101021": 6.7,
	"101100": 8.6,
	"101101": 7.6,
	"101110": 7.4,
	"101111": 5.8,
	"101120": 5.9,
	"101121": 5.0,
	"101200": 7.2,
	"101201": 5.7,
	"101210": 5.7,
	"101211": 5.2,
	"101220": 5.2,
	"101221": 2.5,
	"102001": 8.3,
	"102011": 7.0,
	"102021": 5.4,
	"102101": 6.5,
	"102111": 5.8,
	"102121": 2.6,
	"102201": 5.3,
	"102211": 2.1,
	"102221": 1.3,
	"110000": 9.5,
	"110001": 9.0,
	"110010": 8.8,
	"110011": 7.6,
	"110020": 7.6,
	"110021": 7.0,
	"110100": 9.0,
	"110101": 7.7,
	"110110": 7.5,
	"110111": 6.2,
	"110120": 6.1,
	"110121": 5.3,
	"110200": 7.7,
	"110201": 6.6,
	"110210": 6.8,
	"110211": 5.9,
	"110220": 5.2,
	"110221": 3.0,
	"111000": 8.9,
	"111001": 7.8,
	"111010": 7.6,
	"111011": 6.7,
	"111020": 6.2,
	"111021": 5.8,
	"111100": 7.4,
	"111101": 5.9,
	"111110": 5.7,
	"111111": 5.7,
	"111120": 4.7,
	"111121": 2.3,
	"111200": 6.1,
	"111201": 5.2,
	"111210": 5.7,
	"111211": 2.9,
	"111220": 2.4,
	"111221": 1.6,
	"112001": 7.1,
	"112011": 5.9,
	"112021": 3.0,
	"112101": 5.8,
	"112111": 2.6,
	"112121": 1.5,
	"112201": 2.3,
	"112211": 1.3,
	"112221": 0.6,
	"200000": 9.3,
	"200001": 8.7,
	"200010": 8.6,
	"200011": 7.2,
	"200020": 7.5,
	"200021": 5.8,
	"200100": 8.6,
	"200101": 7.4,
	"200110": 7.4,
	"200111": 6.1,
	"200120": 5.6,
	"200121": 3.4,
	"200200": 7.0,
	"200201": 5.4,
	"200210": 5.2,
	"200211": 4.0,
	"200220": 4.0,
	"200221": 2.2,
	"201000": 8.5,
	"201001": 7.5,
	"201010": 7.4,
	"201011": 5.5,
	"201020": 6.2,
	"201021": 5.1,
	"201100": 7.2,
	"201101": 5.7,
	"201110": 5.5,
	"201111": 4.1,
	"201120": 4.6,
	"201121": 1.9,
	"201200": 5.3,
	"201201": 3.6,
	"201210": 3.4,
	"201211": 1.9,
	"201220": 1.9,
	"201221": 0.8,
	"202001": 6.4,
	"202011": 5.1,
	"202021": 2.0,
	"202101": 4.7,
	"202111": 2.1,
	"202121": 1.1,
	"202201": 2.4,
	"202211": 0.9,
	"202221": 0.4,
	"210000": 8.8,
	"210001": 7.5,
	"210010": 7.3,
	"210011": 5.3,
	"210020": 6.0,
	"210021": 5.0,
	"210100": 7.3,
	"210101": 5.5,
	"210110": 5.9,
	"210111": 4.0,
	"210120": 4.1,
	"210121": 2.0,
	"210200": 5.4,
	"210201": 4.3,
	"210210": 4.5,
	"210211": 2.2,
	"210220": 2.0,
	"210221": 1.1,
	"211000": 7.5,
	"211001": 5.5,
	"211010": 5.8,
	"211011": 4.5,
	"211020": 4.0,
	"211021": 2.1,
	"211100": 6.1,
	"211101": 5.1,
	"211110": 4.8,
	"211111": 1.8,
	"211120": 2.0,
	"211121": 0.9,
	"211200": 4.6,
	"211201": 1.8,
	"211210": 1.7,
	"211211": 0.7,
	"211220": 0.8,
	"211221": 0.2,
	"212001": 5.3,
	"212011": 2.4,
	"212021": 1.4,
	"212101": 2.4,
	"212111": 1.2,
	"212121": 0.5,
	"212201": 1.0,
	"212211": 0.3,
	"212221": 0.1,
}

// v4MaxComposed lists, for each value of each equivalence class, the
// highest-severity base vector(s) in that class -- the candidates a scored
// vector is compared against to find its severity distance from the worst
// case. EQ3 and EQ6 are composed together because the scoring algorithm
// treats them as one class: EQ6 (the environmental requirements) only matters
// relative to which impact metrics EQ3 already set to High.
var v4MaxComposed = struct {
	eq1     map[string][]string
	eq2     map[string][]string
	eq3eq6  map[string]map[string][]string
	eq4     map[string][]string
	eq5     map[string][]string
}{
	eq1: map[string][]string{
		"0": {"AV:N/PR:N/UI:N/"},
		"1": {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
		"2": {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
	},
	eq2: map[string][]string{
		"0": {"AC:L/AT:N/"},
		"1": {"AC:H/AT:N/", "AC:L/AT:P/"},
	},
	eq3eq6: map[string]map[string][]string{
		"0": {
			"0": {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
			"1": {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"},
		},
		"1": {
			"0": {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
			"1": {
				"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
				"VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
				"VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
				"VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
				"VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
			},
		},
		"2": {
			"1": {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"},
		},
	},
	eq4: map[string][]string{
		"0": {"SC:H/SI:S/SA:S/"},
		"1": {"SC:H/SI:H/SA:H/"},
		"2": {"SC:L/SI:L/SA:L/"},
	},
	eq5: map[string][]string{
		"0": {"E:A/"},
		"1": {"E:P/"},
		"2": {"E:U/"},
	},
}

// v4MaxSeverity is the maximal scoring difference ("depth") of each
// equivalence class, in tenths of a point -- the denominator the severity
// distance below is divided by to turn it into a fraction of the gap to the
// next less severe MacroVector.
var v4MaxSeverity = struct {
	eq1    map[int]int
	eq2    map[int]int
	eq3eq6 map[int]map[int]int
	eq4    map[int]int
}{
	eq1: map[int]int{0: 1, 1: 4, 2: 5},
	eq2: map[int]int{0: 1, 1: 2},
	eq3eq6: map[int]map[int]int{
		0: {0: 7, 1: 6},
		1: {0: 8, 1: 8},
		2: {1: 10},
	},
	eq4: map[int]int{0: 6, 1: 5, 2: 4},
}

// v4Levels gives each metric value's position on its own severity scale, 0
// being most severe. Two metrics never appearing in the same vector (SI/SA's
// base "N/L/H" and their Safety-modified "S") share one map, since a
// vector can only ever have one of the two in play.
var v4Levels = map[string]map[string]float64{
	"AV": {"N": 0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0, "H": 0.1},
	"AT": {"N": 0, "P": 0.1},
	"VC": {"H": 0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0, "M": 0.1, "L": 0.2},
}

// v4BaseValues is the legal value set for each of the 11 base metrics, every
// one of which is mandatory.
var v4BaseValues = map[string]map[string]bool{
	"AV": set("N", "A", "L", "P"),
	"AC": set("L", "H"),
	"AT": set("N", "P"),
	"PR": set("N", "L", "H"),
	"UI": set("N", "P", "A"),
	"VC": set("H", "L", "N"),
	"VI": set("H", "L", "N"),
	"VA": set("H", "L", "N"),
	"SC": set("H", "L", "N"),
	"SI": set("H", "L", "N"),
	"SA": set("H", "L", "N"),
}

// v4OptionalValues is the legal value set for every metric this scorer reads
// but does not require: the threat metric, the three environmental
// requirements, and the 11 modified-base metrics that override a base metric
// when present. "X" ("not defined") is always legal and means the metric
// falls back to its documented default -- the worst case for E/CR/IR/AR, the
// unmodified base value for the rest. A vector's supplemental metrics
// (S, AU, R, V, RE, U) do not feed the score at all and so are never
// validated or read here, the same way this package's v3 side ignores
// temporal metrics.
var v4OptionalValues = map[string]map[string]bool{
	"E":   set("X", "A", "P", "U"),
	"CR":  set("X", "H", "M", "L"),
	"IR":  set("X", "H", "M", "L"),
	"AR":  set("X", "H", "M", "L"),
	"MAV": set("X", "N", "A", "L", "P"),
	"MAC": set("X", "L", "H"),
	"MAT": set("X", "N", "P"),
	"MPR": set("X", "N", "L", "H"),
	"MUI": set("X", "N", "P", "A"),
	"MVC": set("X", "H", "L", "N"),
	"MVI": set("X", "H", "L", "N"),
	"MVA": set("X", "H", "L", "N"),
	"MSC": set("X", "H", "L", "N"),
	"MSI": set("X", "S", "H", "L", "N"),
	"MSA": set("X", "S", "H", "L", "N"),
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// scoreV4 returns the CVSS base score for a CVSS:4.0 vector, following the
// specification's MacroVector-plus-interpolation algorithm exactly as the
// reference calculator implements it. The second return is false for
// anything it will not score: a missing or illegal base metric, or an
// illegal value for a threat/environmental/modified metric it does read.
func scoreV4(vector string) (float64, bool) {
	metrics, ok := parseVectorMetrics(vector, "CVSS:4.0/")
	if !ok {
		return 0, false
	}
	if !v4Valid(metrics) {
		return 0, false
	}

	eff := func(m string) string { return v4Effective(metrics, m) }

	// No impact on either the vulnerable or the subsequent system is a real
	// answer of exactly zero, the same shortcut the specification's own
	// calculator takes rather than running it through the table.
	if eff("VC") == "N" && eff("VI") == "N" && eff("VA") == "N" &&
		eff("SC") == "N" && eff("SI") == "N" && eff("SA") == "N" {
		return 0.0, true
	}

	eq := v4MacroVector(eff)
	value, ok := v4Lookup[eq]
	if !ok {
		// Every legal combination of the six equivalence classes has an
		// entry; reaching here would mean v4MacroVector produced a digit
		// combination the table does not carry, which is a bug in this
		// package, not an unscorable vector. Declining is still the safe
		// failure mode: no severity, not a wrong one.
		return 0, false
	}

	mean := v4MeanDistance(eff, eq, value)
	value -= mean
	switch {
	case value < 0:
		value = 0
	case value > 10:
		value = 10
	}
	return roundHalfUp1(value), true
}

// parseVectorMetrics splits a "/"-delimited CVSS vector into its metric map,
// requiring the given version prefix and every part to be a well-formed
// "key:value" pair.
func parseVectorMetrics(vector, prefix string) (map[string]string, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, prefix) {
		return nil, false
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(vector, prefix), "/") {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return nil, false
		}
		metrics[k] = v
	}
	return metrics, true
}

// v4Valid checks that every base metric is present with a legal value, and
// that every optional metric present (threat, environmental, modified-base)
// also has one.
func v4Valid(metrics map[string]string) bool {
	for m, values := range v4BaseValues {
		if !values[metrics[m]] {
			return false
		}
	}
	for m, values := range v4OptionalValues {
		if v, present := metrics[m]; present && !values[v] {
			return false
		}
	}
	return true
}

// v4Effective resolves one metric's effective value: the threat and
// environmental-requirement metrics default to their documented worst case
// when absent or "X" (not defined), and every other metric is overridden by
// its "M"-prefixed modified counterpart when one is present and defined.
func v4Effective(metrics map[string]string, metric string) string {
	switch metric {
	case "E":
		if v := metrics["E"]; v != "" && v != "X" {
			return v
		}
		return "A"
	case "CR", "IR", "AR":
		if v := metrics[metric]; v != "" && v != "X" {
			return v
		}
		return "H"
	}
	if v, ok := metrics["M"+metric]; ok && v != "X" {
		return v
	}
	return metrics[metric]
}

// v4MacroVector sorts a vector's effective metrics into the six equivalence
// classes the specification defines, returning them concatenated as a single
// six-digit string, the key into v4Lookup.
func v4MacroVector(eff func(string) string) string {
	var eq1, eq2, eq3, eq4, eq5, eq6 byte

	switch {
	case eff("AV") == "N" && eff("PR") == "N" && eff("UI") == "N":
		eq1 = '0'
	case (eff("AV") == "N" || eff("PR") == "N" || eff("UI") == "N") &&
		eff("AV") != "P":
		// The "not all three N" half of the spec's condition is implied: the
		// case above already matched and returned when all three are N.
		eq1 = '1'
	default:
		eq1 = '2'
	}

	if eff("AC") == "L" && eff("AT") == "N" {
		eq2 = '0'
	} else {
		eq2 = '1'
	}

	switch {
	case eff("VC") == "H" && eff("VI") == "H":
		eq3 = '0'
	case eff("VC") == "H" || eff("VI") == "H" || eff("VA") == "H":
		eq3 = '1'
	default:
		eq3 = '2'
	}

	switch {
	case eff("MSI") == "S" || eff("MSA") == "S":
		eq4 = '0'
	case eff("SC") == "H" || eff("SI") == "H" || eff("SA") == "H":
		eq4 = '1'
	default:
		eq4 = '2'
	}

	switch eff("E") {
	case "A":
		eq5 = '0'
	case "P":
		eq5 = '1'
	default: // "U"
		eq5 = '2'
	}

	if (eff("CR") == "H" && eff("VC") == "H") ||
		(eff("IR") == "H" && eff("VI") == "H") ||
		(eff("AR") == "H" && eff("VA") == "H") {
		eq6 = '0'
	} else {
		eq6 = '1'
	}

	return string([]byte{eq1, eq2, eq3, eq4, eq5, eq6})
}

// v4MeanDistance computes the mean, over every equivalence class that has a
// next-less-severe MacroVector, of how far the scored vector sits between its
// own MacroVector's score and that lower one's -- the amount subtracted from
// the MacroVector's score to place the vector precisely.
func v4MeanDistance(eff func(string) string, macro string, value float64) float64 {
	eq1v := int(macro[0] - '0')
	eq2v := int(macro[1] - '0')
	eq3v := int(macro[2] - '0')
	eq4v := int(macro[3] - '0')
	eq5v := int(macro[4] - '0')
	eq6v := int(macro[5] - '0')

	lowerScore := func(a, b, c, d, e, f int) (float64, bool) {
		if a > 2 || b > 1 || c > 2 || d > 2 || e > 2 || f > 1 {
			return 0, false
		}
		v, ok := v4Lookup[string([]byte{byte('0' + a), byte('0' + b), byte('0' + c), byte('0' + d), byte('0' + e), byte('0' + f)})]
		return v, ok
	}

	eq1Lower, eq1OK := lowerScore(eq1v+1, eq2v, eq3v, eq4v, eq5v, eq6v)
	eq2Lower, eq2OK := lowerScore(eq1v, eq2v+1, eq3v, eq4v, eq5v, eq6v)
	eq4Lower, eq4OK := lowerScore(eq1v, eq2v, eq3v, eq4v+1, eq5v, eq6v)
	eq5Lower, eq5OK := lowerScore(eq1v, eq2v, eq3v, eq4v, eq5v+1, eq6v)

	// EQ3 and EQ6 are composed, so their next-lower MacroVector depends on
	// both current digits. The "00" case has two candidate lower vectors
	// (lower EQ3, or lower EQ6); the specification takes whichever scores
	// higher, i.e. whichever is the smaller step down.
	var eq3eq6Lower float64
	var eq3eq6OK bool
	switch {
	case eq3v == 0 && eq6v == 0:
		left, leftOK := lowerScore(eq1v, eq2v, eq3v, eq4v, eq5v, eq6v+1)
		right, rightOK := lowerScore(eq1v, eq2v, eq3v+1, eq4v, eq5v, eq6v)
		switch {
		case leftOK && rightOK:
			if left > right {
				eq3eq6Lower, eq3eq6OK = left, true
			} else {
				eq3eq6Lower, eq3eq6OK = right, true
			}
		case leftOK:
			eq3eq6Lower, eq3eq6OK = left, true
		case rightOK:
			eq3eq6Lower, eq3eq6OK = right, true
		}
	case eq3v == 1 && eq6v == 0:
		eq3eq6Lower, eq3eq6OK = lowerScore(eq1v, eq2v, eq3v, eq4v, eq5v, eq6v+1)
	default:
		// eq3==0,eq6==1 and eq3==1,eq6==1 both step EQ3 up; eq3==2 (which
		// forces eq6==1) steps to a combination the table does not carry at
		// all, so the lookup simply misses and this class is excluded below,
		// exactly as the reference calculator's "do not exist" case intends.
		eq3eq6Lower, eq3eq6OK = lowerScore(eq1v, eq2v, eq3v+1, eq4v, eq5v, eq6v)
	}

	// The highest-severity vector(s) in this MacroVector, against which the
	// scored vector's severity distance in each class is measured.
	eq1Max := v4MaxComposed.eq1[macro[0:1]]
	eq2Max := v4MaxComposed.eq2[macro[1:2]]
	eq3eq6Max := v4MaxComposed.eq3eq6[macro[2:3]][macro[5:6]]
	eq4Max := v4MaxComposed.eq4[macro[3:4]]
	eq5Max := v4MaxComposed.eq5[macro[4:5]]

	var d1, d2, d3eq6, d4 float64
	found := false
	for _, m1 := range eq1Max {
		for _, m2 := range eq2Max {
			for _, m3 := range eq3eq6Max {
				for _, m4 := range eq4Max {
					for _, m5 := range eq5Max {
						candidate, ok := parseVectorMetrics(m1+m2+m3+m4+m5, "")
						if !ok {
							continue
						}
						dists, ok := v4Distances(eff, candidate)
						if !ok {
							continue
						}
						d1 = dists["AV"] + dists["PR"] + dists["UI"]
						d2 = dists["AC"] + dists["AT"]
						d3eq6 = dists["VC"] + dists["VI"] + dists["VA"] + dists["CR"] + dists["IR"] + dists["AR"]
						d4 = dists["SC"] + dists["SI"] + dists["SA"]
						found = true
						break
					}
					if found {
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			break
		}
	}

	step := 0.1
	maxSev1 := float64(v4MaxSeverity.eq1[eq1v]) * step
	maxSev2 := float64(v4MaxSeverity.eq2[eq2v]) * step
	maxSev3eq6 := float64(v4MaxSeverity.eq3eq6[eq3v][eq6v]) * step
	maxSev4 := float64(v4MaxSeverity.eq4[eq4v]) * step

	// The reference calculator always sums five terms -- defaulting an
	// excluded class's term to exactly 0 rather than omitting it from the
	// sum -- and only the final division is by the count of classes that did
	// have a lower MacroVector. Structuring this the same way, rather than
	// skipping terms, keeps float64 addition in the same order the
	// specification's own reference implementation uses, since floating-point
	// addition is not associative and a different term order can round a
	// knife's-edge case (one of these sums landing exactly on a tie between
	// two tenths) the other way.
	var normalized1, normalized2, normalized3eq6, normalized4, normalized5 float64
	var n int
	if eq1OK {
		n++
		normalized1 = (value - eq1Lower) * (d1 / maxSev1)
	}
	if eq2OK {
		n++
		normalized2 = (value - eq2Lower) * (d2 / maxSev2)
	}
	if eq3eq6OK {
		n++
		normalized3eq6 = (value - eq3eq6Lower) * (d3eq6 / maxSev3eq6)
	}
	if eq4OK {
		n++
		normalized4 = (value - eq4Lower) * (d4 / maxSev4)
	}
	if eq5OK {
		// EQ5 (Exploit Maturity) never contributes a fraction of its own: the
		// specification fixes its proportion at 0, so only whether a lower
		// MacroVector exists is relevant, not how close this vector in
		// particular is to it.
		n++
		normalized5 = (value - eq5Lower) * 0
	}
	if n == 0 {
		return 0
	}
	return (normalized1 + normalized2 + normalized3eq6 + normalized4 + normalized5) / float64(n)
}

// v4Distances compares the scored vector's effective metrics against one
// candidate highest-severity vector, metric by metric. ok is false if the
// candidate is not in fact at least as severe on every metric -- the scored
// vector sits outside the severity range this candidate bounds, and the
// caller must try the next candidate combination.
func v4Distances(eff func(string) string, candidate map[string]string) (map[string]float64, bool) {
	out := map[string]float64{}
	for _, m := range []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"} {
		levels := v4Levels[m]
		d := levels[eff(m)] - levels[candidate[m]]
		if d < 0 {
			return nil, false
		}
		out[m] = d
	}
	return out, true
}

// roundHalfUp1 rounds to one decimal place the way the specification's
// reference calculator does: JavaScript's toFixed(1), which the ECMA-262
// spec defines as picking whichever of the two nearest tenths is closer to
// the number's exact double-precision value, and the larger one on an exact
// tie.
//
// Both halves of that rule need exact rational arithmetic, not float64 math.
// A naive x*10+0.5 truncation can itself introduce the last bit of binary
// imprecision that tips a value the wrong way, and formatting via Go's
// strconv (which, like fmt, breaks an exact tie toward the even digit
// instead of the larger one) silently disagrees with toFixed on values like
// 4.25, which is exactly representable in binary: toFixed(1) gives "4.3",
// not the "4.2" a round-half-to-even formatter produces. big.Rat.SetFloat64
// captures x's exact value, so the comparison this performs against the tie
// point is exact too -- unlike v3's Roundup, v4.0 defines no ceiling rule,
// just "rounded to one decimal place."
func roundHalfUp1(x float64) float64 {
	r := new(big.Rat).SetFloat64(x)
	r.Mul(r, big.NewRat(10, 1))
	num, den := r.Num(), r.Denom()
	q, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	if new(big.Int).Mul(rem, big.NewInt(2)).Cmp(den) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	tenths, _ := new(big.Float).SetInt(q).Float64()
	return tenths / 10
}
