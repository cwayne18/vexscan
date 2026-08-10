// Package pep440 compares Python package versions by PEP 440's rules.
//
// It exists for the offline advisory path. Against the OSV API, whether
// cryptography 41.0.3 falls inside an advisory's range is osv.dev's answer;
// against a local data export there is nobody to ask, and PyPI is too large an
// ecosystem to hand back unchecked.
//
// Semver will not substitute for it, and the failure is silent rather than
// loud. PEP 440 sorts 1.0rc1 below 1.0 and so does semver, but 1.0.post1 above
// 1.0 where semver has no notion of it at all; 1.0.dev1 below everything;
// 1!1.0 above 2.0 because the epoch outranks the release; and 1.0 equal to
// 1.0.0 because trailing zeros are not significant. Each of those is a
// vulnerability reported as fixed, or a fix reported as vulnerable, with
// nothing on the page to say a guess was made.
//
// The grammar and the comparison are PEP 440's own, including the sort-key
// construction pypa/packaging uses:
//
//	[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]
package pep440

import (
	"regexp"
	"strconv"
	"strings"
)

// pattern is PEP 440's own VERSION_PATTERN, transcribed. Anchored, and with the
// leading "v" and surrounding space the spec permits.
//
// A regexp rather than a hand-rolled scanner because the specification is
// written as this regexp: a transcription can be read against the source, and a
// scanner can only be argued about.
var pattern = regexp.MustCompile(`^\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?` +
	`\s*$`)

// Valid reports whether v is a version PEP 440 defines.
//
// Callers must check this before acting on Compare. PyPI accepts only conforming
// versions from new uploads, but an OSV record's range boundary is written by a
// human and an installed-distribution directory can hold anything at all.
func Valid(v string) bool {
	_, ok := parse(v)
	return ok
}

// Compare returns -1 if a sorts before b, +1 if after, and 0 if equal. The
// result is meaningless unless Valid is true for both; see Valid.
func Compare(a, b string) int {
	pa, _ := parse(a)
	pb, _ := parse(b)
	return pa.compare(pb)
}

// version is a parsed version, held as the sort key PEP 440 compares rather
// than as the text it was written in. Every field below is a component of that
// key, in the order the key applies them.
type version struct {
	epoch int
	// release has its insignificant trailing zeros already dropped, which is
	// what makes 1.0 and 1.0.0 equal.
	release []int
	// pre is the pre-release, if any. The two sentinels do the work of PEP
	// 440's negative and positive infinities: a version with no pre-release
	// outranks every pre-release of the same release, unless it is a bare dev
	// release, which is outranked by all of them.
	pre    segment
	hasPre bool
	// isDevOnly marks a version with a dev release and no pre-release, the one
	// case that sorts below the pre-releases.
	isDevOnly bool

	post    int
	hasPost bool
	dev     int
	hasDev  bool
	local   []localSegment
}

// segment is a pre-release: its normalized letter and its number.
type segment struct {
	letter string
	number int
}

// localSegment is one dot-separated piece of a local version label. A numeric
// piece outranks an alphanumeric one, so which of the two this is has to
// survive parsing.
type localSegment struct {
	num   int
	str   string
	isNum bool
}

func parse(v string) (version, bool) {
	m := pattern.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return version{}, false
	}
	at := func(name string) string { return m[pattern.SubexpIndex(name)] }

	var p version
	if s := at("epoch"); s != "" {
		p.epoch = atoiSaturating(s)
	}
	for _, part := range strings.Split(at("release"), ".") {
		p.release = append(p.release, atoiSaturating(part))
	}
	// Trailing zeros carry no meaning, so they are dropped here rather than
	// compensated for at every comparison.
	for len(p.release) > 1 && p.release[len(p.release)-1] == 0 {
		p.release = p.release[:len(p.release)-1]
	}

	if l := at("pre_l"); l != "" {
		p.hasPre = true
		p.pre = segment{letter: normalizePre(l), number: atoiSaturating(at("pre_n"))}
	}

	// A post-release is spelled two ways: ".postN", and the implicit "-N" that
	// predates it. Both land in the same field.
	if n1 := at("post_n1"); n1 != "" {
		p.hasPost = true
		p.post = atoiSaturating(n1)
	} else if at("post_l") != "" {
		p.hasPost = true
		p.post = atoiSaturating(at("post_n2"))
	}

	if at("dev_l") != "" {
		p.hasDev = true
		p.dev = atoiSaturating(at("dev_n"))
	}
	p.isDevOnly = p.hasDev && !p.hasPre && !p.hasPost

	if loc := at("local"); loc != "" {
		for _, part := range strings.FieldsFunc(loc, func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		}) {
			if n, err := strconv.Atoi(part); err == nil {
				p.local = append(p.local, localSegment{num: n, isNum: true})
			} else {
				p.local = append(p.local, localSegment{str: part})
			}
		}
	}
	return p, true
}

// normalizePre folds the spellings PEP 440 treats as the same pre-release onto
// one letter, so "1.0alpha1", "1.0.a1" and "1.0-a-1" compare as one version.
func normalizePre(l string) string {
	switch l {
	case "alpha":
		return "a"
	case "beta":
		return "b"
	case "c", "pre", "preview":
		return "rc"
	}
	return l
}

// atoiSaturating reads a decimal number, clamping rather than failing. The
// regexp has already established the field is digits; a version number long
// enough to overflow is nobody's release, and refusing to order it would be a
// finding lost to a typo.
func atoiSaturating(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return int(^uint(0) >> 1)
	}
	return n
}

func (p version) compare(o version) int {
	if c := cmpInt(p.epoch, o.epoch); c != 0 {
		return c
	}
	if c := cmpInts(p.release, o.release); c != 0 {
		return c
	}

	// The pre-release comparison, with PEP 440's two infinities spelled out. A
	// bare dev release sorts below every pre-release of the same release; a
	// version with no pre-release at all sorts above them.
	pa, pb := p.preRank(), o.preRank()
	if pa != pb {
		return cmpInt(pa, pb)
	}
	if pa == 0 {
		if c := strings.Compare(p.pre.letter, o.pre.letter); c != 0 {
			return c
		}
		if c := cmpInt(p.pre.number, o.pre.number); c != 0 {
			return c
		}
	}

	// No post-release sorts below any post-release: 1.0 < 1.0.post1.
	if c := cmpInt(rank(p.hasPost, p.post, -1), rank(o.hasPost, o.post, -1)); c != 0 {
		return c
	}
	// No dev release sorts above any dev release: 1.0.dev1 < 1.0.
	if c := cmpInt(rank(p.hasDev, p.dev, maxInt), rank(o.hasDev, o.dev, maxInt)); c != 0 {
		return c
	}
	return cmpLocal(p.local, o.local)
}

const maxInt = int(^uint(0) >> 1)

// preRank places a version in one of the three pre-release bands: below the
// pre-releases (a bare dev release), among them, or above them.
func (p version) preRank() int {
	switch {
	case p.hasPre:
		return 0
	case p.isDevOnly:
		return -1
	default:
		return 1
	}
}

func rank(has bool, n, absent int) int {
	if !has {
		return absent
	}
	return n
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpInts compares release segments, treating a missing trailing segment as
// zero -- though parse has already dropped those, so this only sees a genuine
// difference such as 1.2 against 1.2.1.
func cmpInts(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// cmpLocal orders local version labels. No local label sorts below any label,
// and within a label a numeric segment outranks an alphanumeric one -- so
// 1.0 < 1.0+foo < 1.0+1.
func cmpLocal(a, b []localSegment) int {
	if len(a) == 0 || len(b) == 0 {
		return cmpInt(len(a), len(b))
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		switch {
		case x.isNum && y.isNum:
			if c := cmpInt(x.num, y.num); c != 0 {
				return c
			}
		case x.isNum:
			return 1
		case y.isNum:
			return -1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}
