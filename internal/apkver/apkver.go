// Package apkver compares Alpine package version strings by apk's own rules.
//
// It exists for the offline advisory path. Against the OSV API, whether
// busybox 1.36.1-r15 falls inside an advisory's range is osv.dev's answer and
// no comparator is needed here; against a local data export there is nobody to
// ask, and Alpine records state their fixed versions as apk versions. Neither
// debver nor rpmver will do -- apk orders a pre-release suffix below its
// release (1.0_rc1 < 1.0), has a -rN revision that dpkg and rpm do not share,
// and switches a numeric component to string comparison the moment either side
// carries a leading zero.
//
// The algorithm is apk-tools' own (src/version.c, apk_version_compare), ported
// token for token rather than approximated, because a fix judged "already
// installed" by the wrong ruleset is a real CVE waved through.
//
// Grammar, as apk states it:
//
//	digit{.digit}...{letter}{_suf{#}}...{~hash}{-r#}
package apkver

import "strings"

// Valid reports whether v parses as an apk version.
//
// Callers must check this before acting on Compare: an unparseable version has
// no place in an ordering, and this package says so rather than inventing one.
// apk itself sorts invalid input below valid input, which is a reasonable rule
// for a package manager listing what it has and the wrong one for deciding
// whether a vulnerability applies.
func Valid(v string) bool {
	var t token
	for t.first(&v); t.kind < kindEnd; t.next(&v) {
	}
	return t.kind == kindEnd
}

// Compare returns -1 if a sorts before b, +1 if after, and 0 if equal. The
// result is meaningless unless Valid is true for both; see Valid.
func Compare(a, b string) int {
	var ta, tb token
	ta.first(&a)
	tb.first(&b)
	for ta.kind == tb.kind && ta.kind < kindEnd {
		if r := ta.cmp(&tb); r != 0 {
			return r
		}
		ta.next(&a)
		tb.next(&b)
	}

	// The token streams diverged, or both ended together.
	if ta.kind == tb.kind {
		return 0
	}
	// One version continues where the other stopped. Continuing normally makes
	// it the greater -- 1.0.1 beats 1.0 -- but a pre-release suffix is the one
	// continuation that means the opposite: 1.0_rc1 is on the way to 1.0, not
	// past it.
	if ta.kind == kindSuffix && ta.suffix < suffixNone {
		return -1
	}
	if tb.kind == kindSuffix && tb.suffix < suffixNone {
		return 1
	}
	if ta.kind > tb.kind {
		return -1
	}
	if tb.kind > ta.kind {
		return 1
	}
	return 0
}

// kind is a token type. The values are ordered, and the order is load-bearing
// twice over: the tokenizer rejects a token that cannot follow the previous
// one by comparing kinds, and Compare breaks a tie between two versions of
// different lengths the same way.
type kind int

const (
	kindInitialDigit kind = iota
	kindDigit
	kindLetter
	kindSuffix
	kindSuffixNo
	kindCommitHash
	kindRevisionNo
	kindEnd
	kindInvalid
)

// Suffix ranks. Everything below suffixNone is a pre-release and sorts under
// the bare version; everything above is a post-release and sorts over it.
// suffixNone is never parsed -- it is only the pivot the two groups are
// measured against.
const (
	suffixInvalid = iota
	suffixAlpha
	suffixBeta
	suffixPre
	suffixRC
	suffixNone
	suffixCVS
	suffixSVN
	suffixGit
	suffixHg
	suffixP
)

// suffixNames maps a rank to the exact spelling that earns it. A prefix is not
// enough: "_post" starts with 'p' and is not a suffix apk knows.
var suffixNames = map[int]string{
	suffixAlpha: "alpha", suffixBeta: "beta", suffixPre: "pre", suffixRC: "rc",
	suffixCVS: "cvs", suffixSVN: "svn", suffixGit: "git", suffixHg: "hg", suffixP: "p",
}

func suffixValue(s string) int {
	if s == "" {
		return suffixInvalid
	}
	var val int
	switch s[0] {
	case 'a':
		val = suffixAlpha
	case 'b':
		val = suffixBeta
	case 'c':
		val = suffixCVS
	case 'g':
		val = suffixGit
	case 'h':
		val = suffixHg
	case 'p':
		// "p" alone is the post-release marker; anything longer starting with
		// 'p' can only be "pre".
		if len(s) > 1 {
			val = suffixPre
		} else {
			val = suffixP
		}
	case 'r':
		val = suffixRC
	case 's':
		val = suffixSVN
	default:
		return suffixInvalid
	}
	if suffixNames[val] != s {
		return suffixInvalid
	}
	return val
}

// token is the tokenizer's position: one token, plus whatever of its content
// the comparison needs.
type token struct {
	kind   kind
	suffix int
	number uint64
	value  string
}

func (t *token) first(b *string) {
	t.kind = kindInitialDigit
	t.parseDigits(b)
}

func (t *token) parseDigits(b *string) {
	n := 0
	for n < len(*b) && (*b)[n] >= '0' && (*b)[n] <= '9' {
		n++
	}
	if n == 0 {
		t.kind = kindInvalid
		return
	}
	t.value = (*b)[:n]
	*b = (*b)[n:]

	// Parsed by hand rather than with strconv so an absurdly long run of digits
	// saturates instead of erroring. apk pulls a uint64 and so does this; the
	// string form is kept in value for the leading-zero rule in cmp.
	t.number = 0
	for i := 0; i < len(t.value); i++ {
		d := uint64(t.value[i] - '0')
		if t.number > (1<<64-1-d)/10 {
			t.number = 1<<64 - 1
			break
		}
		t.number = t.number*10 + d
	}
}

func (t *token) next(b *string) {
	if len(*b) == 0 {
		t.kind = kindEnd
		return
	}
	c := (*b)[0]
	switch {
	case c >= 'a' && c <= 'z':
		if t.kind > kindDigit {
			t.kind = kindInvalid
			return
		}
		t.value = (*b)[:1]
		*b = (*b)[1:]
		t.kind = kindLetter

	case c == '.' || (c >= '0' && c <= '9'):
		if c == '.' {
			if t.kind > kindDigit {
				t.kind = kindInvalid
				return
			}
			*b = (*b)[1:]
		}
		// The new kind is decided by the kind we are leaving: digits after a
		// suffix are that suffix's number, digits after digits are another
		// dotted component.
		switch t.kind {
		case kindInitialDigit, kindDigit:
			t.kind = kindDigit
		case kindSuffix:
			t.kind = kindSuffixNo
		default:
			t.kind = kindInvalid
			return
		}
		t.parseDigits(b)

	case c == '_':
		if t.kind > kindSuffixNo {
			t.kind = kindInvalid
			return
		}
		*b = (*b)[1:]
		n := 0
		for n < len(*b) && (*b)[n] >= 'a' && (*b)[n] <= 'z' {
			n++
		}
		t.value = (*b)[:n]
		*b = (*b)[n:]
		t.suffix = suffixValue(t.value)
		if t.suffix == suffixInvalid {
			t.kind = kindInvalid
			return
		}
		t.kind = kindSuffix

	case c == '~':
		if t.kind >= kindCommitHash {
			t.kind = kindInvalid
			return
		}
		*b = (*b)[1:]
		n := 0
		for n < len(*b) && isHex((*b)[n]) {
			n++
		}
		if n == 0 {
			t.kind = kindInvalid
			return
		}
		t.value = (*b)[:n]
		*b = (*b)[n:]
		t.kind = kindCommitHash

	case c == '-':
		if t.kind >= kindRevisionNo {
			t.kind = kindInvalid
			return
		}
		if !strings.HasPrefix(*b, "-r") {
			t.kind = kindInvalid
			return
		}
		*b = (*b)[2:]
		t.kind = kindRevisionNo
		t.parseDigits(b)

	default:
		t.kind = kindInvalid
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// cmp orders two tokens of the same kind.
func (t *token) cmp(o *token) int {
	var a, b uint64
	switch t.kind {
	case kindDigit:
		// A leading zero on either side means the component is a fraction, not
		// a count: .10 sorts below .9 because it reads as 0.10 against 0.9.
		// Gentoo's rule, which apk adopted.
		if strings.HasPrefix(t.value, "0") || strings.HasPrefix(o.value, "0") {
			return strings.Compare(t.value, o.value)
		}
		a, b = t.number, o.number
	case kindInitialDigit, kindSuffixNo, kindRevisionNo:
		a, b = t.number, o.number
	case kindLetter:
		a, b = uint64(t.value[0]), uint64(o.value[0])
	case kindSuffix:
		a, b = uint64(t.suffix), uint64(o.suffix)
	default:
		return strings.Compare(t.value, o.value)
	}
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
