// Package rpmver compares rpm version strings by rpm's own rules.
//
// It exists because the rpm distributions -- SUSE, Red Hat and their kin -- state
// a fixed version in the exact grammar rpm's rpmvercmp uses, and deciding whether
// an installed package has already reached that fix is a version comparison that
// must be done rpm's way or not at all. dpkg's verrevcmp (internal/debver) looks
// almost identical and is not: rpmvercmp has no epoch-less short-circuit, treats
// a run of separators as one, and orders "~" and "^" with rules dpkg does not
// share. A fix judged "already installed" by the wrong ruleset is a real CVE
// waved through, so this package ports the reference algorithm faithfully rather
// than approximating it.
package rpmver

import "strings"

// Compare orders two rpm EVR strings -- an optional "epoch:", a version, and an
// optional "-release" -- returning -1, 0 or 1 for a<b, a==b, a>b.
//
// Epoch is compared first as an integer, but only when both strings actually
// carry one. rpm's own rule reads a missing epoch as 0, and that is right when
// comparing two real packages; it is a hazard when the second string is a
// vendor's fixed version quoted without an epoch (SUSE's and Azure's CSAF do
// this) while the first is an installed package the database always stamps with
// one. Reading the absent epoch as 0 would let an installed "1:..." outrank the
// fix on epoch alone and clear a package whose version has not reached it. So
// when exactly one side carries an epoch, a non-zero epoch on that side cannot
// be proven greater-or-equal to the unknown and the comparison fails closed: the
// epoch-bearing side is ordered below the bare one, which in the installed-vs-fix
// direction leaves the finding affected. An epoch of 0 (or absent on both) falls
// through to the version, the ordinary case. Version is compared by rpmvercmp.
// Release is compared last, and only when both strings carry one: a fix quoted
// without a release ("1.1.1l") is a statement about the version line, and pinning
// it to a release it never named would be a comparison the vendor did not make.
func Compare(a, b string) int {
	pa, ea, va, ra := splitEVR(a)
	pb, eb, vb, rb := splitEVR(b)
	switch {
	case pa && pb:
		if ea != eb {
			if ea < eb {
				return -1
			}
			return 1
		}
	case pa && !pb:
		// Only a carries an epoch. A non-zero epoch cannot be proven >= the
		// unknown, so a sorts below b; epoch 0 ties and falls through.
		if ea != 0 {
			return -1
		}
	case !pa && pb:
		if eb != 0 {
			return 1
		}
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		return 0
	}
	return rpmvercmp(ra, rb)
}

// splitEVR breaks an EVR into whether an epoch was present, its integer value (0
// when absent or unparseable), a version, and a release (empty when absent).
func splitEVR(s string) (hasEpoch bool, epoch int, version, release string) {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		hasEpoch = true
		epoch = atoiDefault(s[:i], 0)
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		release = s[i+1:]
		version = s[:i]
		return hasEpoch, epoch, version, release
	}
	return hasEpoch, epoch, s, ""
}

// atoiDefault parses a non-negative decimal, returning def on any non-digit so a
// malformed epoch can never masquerade as a comparable number.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return def
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// rpmvercmp is the direct port of rpm's lib/rpmvercmp.c: it walks both strings a
// segment at a time, a segment being a maximal run of digits or a maximal run of
// letters, and compares segment by segment. Separators are skipped, a numeric
// segment outranks an alphabetic one, longer numbers outrank shorter, and "~"
// and "^" get their special ordering. Returns -1, 0 or 1.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Skip anything that is not alphanumeric and not a tilde or caret;
		// rpm treats a run of separators as a single boundary.
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// A tilde sorts before everything, including the empty string, so
		// "1.0~rc1" precedes "1.0". The side without the tilde is the greater.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// A caret sorts after everything except the end of string, so "1.0^"
		// follows "1.0" but a bare end still outranks a dangling caret.
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			i++
			j++
			continue
		}

		// If either side is spent, the segment walk is over; the tail decides.
		if !(i < len(a) && j < len(b)) {
			break
		}

		startI, startJ := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA := a[startI:i]
		segB := b[startJ:j]

		// segA is non-empty by construction. If segB is empty the two segments
		// are of different kinds -- one numeric, one alphabetic -- and a numeric
		// segment is always the newer.
		if len(segB) == 0 {
			if isNum {
				return 1
			}
			return -1
		}

		if isNum {
			// Leading zeros carry no value, so drop them and let the longer
			// remaining run of digits -- the larger number -- win.
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			if c < 0 {
				return -1
			}
			return 1
		}
	}

	// Every compared segment tied. Whichever string still has an unread segment
	// is the newer; if both are spent they are equal.
	aLeft := i < len(a)
	bLeft := j < len(b)
	switch {
	case aLeft == bLeft:
		return 0
	case aLeft:
		return 1
	default:
		return -1
	}
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isAlnum(b byte) bool { return isDigit(b) || isAlpha(b) }
