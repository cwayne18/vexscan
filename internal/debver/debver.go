// Package debver compares Debian package version strings.
//
// vexscan does not otherwise order versions: whether a package is affected is
// OSV's answer, made server-side by /v1/querybatch, so no comparator was ever
// needed. The fix plan needs one. A package with a dozen advisories, each
// fixed in a different point release, has one honest remediation -- upgrade to
// the newest of those versions, which clears them all because distro point
// releases are cumulative -- and finding "the newest" means comparing them.
//
// The algorithm is dpkg's own (deb-version(7), verrevcmp), reimplemented so a
// bookworm image's "2.36-9+deb12u7" and "2.36-9+deb12u14" order the way apt
// would order them. It is deliberately scoped to Debian/Ubuntu versions; other
// ecosystems have their own rules (a semver pre-release sorts *below* its
// release, the opposite of a Debian revision) and are compared elsewhere or
// not at all.
package debver

// Compare returns -1 if a sorts before b, +1 if after, and 0 if equal, using
// the Debian version-comparison algorithm.
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)

	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// split breaks a version into its epoch, upstream version and Debian revision.
// A missing epoch is 0 and a missing revision is empty, matching dpkg.
func split(v string) (epoch int, upstream, revision string) {
	// Epoch: digits up to the first colon. dpkg treats a colon with no valid
	// numeric prefix as part of the upstream version, but every real version
	// has a well-formed epoch or none, so a plain scan is enough here.
	if i := indexByte(v, ':'); i >= 0 {
		if n, ok := atoi(v[:i]); ok {
			epoch = n
			v = v[i+1:]
		}
	}
	// Revision: everything after the last hyphen. No hyphen means no Debian
	// revision, which dpkg compares as empty.
	if i := lastIndexByte(v, '-'); i >= 0 {
		upstream = v[:i]
		revision = v[i+1:]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

// verrevcmp compares one upstream-or-revision fragment using dpkg's rule:
// alternating runs of non-digits (ordered by order() below) and digits
// (compared numerically, leading zeros ignored).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit run: compare character by character under order().
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		// Digit run: skip leading zeros, then compare by length, then by the
		// first differing digit.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

// order assigns each byte its dpkg sort weight. A digit weighs 0, the same as
// the end of the string, so that in a non-digit run compared against a shorter
// side a digit sorts before any letter; '~' sorts before everything including
// the end of string; letters sort by their byte value; and every other
// punctuation sorts after letters. The digit case is reached only when the two
// versions' runs are misaligned -- one side still in a non-digit run while the
// other has reached a digit -- but omitting it inverts exactly those
// comparisons (a digit would otherwise fall through to c+256 and sort after
// letters instead of before them).
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// atoi parses a run of ASCII digits. It rejects anything else so a colon that
// is not an epoch separator (none occur in practice) leaves the version alone.
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
