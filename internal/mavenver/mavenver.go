// Package mavenver compares Maven artifact versions by Maven's own rules.
//
// It exists for the offline advisory path. Against the OSV API, whether
// log4j-core 2.14.1 falls inside an advisory's range is osv.dev's answer;
// against a local data export there is nobody to ask, and Maven is the last
// ecosystem vexscan has a plugin for that had no comparator here.
//
// Nothing else in this repository will substitute, and the failures would be
// quiet ones. Maven has no specification of its version order beyond the
// implementation, and that implementation makes decisions no other scheme
// shares: an unrecognised qualifier sorts *above* every recognised one but
// still below the bare release, so 1.0-foo is above 1.0-sp and below 1.0; a
// dash opens a sub-list, so 1.0-1 and 1.0.1 are different versions; 1, 1.0 and
// 1.0.0 are the same one; and "1.0.0.X1" is read as "1.0.0-X1". Ordering these
// with semver would invert pairs with nothing on the page to say so.
//
// The algorithm is Maven's own ComparableVersion, ported item for item.
package mavenver

import "strings"

// Valid reports whether v is a version this package will order.
//
// Maven itself has no invalid version -- ComparableVersion tokenizes anything,
// which is right for a build tool that must do something with whatever the POM
// says and wrong for deciding whether a vulnerability applies. An arbitrary
// string tokenizes happily and orders meaninglessly, so this declines the
// strings that carry no version at all -- a branch name, a commit hash,
// "RELEASE", "LATEST" -- and package osv keeps the advisory and says it could
// not check, rather than acting on an ordering of nonsense.
func Valid(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v[0] >= '0' && v[0] <= '9'
}

// Compare returns -1 if a sorts before b, +1 if after, and 0 if equal. The
// result is meaningless unless Valid is true for both; see Valid.
func Compare(a, b string) int {
	return cmp(parse(strings.TrimSpace(a)), parse(strings.TrimSpace(b)))
}

// qualifiers is Maven's ordering of the qualifiers it knows, and the position
// of "" in it is the pivot the whole scheme turns on: a qualifier below index 5
// makes the version older than the bare release, one above makes it newer.
var qualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// releaseRank is the rank of the empty qualifier -- the plain release -- which
// is also what a missing item is measured against.
const releaseRank = "5"

// rankOf maps a qualifier to the token that orders it lexically.
//
// An unrecognised qualifier is prefixed with the table's length, so it sorts
// above every recognised qualifier and unrecognised ones sort among themselves
// by name. Comparing the tokens as strings rather than as numbers is Maven's
// own trick for getting both bands out of one comparison.
func rankOf(q string) string {
	for i, known := range qualifiers {
		if q == known {
			return string(rune('0' + i))
		}
	}
	return "7-" + q
}

type kind int

const (
	kindInt kind = iota
	kindString
	kindList
)

// item is one token: a number, a qualifier, or a sub-list.
//
// Held behind a pointer because parsing threads a "current list" through the
// scan the way Maven's does, appending a fresh sub-list to its parent and then
// descending into it.
type item struct {
	kind kind
	// num is a decimal string with its leading zeros stripped, never empty.
	// A string and not an integer because Maven's numbers have no width limit
	// and a version segment is sometimes a timestamp.
	num string
	// str is the qualifier, already folded through the aliases.
	str string
	sub []*item
}

func intItem(buf string) *item {
	// Maven strips leading zeros so 1.01 and 1.1 are one version. An all-zero
	// run is the number zero, which is also the null item.
	s := strings.TrimLeft(buf, "0")
	if s == "" {
		s = "0"
	}
	return &item{kind: kindInt, num: s}
}

// stringItem folds a qualifier onto its canonical spelling.
//
// followedByDigit is why "1-a1" is alpha-1 and "1-a" is the unknown qualifier
// "a": a lone letter is only shorthand when a number follows it, and the two
// land in different bands -- alpha below the release, "a" above every known
// qualifier.
func stringItem(v string, followedByDigit bool) *item {
	if followedByDigit && len(v) == 1 {
		switch v[0] {
		case 'a':
			v = "alpha"
		case 'b':
			v = "beta"
		case 'm':
			v = "milestone"
		}
	}
	switch v {
	case "ga", "final", "release":
		v = ""
	case "cr":
		v = "rc"
	}
	return &item{kind: kindString, str: v}
}

func parseItem(isDigit bool, buf string) *item {
	if isDigit {
		return intItem(buf)
	}
	return stringItem(buf, false)
}

// parse tokenizes a version into the nested item list Maven compares.
//
// Tokens break on '.', on '-', and at every transition between digits and
// non-digits. A '-' always opens a sub-list; so does a transition, which is
// what makes "1.0.0.X1" read as "1.0.0-X1" and keeps "1.0-1" apart from
// "1.0.1".
func parse(v string) *item {
	v = strings.ToLower(v)
	root := &item{kind: kindList}
	list := root
	stack := []*item{root}

	add := func(it *item) { list.sub = append(list.sub, it) }
	pushList := func() {
		nl := &item{kind: kindList}
		add(nl)
		list = nl
		stack = append(stack, nl)
	}

	isDigit := false
	start := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			if i == start {
				add(intItem("0"))
			} else {
				add(parseItem(isDigit, v[start:i]))
			}
			start = i + 1

		case c == '-':
			if i == start {
				add(intItem("0"))
			} else {
				add(parseItem(isDigit, v[start:i]))
			}
			start = i + 1
			pushList()

		case c >= '0' && c <= '9':
			if !isDigit && i > start {
				if len(list.sub) != 0 {
					pushList()
				}
				add(stringItem(v[start:i], true))
				start = i
				pushList()
			}
			isDigit = true

		default:
			if isDigit && i > start {
				add(parseItem(true, v[start:i]))
				start = i
				pushList()
			}
			isDigit = false
		}
	}
	if len(v) > start {
		if !isDigit && len(list.sub) != 0 {
			pushList()
		}
		add(parseItem(isDigit, v[start:]))
	}

	// Innermost first, as Maven pops its stack: normalizing a sub-list can
	// empty it, and an empty sub-list is itself a null item its parent then
	// drops.
	for i := len(stack) - 1; i >= 0; i-- {
		normalize(stack[i])
	}
	return root
}

// normalize drops trailing null items -- a zero, a plain-release qualifier, an
// empty sub-list -- which is the rule that makes 1, 1.0, 1.0.0 and 1.0-ga one
// version.
//
// It stops at the first trailing item that is neither null nor a sub-list, and
// keeps going past a non-null sub-list, exactly as Maven's does.
func normalize(l *item) {
	for i := len(l.sub) - 1; i >= 0; i-- {
		last := l.sub[i]
		if last.isNull() {
			l.sub = append(l.sub[:i], l.sub[i+1:]...)
		} else if last.kind != kindList {
			break
		}
	}
}

// isNull reports whether the item is what a missing item is padded with.
func (i *item) isNull() bool {
	switch i.kind {
	case kindInt:
		return i.num == "0"
	case kindString:
		return rankOf(i.str) == releaseRank
	default:
		return len(i.sub) == 0
	}
}

// cmp orders a against b. b may be nil, standing for the padding a shorter
// version gets; a may not.
//
// Padding rather than "shorter is smaller" is what puts 1.0-beta below 1.0 and
// 1.0-sp above it: the qualifier is measured against the plain-release rank,
// not against nothing at all.
func cmp(a, b *item) int {
	switch a.kind {
	case kindInt:
		switch {
		case b == nil:
			if a.num == "0" {
				return 0 // 1.0 == 1
			}
			return 1 // 1.1 > 1
		case b.kind == kindInt:
			return cmpNumeric(a.num, b.num)
		default:
			return 1 // 1.1 > 1-sp, and 1.1 > 1-1
		}

	case kindString:
		switch {
		case b == nil:
			return strings.Compare(rankOf(a.str), releaseRank) // 1-rc < 1, 1-sp > 1
		case b.kind == kindString:
			return strings.Compare(rankOf(a.str), rankOf(b.str))
		case b.kind == kindInt:
			return -1 // 1.any < 1.1
		default:
			return -1 // 1-sp < 1-1
		}

	default:
		switch {
		case b == nil:
			// The whole sub-list against the padding, not just its head: a
			// sub-list of nothing but nulls is equal to no sub-list at all.
			for _, sub := range a.sub {
				if r := cmp(sub, nil); r != 0 {
					return r
				}
			}
			return 0
		case b.kind == kindList:
			return cmpLists(a.sub, b.sub)
		case b.kind == kindInt:
			return -1 // 1-1 < 1.0.x
		default:
			return 1 // 1-1 > 1-sp
		}
	}
}

func cmpLists(a, b []*item) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var l, r *item
		if i < len(a) {
			l = a[i]
		}
		if i < len(b) {
			r = b[i]
		}
		var result int
		switch {
		case l == nil && r == nil:
			result = 0
		case l == nil:
			// The left ran out, so the comparison is inverted: compare the
			// right against the padding and flip the sign.
			result = -cmp(r, nil)
		default:
			result = cmp(l, r)
		}
		if result != 0 {
			return result
		}
	}
	return 0
}

// cmpNumeric orders two zero-stripped decimal strings, longer being larger.
func cmpNumeric(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
