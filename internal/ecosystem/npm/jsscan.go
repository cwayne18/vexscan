package npm

import (
	"regexp"
	"strings"

	"github.com/cwayne18/vexscan/internal/modgraph"
)

// This is a lexer, not a parser, and that is the same trade the Python scanner
// makes.
//
// It over-approximates: it reads a require() in a branch that never runs, in
// dead code, and in a block guarded by a feature test. Every one of those adds
// a module to the reachable set, and a larger reachable set can only ever
// *prevent* a not_affected conclusion. The direction that would be dangerous
// is missing a require, and the one class it cannot see -- a specifier
// computed at runtime -- is exactly what the dynamic-import taint reports.
//
// What it does have to get right is which text is code. A require() inside a
// string or a comment is not an import, and JavaScript's template literals and
// regex literals both contain characters that would otherwise end a string. So
// the lexer strips comments and blanks out literals before matching, rather
// than matching against raw source.

var (
	// require("x") and require.resolve("x"). The optional quoted group is what
	// separates a literal from a computed argument: with it the edge is
	// ordinary, without it the file taints.
	reRequire = regexp.MustCompile(`\brequire(?:\.resolve)?\s*\(\s*(?:(["'` + "`" + `])([^"'` + "`" + `]*)["'` + "`" + `])?`)

	// import("x") -- the dynamic form, which is still static when its argument
	// is a literal. "import" is matched at a word boundary that is not a dot,
	// so a method called .import() does not count.
	reImportCall = regexp.MustCompile(`(^|[^.\w$])import\s*\(\s*(?:(["'` + "`" + `])([^"'` + "`" + `]*)["'` + "`" + `])?`)

	// import x from "y" / export * from "y" / export {a} from "y".
	//
	// The import or export keyword is deliberately not required to be on this
	// line: a braced list routinely spans several lines and the "from" lands
	// on the last of them. Matching the "from" alone over-approximates -- an
	// English sentence in a string can produce one -- and that is the safe
	// direction, where anchoring to the keyword would silently drop the
	// multi-line form.
	reFrom = regexp.MustCompile(`\bfrom\s*(["'])([^"']*)["']`)

	// A side-effect import, which has no "from": import "./polyfill".
	reBareImport = regexp.MustCompile(`(^|[^.\w$])import\s*(["'])([^"']*)["']`)
)

// scanResult is what one file says about what it loads.
type scanResult struct {
	specs []modgraph.Spec

	// computed are the lines that require a name this package cannot read.
	computed []int
}

// scanJS extracts the import specifiers from JavaScript source.
func scanJS(src []byte) scanResult {
	var out scanResult
	seen := map[string]bool{}

	add := func(name string, line int, dynamic bool) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out.specs = append(out.specs, modgraph.Spec{Name: name, Line: line, Dynamic: dynamic})
	}

	text := stripJS(string(src))
	for i, line := range strings.Split(text, "\n") {
		num := i + 1

		for _, m := range reFrom.FindAllStringSubmatch(line, -1) {
			add(m[2], num, false)
		}
		for _, m := range reBareImport.FindAllStringSubmatch(line, -1) {
			add(m[3], num, false)
		}
		for _, m := range reRequire.FindAllStringSubmatch(line, -1) {
			if m[2] != "" {
				add(m[2], num, true)
			} else {
				out.computed = append(out.computed, num)
			}
		}
		for _, m := range reImportCall.FindAllStringSubmatch(line, -1) {
			if m[3] != "" {
				add(m[3], num, true)
			} else {
				out.computed = append(out.computed, num)
			}
		}
	}
	return out
}

// stripJS removes comments and blanks out the interiors of string and template
// literals, keeping every byte offset and every newline so that line numbers
// and the quote characters the patterns match on both survive.
//
// A template literal's interior is blanked rather than removed for a reason
// worth stating: `require(${x})` inside a template is not a require, and
// leaving the text in place would make it look like one.
func stripJS(src string) string {
	out := []byte(src)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}

	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '/':
			if i+1 >= len(src) {
				continue
			}
			switch {
			case src[i+1] == '/':
				j := strings.IndexByte(src[i:], '\n')
				if j < 0 {
					j = len(src) - i
				}
				blank(i, i+j)
				i += j
			case src[i+1] == '*':
				j := strings.Index(src[i+2:], "*/")
				if j < 0 {
					blank(i, len(src))
					return string(out)
				}
				blank(i, i+2+j+2)
				i += 2 + j + 1
			case startsRegex(src, i):
				// A regex literal can contain an apostrophe -- /don't/ is
				// legal -- and letting the string scanner see that quote would
				// blank every line until the next one, taking real require()
				// calls with it. Skipping the literal is worth the small risk
				// of misreading a division, because misreading a division
				// costs at most the rest of one line.
				if end := regexEnd(src, i); end > 0 {
					blank(i+1, end)
					i = end
				}
			}

		case '"', '\'', '`':
			quote := src[i]
			j := i + 1
			for j < len(src) {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == quote {
					break
				}
				// An unterminated single- or double-quoted string ends at the
				// newline; a template literal spans lines legitimately.
				if src[j] == '\n' && quote != '`' {
					break
				}
				j++
			}
			if j >= len(src) {
				j = len(src)
			}
			// The quotes themselves stay: the patterns match on them, and the
			// specifier between them is what we are after. Only a template
			// literal's interior is blanked, since it is the one that can
			// contain code.
			if quote == '`' {
				blank(i+1, j)
			}
			i = j
		}
	}
	return string(out)
}

// startsRegex guesses whether the slash at i opens a regex literal rather than
// being a division operator.
//
// Telling those apart properly needs the previous *token*, which needs a
// parser. The standard heuristic is used instead: a slash that follows an
// operator or an opening bracket cannot be a division, because there is no
// value on its left to divide. It is wrong for `x++ /re/` and similar
// contrivances, and being wrong costs the rest of one line.
func startsRegex(src string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		c := src[j]
		if c == ' ' || c == '\t' || c == '\r' {
			continue
		}
		if c == '\n' {
			// A slash first thing on a line follows either nothing or a
			// complete statement; treating it as a regex is the safer read,
			// since a leading-slash division is vanishingly rare.
			return true
		}
		return strings.IndexByte("(,=:[!&|?{};+-*%~^<>", c) >= 0
	}
	return true
}

// regexEnd finds the closing slash of the regex literal opening at i, or -1 if
// the line ends first.
func regexEnd(src string, i int) int {
	for j := i + 1; j < len(src) && src[j] != '\n'; j++ {
		switch src[j] {
		case '\\':
			j++
		case '[':
			// A character class may hold an unescaped slash: /[/]/ is legal.
			for j++; j < len(src) && src[j] != ']' && src[j] != '\n'; j++ {
				if src[j] == '\\' {
					j++
				}
			}
		case '/':
			return j
		}
	}
	return -1
}
