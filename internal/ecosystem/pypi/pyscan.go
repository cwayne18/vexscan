package pypi

import (
	"regexp"
	"strings"

	"github.com/cwayne18/vexscan/internal/modgraph"
)

// This is a lexer, not a parser, and that is the right trade.
//
// It over-approximates: it reads imports inside "if TYPE_CHECKING:", in
// branches that never execute, and inside docstrings. Every one of those adds
// a module to the reachable set, and a larger reachable set can only ever
// *prevent* a not_affected conclusion. The direction that would be dangerous
// is missing an import, and the one class of import it cannot see -- a name
// computed at runtime -- is exactly what the dynamic-import taint reports.
//
// A real parser would cost a Python grammar and would buy precision in the
// safe direction only.

var (
	// import a.b.c as d, e.f
	reImport = regexp.MustCompile(`^import\s+(.+)$`)

	// from .a.b import (c, d)  /  from . import x
	reFrom = regexp.MustCompile(`^from\s+([.\w]+)\s+import\s+(.+)$`)

	// importlib.import_module("x") / __import__("x") / import_module(name)
	// The optional quoted group is what separates a literal from a computed
	// argument: with it the edge is ordinary, without it the file taints.
	reImportCall = regexp.MustCompile(`(?:importlib\.import_module|import_module|__import__)\s*\(\s*(?:(["'])([^"']*)["'])?`)

	// Plugin discovery: the code asks the installed distributions what they
	// provide rather than naming anything.
	reDiscovery = regexp.MustCompile(`\bentry_points\s*\(|\biter_modules\s*\(|\biter_entry_points\s*\(|\bimportlib\.metadata\b|\bpkg_resources\b`)
)

// scanResult is what one file says about what it loads.
type scanResult struct {
	specs []modgraph.Spec

	// computed are the lines that import a name this package cannot read.
	computed []int

	// discovery is set when the file enumerates installed distributions
	// instead of naming a module.
	discovery bool
}

// scanPython extracts the import specifiers from Python source.
func scanPython(src []byte) scanResult {
	var out scanResult
	seen := map[string]bool{}

	add := func(name string, line int, dynamic, optional bool) {
		if name == "" || name == "." {
			// A bare "from . import x" names the importing package itself,
			// which is already in the graph by definition.
			return
		}
		key := name
		if seen[key] {
			return
		}
		seen[key] = true
		out.specs = append(out.specs, modgraph.Spec{Name: name, Line: line, Dynamic: dynamic, Optional: optional})
	}

	for _, l := range logicalLines(string(src)) {
		for _, text := range splitStatements(stripComment(l.text)) {
			text = strings.TrimSpace(text)
			if text == "" {
				continue
			}

			switch {
			case reFrom.MatchString(text):
				m := reFrom.FindStringSubmatch(text)
				pkg, names := m[1], m[2]
				add(pkg, l.num, false, false)
				for _, n := range importedNames(names) {
					// "from pkg import name" reaches pkg/name.py when name is
					// a submodule, and nothing when it is an attribute.
					// Optional, so the common attribute case does not report a
					// missing module.
					add(joinModule(pkg, n), l.num, false, true)
				}
			case reImport.MatchString(text):
				for _, n := range importedNames(reImport.FindStringSubmatch(text)[1]) {
					add(n, l.num, false, false)
				}
			}

			// An import call can appear anywhere, including on a line that is
			// also a plain import, so this is not part of the switch.
			for _, m := range reImportCall.FindAllStringSubmatch(text, -1) {
				if m[2] != "" {
					add(m[2], l.num, true, false)
				} else {
					out.computed = append(out.computed, l.num)
				}
			}
			if reDiscovery.MatchString(text) {
				out.discovery = true
			}
		}
	}
	return out
}

// logicalLine is a source line with its continuations folded in.
type logicalLine struct {
	num  int
	text string
}

// logicalLines joins backslash continuations and parenthesised import lists,
// so that a "from x import (\n a,\n b,\n)" is one line to match against.
func logicalLines(src string) []logicalLine {
	var out []logicalLine
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		text := strings.TrimRight(lines[i], "\r")
		num := i + 1

		// Only import statements are worth folding: doing it for every line
		// would mean tracking Python's whole expression grammar to find out
		// where a parenthesis closes.
		trimmed := strings.TrimSpace(text)
		if !strings.HasPrefix(trimmed, "import ") && !strings.HasPrefix(trimmed, "from ") {
			out = append(out, logicalLine{num, text})
			continue
		}
		for i+1 < len(lines) && needsMore(text) {
			i++
			text = strings.TrimSuffix(strings.TrimRight(text, " \t"), "\\") + " " + strings.TrimSpace(lines[i])
		}
		out = append(out, logicalLine{num, text})
	}
	return out
}

// needsMore reports whether a folded line is still open.
func needsMore(text string) bool {
	t := strings.TrimRight(text, " \t")
	if strings.HasSuffix(t, "\\") {
		return true
	}
	return strings.Count(stripComment(t), "(") > strings.Count(stripComment(t), ")")
}

// stripComment removes a trailing "#" comment, respecting quotes well enough
// that a "#" inside a string literal does not truncate the line.
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}

// splitStatements cuts a line at semicolons, so that the second half of
// "os.chdir(d); import plugin" is seen. Semicolons inside string literals are
// left alone, since splitting there would truncate a line rather than reveal
// a statement.
func splitStatements(s string) []string {
	var out []string
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ';':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// importedNames splits an import list into module or attribute names, dropping
// "as" bindings, parentheses and star imports.
func importedNames(list string) []string {
	list = strings.NewReplacer("(", " ", ")", " ").Replace(list)
	var out []string
	for _, part := range strings.Split(list, ",") {
		f := strings.Fields(part)
		if len(f) == 0 || f[0] == "*" {
			continue
		}
		out = append(out, f[0])
	}
	return out
}

// joinModule appends a name to a package, keeping the relative dots intact:
// joinModule(".", "x") is ".x", not "..x".
func joinModule(pkg, name string) string {
	if strings.HasSuffix(pkg, ".") {
		return pkg + name
	}
	return pkg + "." + name
}
