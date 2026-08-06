package ospkg

import (
	"strings"

	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
)

// Methods for the mined-symbol layer. Both only ever appear under
// --mine-advisories.
const (
	// MethodDynsymAbsent: the vulnerable function the advisory names is not in
	// the export table of anything this package installed.
	MethodDynsymAbsent = "elf-dynsym-absent"
	// MethodImportAbsent: the function is exported, but nothing the closure
	// reaches references it.
	MethodImportAbsent = "elf-import-absent"
	// MethodMined marks an observation from the mining layer that changed no
	// status -- including every case where validation rejected a hint.
	MethodMined = "llm-mined"
)

// symbolCheck is what the mined-symbol layer concluded about one advisory
// against one package.
type symbolCheck struct {
	// Validated are the mined symbols that survived validation.
	Validated []string
	// Defined are the validated symbols the package's own objects export.
	Defined []string
	// Importers are the reachable objects that reference a defined symbol.
	Importers []string
	// Why records what happened, for the evidence line. Always set.
	Why string
	// Usable reports whether the check may influence a status at all.
	Usable bool
}

// checkSymbols applies the hallucination containment rule and then looks the
// surviving symbols up in the package's export tables.
//
// The rule has two gates, and a hint that fails either is inert -- recorded as
// an observation, never as a reason.
//
// The first gate is that a mined symbol must appear *literally* in the
// advisory's own text. The model was instructed to extract rather than infer,
// and this is where that instruction stops being trusted and starts being
// enforced. A name the advisory does not contain was invented, whatever else
// it might be, and no amount of it being absent from a library means anything.
//
// The second gate is that the symbol must come from the right software. A
// validated symbol's absence is only informative if the library would have
// exported it had it been vulnerable, so the package must export at least one
// symbol sharing the mined symbol's namespace -- SSL_ for SSL_free_buffers,
// png_ for png_handle_iCCP. Without this, "SSL_free_buffers" and
// "wholly_invented_thing" are equally absent from libssl, and only one of them
// says anything about the build.
//
// What survives both gates is a name this advisory really used, drawn from the
// namespace this package really exports. Its absence from the export table is
// then a fact about which version was compiled, which is the whole point.
func (e evaluator) checkSymbols(adv *osv.Advisory, hints *llm.Hints, elfFiles []string) symbolCheck {
	if hints == nil {
		return symbolCheck{Why: "advisory mining was not run for this advisory"}
	}
	if len(hints.Symbols) == 0 {
		note := hints.Note
		if note == "" {
			note = "the advisory text names no function"
		}
		return symbolCheck{Why: "no symbol could be mined: " + note}
	}

	text := advisoryText(adv)
	var literal []string
	for _, s := range hints.Symbols {
		if strings.Contains(text, s) {
			literal = append(literal, s)
		}
	}
	if len(literal) == 0 {
		return symbolCheck{Why: "every mined symbol (" + strings.Join(hints.Symbols, ", ") +
			") is absent from the advisory's own text, so it was invented rather than extracted"}
	}

	defined, undefined := e.symbols(elfFiles)
	if len(defined) == 0 {
		return symbolCheck{Why: "no export table could be read from the objects " +
			e.st.pkg.Name + " installs, so a symbol's absence from them proves nothing"}
	}

	var validated []string
	for _, s := range literal {
		if hasNamespace(defined, s) {
			validated = append(validated, s)
		}
	}
	if len(validated) == 0 {
		return symbolCheck{Why: "no mined symbol (" + strings.Join(literal, ", ") +
			") shares a namespace with anything " + e.st.pkg.Name + " exports, so its absence is not evidence"}
	}

	c := symbolCheck{Validated: validated, Usable: true}
	for _, s := range validated {
		if defined[s] {
			c.Defined = append(c.Defined, s)
		}
	}
	if len(c.Defined) == 0 {
		c.Why = strings.Join(validated, ", ") + " named by the advisory, exported by nothing " +
			e.st.pkg.Name + " installs"
		return c
	}
	for _, s := range c.Defined {
		c.Importers = append(c.Importers, undefined[s]...)
	}
	c.Importers = sortedUnique(c.Importers)
	c.Why = strings.Join(c.Defined, ", ") + " exported by " + e.st.pkg.Name
	return c
}

// symbols reads the export tables of the package's objects, and the references
// every reachable object in the image makes.
//
// The second map is what answers "does anything actually call this": it maps a
// symbol name to the reachable objects whose dynamic relocations name it.
func (e evaluator) symbols(elfFiles []string) (defined map[string]bool, importers map[string][]string) {
	defined = map[string]bool{}
	for _, f := range elfFiles {
		def, _, err := e.readSymbols(f)
		if err != nil {
			e.logf("  ! could not read the symbols of %s: %v", f, err)
			continue
		}
		for _, s := range def {
			defined[s] = true
		}
	}
	if len(defined) == 0 {
		return defined, nil
	}

	// The importer scan needs the closure, to know which objects are reachable
	// and what they reference. In metadata-only mode (--rpm-deep) there is no
	// closure -- the package's own objects were extracted but no tree was
	// walked -- so there is nothing to scan for importers. The defined set
	// alone still answers the dynsym-absent question, which is the only one
	// that mode is entitled to ask.
	if e.g == nil {
		return defined, nil
	}

	importers = map[string][]string{}
	for _, n := range e.g.Nodes() {
		if !n.Reachable {
			continue
		}
		_, undef, err := e.readSymbols(n.Path)
		if err != nil {
			continue
		}
		for _, s := range undef {
			if defined[s] {
				importers[s] = append(importers[s], n.Path)
			}
		}
	}
	return defined, importers
}

// advisoryText is everything the advisory says, for the literal-substring gate.
func advisoryText(adv *osv.Advisory) string {
	if adv == nil {
		return ""
	}
	return adv.Summary + "\n" + adv.Details
}

// hasNamespace reports whether anything in defined shares sym's namespace.
func hasNamespace(defined map[string]bool, sym string) bool {
	prefix := namespace(sym)
	if prefix == "" {
		return false
	}
	for d := range defined {
		if d != sym && strings.HasPrefix(d, prefix) {
			return true
		}
	}
	return defined[sym]
}

// namespace is the library prefix a C symbol carries.
//
// Almost every C library prefixes its exports, which is what makes this work
// at all: SSL_free_buffers -> "SSL_", png_handle_iCCP -> "png_". Names with no
// underscore fall back to their first few characters, which catches the
// camelCase convention libxml2 and friends use (xmlParseDoc -> "xmlP") and
// costs nothing when it does not.
func namespace(sym string) string {
	if len(sym) < 3 {
		return ""
	}
	if i := strings.Index(sym, "_"); i >= 2 {
		return sym[:i+1]
	}
	if len(sym) < 4 {
		return sym
	}
	return sym[:4]
}

// readSymbols reads one object's dynamic symbols, once per image.
//
// glibc alone exports a couple of thousand symbols and the importer scan walks
// every reachable object, so the same tables would otherwise be parsed
// repeatedly within a single scan.
func (e evaluator) readSymbols(path string) (defined, undefined []string, err error) {
	e.sym.mu.Lock()
	if c, ok := e.sym.cache[path]; ok {
		e.sym.mu.Unlock()
		return c.defined, c.undefined, c.err
	}
	e.sym.mu.Unlock()

	read := e.sym.read
	if read == nil {
		read = elfgraph.Symbols
	}
	defined, undefined, err = read(e.sym.fsys, path)

	e.sym.mu.Lock()
	e.sym.cache[path] = symbolEntry{defined: defined, undefined: undefined, err: err}
	e.sym.mu.Unlock()
	return defined, undefined, err
}
