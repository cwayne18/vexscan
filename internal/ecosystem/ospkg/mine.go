package ospkg

import (
	"strings"
	"unicode"

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
	// MethodStaticSymbolAbsent: a blocking static entrypoint is a cgo build --
	// which the CGO_ENABLED=0 discharge in #24 cannot touch, because a cgo
	// binary might have linked the C library in -- but its own static symbol
	// table carries the vulnerable function's namespace and not the function,
	// so the vulnerable code was provably not statically linked into it.
	//
	// It is the cgo analogue of #24's structural discharge. That one clears the
	// static-elf taint when the binary provably links no C library at all; this
	// one clears it by proof from the symbol table, for exactly the case the
	// structural test leaves blocking. Like the other two it only ever appears
	// under --mine-advisories, because it needs a validated vulnerable symbol to
	// look for.
	MethodStaticSymbolAbsent = "elf-static-symbol-absent"
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
// The rule has three gates, and a hint that fails any of them is inert --
// recorded as an observation, never as a reason.
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
// The third gate is that the absence has to be informative. The first two say
// where the name came from; neither says the name is a function this build would
// have exported, and that is the premise the conclusion actually rests on. A
// struct tag, a build macro and a name the library exports under a different
// ABI decoration all sit in the right namespace and are all absent from every
// version ever built, so their absence is guaranteed rather than observed. See
// informativeAbsence.
//
// What survives all three is a name this advisory really used, drawn from the
// namespace this package really exports, whose absence is a fact about this
// build rather than about the name. That absence is then a fact about which
// version was compiled, which is the whole point.
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

	var informative []string
	var uninformative []string
	for _, s := range validated {
		if why, ok := informativeAbsence(defined, s); ok {
			informative = append(informative, s)
		} else {
			uninformative = append(uninformative, why)
		}
	}
	if len(informative) == 0 {
		return symbolCheck{Why: "no mined symbol's absence from " + e.st.pkg.Name +
			" says anything about which version was built: " + strings.Join(uninformative, "; ")}
	}
	validated = informative

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

// informativeAbsence reports whether a mined symbol's absence from defined says
// anything about which version was built, and if not, why not.
//
// The namespace gate establishes that a name belongs to the right software. It
// does not establish that the name is a *function this build would have
// exported*, and that premise is the one the whole absence test rests on. Two
// ways it fails, both observed against Rancher's images, and both of which
// produce an absence that was guaranteed before the image was ever opened:
//
// A name that is not a function. A namespace is shared by far more than its
// functions -- OSSL_CMP_CTX is a struct tag, OPENSSL_NO_COMP_ALG is a build
// macro, SSL_OP_NO_RX_CERTIFICATE_COMPRESSION is an option constant, ASN1_TYPE
// is a type -- and none of them appears in any symbol table, of any version,
// ever. C spells these in upper case and has since it had a preprocessor, so
// the absence of a lower-case letter is the signal. It costs the occasional
// real all-caps export (MD5, SHA1) the chance to be ruled out, which is a lost
// conclusion rather than a wrong one.
//
// A name the package exports under a different decoration. PCRE2 builds one
// library per code unit width and suffixes every export accordingly, so an
// advisory written about pcre2_compile is absent from libpcre2-8 -- which
// exports pcre2_compile_8 -- no matter which version it is. Normalising that
// suffix off both sides catches it: if the package exports the same function
// under its own decoration, the function is there and the miss was ours.
func informativeAbsence(defined map[string]bool, sym string) (string, bool) {
	if !strings.ContainsFunc(sym, unicode.IsLower) {
		return sym + " is spelled as a macro, constant or type rather than a function, " +
			"and no build of any version exports one of those", false
	}
	if defined[sym] {
		// Exported under its own name, so there is no absence to explain and
		// nothing for this gate to say. The caller takes the Defined branch.
		return "", true
	}
	base := undecorate(sym)
	for d := range defined {
		if undecorate(d) == base {
			return sym + " is exported as " + d + ", so the package has the function and the " +
				"name in the advisory is just the undecorated one", false
		}
	}
	return "", true
}

// undecorate strips an ABI-width suffix, so pcre2_compile_8, pcre2_compile_32
// and pcre2_compile all compare equal.
func undecorate(sym string) string {
	i := strings.LastIndexByte(sym, '_')
	if i <= 0 || i == len(sym)-1 {
		return sym
	}
	for _, r := range sym[i+1:] {
		if !unicode.IsDigit(r) {
			return sym
		}
	}
	return sym[:i]
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
