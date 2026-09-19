package ospkg

import (
	"fmt"
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// Methods name the deterministic test behind a status, and appear in the
// output. They are part of the tool's published vocabulary.
const (
	// MethodInventory: the package database was consulted and nothing else.
	MethodInventory = "pkgdb-inventory"
	// MethodNoCode: the package is installed but installs no ELF object.
	MethodNoCode = "pkgdb-no-code"
	// MethodClosure: the DT_NEEDED closure was resolved from the image's
	// entrypoint and none of the package's objects appeared in it.
	MethodClosure = "elf-needed-closure"
	// MethodRPMFile: the rpm header was read and there was no filesystem to
	// test anything against. It is an evidence origin rather than a method,
	// because it names the absence of a test and not a test -- the statuses it
	// accompanies are undetermined.
	MethodRPMFile = "rpm-file-metadata"
	// MethodSBOM: a bill of materials said the package is there and nothing
	// else. Like MethodRPMFile it is an evidence origin rather than a method,
	// and it is the weaker of the two: an rpm header at least lists the files
	// the package would install, so it can rule out code; a CycloneDX component
	// is a name, a version and a purl, so it can rule out nothing.
	//
	// Shared with the language plugins, which say exactly the same thing about
	// exactly the same document. See ecosystem.OriginSBOM.
	MethodSBOM = ecosystem.OriginSBOM
)

// ReasonNoReachabilityTest is the reason on every finding a metadata-only scan
// could not decide. See ecosystem.ReasonNoReachabilityTest, where it is shared
// with the plugins that produce the same rows from the same SBOM.
const ReasonNoReachabilityTest = ecosystem.ReasonNoReachabilityTest

// evaluator holds what every finding for one component needs.
type evaluator struct {
	g     *elfgraph.Graph
	st    *state
	sym   *symbolCache
	trust bool // --trust-import-absence
	// meta is set when the inventory was handed in rather than read out of a
	// tree, and g is nil. See evaluateMetadata. origin names what handed it in,
	// and is what the evidence rows say.
	meta   bool
	origin string
	logf   func(string, ...any)
}

func (p *Plugin) evaluator(pr *prepared, g *elfgraph.Graph, st *state) evaluator {
	return evaluator{
		g: g, st: st, sym: pr.syms, trust: p.TrustImportAbsence,
		meta: pr.metadataOnly, origin: pr.metaOrigin, logf: p.Logf,
	}
}

// evaluate decides one advisory against one installed package.
//
// The order of the cases is the order of increasing cost and decreasing
// certainty: whether the package exists, whether it ships code, and only then
// whether that code could be loaded.
func (e evaluator) evaluate(c ecosystem.Component, req ecosystem.Request) ecosystem.Finding {
	f := ecosystem.Finding{
		Module:  c.Name,
		Version: c.Version,
		PURL:    c.PURL,
		CVE:     req.ID,
	}

	// Absence is decided before the advisory is even looked at. Whether OSV
	// carries a record for this id makes no difference to the fact that the
	// image does not contain the package the id was asked about.
	if e.st.absent {
		if e.metaOrigin() == MethodSBOM {
			return ecosystem.SBOMAbsent(f, c.Name, MethodInventory)
		}
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "component_not_present"
		f.Method = MethodInventory
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodInventory,
			Detail: fmt.Sprintf("no dpkg, apk or rpm database in this image lists a package named %s", c.Name),
		}}
		return f
	}

	if req.Advisory == nil {
		// An explicitly requested id that OSV could not map to this package.
		// Reported rather than dropped: a missing finding reads as a clean one.
		f.Status = ecosystem.StatusUndetermined
		f.Reason = "no_osv_package_mapping"
		return f
	}

	if e.meta {
		return e.evaluateMetadata(f, req)
	}

	pkg := e.st.pkg
	files := e.g.Classify(pkg.Files)

	if len(files.ELF) == 0 {
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		f.Method = MethodNoCode
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodNoCode,
			Detail: fmt.Sprintf("%s installs %d files and none of them is an ELF object",
				pkg.Name, len(pkg.Files)),
		}}
		return f
	}

	blockers := e.blockers(files.ELF)

	// The mined-symbol check runs first because two later steps depend on it: it
	// answers whether the vulnerable function is in this build at all, and it is
	// what supplies the validated symbol the cgo static discharge needs.
	sym := e.checkSymbols(req.Advisory, req.Hints, files.ELF)

	// The cgo static-symbol discharge continues #24. That PR cleared the
	// static-elf taint for a CGO_ENABLED=0 entrypoint, which links no C library
	// and so cannot hide a copy of one. A cgo entrypoint might have linked it
	// in, so it stayed blocking -- but if it is unstripped, its own symbol table
	// can prove this specific advisory's function was not linked into it. That
	// proof is CVE-specific, because which namespace to look for comes from the
	// advisory, so it lives here per finding rather than at graph-build time
	// with the structural discharge. A cleared taint is dropped from this
	// finding's blockers, so the discharge unlocks a conclusion rather than
	// merely annotating a blocked one.
	cleared := e.staticSymbolDischarges(sym)
	if len(cleared) > 0 {
		blockers = e.blockersExcept(files.ELF, cleared)
	}

	// The two questions this function can answer are gated separately. Whether
	// the vulnerable code is in the image is a claim about what the package's
	// objects define; whether it would be loaded is a claim about the closure.
	// A dlopen call breaks the second and leaves the first standing, so gating
	// both on the same set withholds an answer the evidence supports.
	presence := e.presenceBlockers(files.ELF, cleared)

	// Recorded first, before anything the closure goes on to conclude, because
	// a discharged taint is the ground the conclusion stands on rather than a
	// footnote to it.
	f.Evidence = append(f.Evidence, e.discharged()...)
	for _, p := range sortedUnique(mapKeys(cleared)) {
		f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodStaticSymbolAbsent, Detail: cleared[p]})
	}

	// The mined-symbol layer runs before the closure is consulted, because it
	// answers a stronger question: whether the vulnerable function is in this
	// build at all. It is gated on the presence blockers only. A statically
	// linked entrypoint may hold a copy of the vulnerable code that the
	// package's export tables say nothing about, so that one still withholds
	// the answer -- but a dlopen call cannot put a function into a library that
	// does not export one, and neither can an unresolved DT_NEEDED.
	if sym.Usable {
		f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: sym.Why})
		switch {
		case len(sym.Defined) == 0 && len(presence) == 0:
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Method = MethodDynsymAbsent
			f.Evidence = append(f.Evidence, reachabilityNotes(blockers)...)
			return f

		case len(sym.Defined) > 0 && len(sym.Importers) == 0 && len(files.Reachable) > 0:
			f.Evidence = append(f.Evidence, ecosystem.Evidence{
				Origin: MethodImportAbsent,
				Detail: fmt.Sprintf("no object the closure reaches imports %s",
					strings.Join(sym.Defined, ", ")),
			})
			if e.trust && len(blockers) == 0 {
				f.Status = ecosystem.StatusNotInPath
				f.Justification = "vulnerable_code_not_in_execute_path"
				f.Method = MethodImportAbsent
				return f
			}
		}
	} else if req.Hints != nil {
		// Validation rejected the hints. Recording that is the point: a reader
		// must be able to tell "the model found nothing usable" from "the
		// model was never asked".
		f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: sym.Why})
	}

	switch {
	case len(files.Reachable) == 0 && len(blockers) == 0:
		f.Status = ecosystem.StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = MethodClosure
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodClosure,
			Detail: fmt.Sprintf("%s installs %s, and the dynamic linker would load none of them starting from %s",
				pkg.Name, objects(files.ELF), e.entrypoint()),
		})
		f.Evidence = append(f.Evidence, e.gated(files.ELF)...)

	case len(files.Reachable) == 0:
		// Unreachable, but something about this image makes the closure an
		// incomplete account of what gets loaded. The evidence records both
		// halves: a reader can see the closure found nothing and see exactly
		// what stopped that from being the answer.
		f.Status = ecosystem.StatusLinked
		f.Method = MethodClosure
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodClosure,
			Detail: fmt.Sprintf("%s installs %s and the closure reaches none of them, but this image cannot be closed over",
				pkg.Name, objects(files.ELF)),
		})
		f.Evidence = append(f.Evidence, e.gated(files.ELF)...)
		f.Evidence = append(f.Evidence, blockers...)
		f.Reachability = "installed but not reached by the shared-library closure, which this image blocks from being conclusive"

	default:
		f.Status = ecosystem.StatusLinked
		f.Method = MethodClosure
		f.Evidence = append(f.Evidence, e.loadedBy(files.Reachable)...)
		f.Evidence = append(f.Evidence, blockers...)
		f.Reachability = fmt.Sprintf("loaded: the dynamic linker reaches %s from %s (whether the vulnerable function is called is not asserted)",
			objects(files.Reachable), e.entrypoint())
	}
	return f
}

// evaluateMetadata decides one advisory against an inventory handed in from
// outside, with no filesystem behind it.
//
// Up to three answers are available and one is not. A package whose header
// lists no ELF object installs no code that could execute, and that is the same
// evidence MethodNoCode rests on when it is read out of an image -- so it is
// reused verbatim rather than given a weaker name for having come from a file.
// Under --rpm-deep a second not_present is reachable: the package's objects were
// extracted, so the dynsym-absent test can find that the vulnerable function is
// exported by none of them. Everything else is undetermined.
//
// Whether even the first answer is available depends on the source. An rpm
// header carries FILECLASS, so it earns not_present; a description that lists
// no files at all -- an SBOM component, say -- has not established that the
// package ships no code, only that nobody looked. Meta.CanRuleOutCode is where
// those two part company, and it is deliberately the conservative test: the
// cost of the wrong answer here is a package declared clean that is not.
//
// It is never linked and never not_in_path, even under --rpm-deep. Both of
// those are claims about what the dynamic linker would load, no closure ran, and
// there is nothing to have run one over. An honest undetermined is the whole
// reason this mode can be trusted at all: what it cannot see, it says it cannot
// see.
func (e evaluator) evaluateMetadata(f ecosystem.Finding, req ecosystem.Request) ecosystem.Finding {
	pkg, meta := e.st.pkg, e.st.meta

	if meta.CanRuleOutCode() {
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		f.Method = MethodNoCode
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodNoCode,
			Detail: fmt.Sprintf("%s would install %d files and its header classifies none of them as an ELF object",
				pkg.Name, len(pkg.Files)),
		}}
		return f
	}

	// Under --rpm-deep the package's ELF objects were extracted, so the same
	// dynsym-absent test an installed scan runs is available here: if the
	// vulnerable function the advisory names shares a namespace with what this
	// package exports but is itself exported by none of its objects, the
	// vulnerable code is not in this build. It needs a symbol to look for,
	// which only --mine-advisories supplies, so this fires only when both flags
	// are set and the header listed ELF objects to read. It can reach
	// not_present and nothing stronger: no closure ran, so nothing is ever
	// linked or ruled out as unreachable.
	if len(meta.ELF) > 0 {
		if sym := e.checkSymbols(req.Advisory, req.Hints, meta.ELF); sym.Usable && len(sym.Defined) == 0 {
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Method = MethodDynsymAbsent
			f.Evidence = []ecosystem.Evidence{
				{Origin: e.metaOrigin(), Detail: metadataDetail(pkg, meta)},
				{Origin: MethodDynsymAbsent, Detail: sym.Why},
			}
			return f
		}
	}

	f.Status = ecosystem.StatusUndetermined
	f.Reason = ReasonNoReachabilityTest
	f.Evidence = []ecosystem.Evidence{{
		Origin: e.metaOrigin(),
		Detail: metadataDetail(pkg, meta),
	}}
	return f
}

// metaOrigin is the evidence origin for a handed-in inventory, defaulting to
// the rpm file this path was built for. The default is here as well as in
// suppliedOrigin because an evaluator can be built directly in a test.
func (e evaluator) metaOrigin() string {
	if e.origin != "" {
		return e.origin
	}
	return MethodRPMFile
}

// metadataDetail says what the metadata did and did not establish.
//
// The two cases are separate sentences because they are separate sizes of gap.
// A package known to ship ELF objects that could not be traced leaves one
// question open; a package whose file list was never available leaves two, and
// a reader deciding how much to trust the row needs to know which.
func metadataDetail(pkg pkgdb.Package, meta pkgdb.Meta) string {
	if !meta.FilesKnown {
		return fmt.Sprintf("%s was described by metadata that does not list its files, so neither whether it installs executable code nor whether that code would be loaded can be answered from it",
			pkg.Name)
	}
	return fmt.Sprintf("%s would install %s, but this scan read a package file and not a system, so nothing can be said about whether they would be loaded",
		pkg.Name, objects(meta.ELF))
}

// blockers are the taints that stop this package's objects being declared
// unreachable: every global one, plus any scoped to a library it installs.
func (e evaluator) blockers(elfFiles []string) []ecosystem.Evidence {
	return e.taints(elfFiles, true, nil)
}

// blockersExcept is blockers with the static-elf taints in cleared removed,
// because the cgo static-symbol discharge accounted for their contents for this
// finding. Only static-elf taints are dropped, and only the ones whose
// entrypoint path is in cleared: a discharge is a claim about one binary and
// one advisory, so it must not silence an unrelated blocker.
func (e evaluator) blockersExcept(elfFiles []string, cleared map[string]string) []ecosystem.Evidence {
	return e.taints(elfFiles, true, cleared)
}

// presenceBlockers are the blockers that bear on whether the vulnerable code is
// in the image at all, as opposed to whether the closure reaches it. See
// TaintKind.ThreatensPresence for why the two differ.
//
// It exists because the dynsym-absent conclusion is a different claim from the
// closure's. "No object this package installs defines the vulnerable function"
// is read out of the package's own symbol tables, and a dlopen call elsewhere
// in the image cannot make it false -- dlopen decides which objects get loaded,
// not what is inside them. Gating that conclusion on every dlopen in the image
// is what kept it from ever firing: a Debian base layer has fifteen dlopen
// callers in it before the application is added, and only one of them has to
// survive for the answer to be withheld.
func (e evaluator) presenceBlockers(elfFiles []string, cleared map[string]string) []ecosystem.Evidence {
	return e.taintsWhere(elfFiles, true, cleared, elfgraph.TaintKind.ThreatensPresence)
}

// reachabilityNotes restates the taints that still stand for a finding decided
// on presence, as notes rather than blockers.
//
// They are not dropped. An image whose closure could not be completed and an
// image whose closure was clean must never produce the same report, even when
// the answer did not turn on the difference -- a reader weighing the row is
// entitled to see that the image has fifteen runtime loaders in it. They carry
// Blocking false because for this conclusion that is simply true: nothing was
// overridden or waved away, they do not bear on it.
func reachabilityNotes(blockers []ecosystem.Evidence) []ecosystem.Evidence {
	if len(blockers) == 0 {
		return nil
	}
	out := make([]ecosystem.Evidence, 0, len(blockers)+1)
	out = append(out, ecosystem.Evidence{
		Origin: MethodClosure,
		Detail: fmt.Sprintf("%d %s stop the closure being a complete account of what loads, which withholds any answer about reachability but not this one: choosing to load an object cannot add a symbol the object does not define",
			len(blockers), noun(len(blockers))),
	})
	for _, b := range blockers {
		b.Blocking = false
		out = append(out, b)
	}
	return out
}

func noun(n int) string {
	if n == 1 {
		return "observation does"
	}
	return "observations"
}

// discharged are the taints that would have blocked this package's conclusion
// and were answered: a static entrypoint a prober could account for, a dlopen
// call the user waved off with --dlopen-policy=assume-none.
//
// They are reported because they are the reason a conclusion was available. A
// clean nothing ever threatened and a clean resting on a prober having looked
// inside a static binary are different claims, and a reader weighing the row
// cannot tell them apart if the second leaves no trace.
//
// Every discharged taint is in scope for every package, because the taints
// that can be discharged are the ones that blocked globally before they were.
// They carry Blocking false, so they are evidence and not a gate, and they are
// deliberately not part of blockers() -- callers count that slice to decide
// whether a conclusion is available at all, and an answered taint must not
// resurrect itself as a blocker by being counted there.
func (e evaluator) discharged() []ecosystem.Evidence {
	var out []ecosystem.Evidence
	for _, t := range e.g.Taints() {
		if !t.Discharged {
			continue
		}
		out = append(out, ecosystem.Evidence{Origin: MethodClosure, Detail: t.Detail})
	}
	return out
}

// gated explains the package's objects that are runtime-loaded plugins the
// closure declined to root.
//
// "The dynamic linker would load none of them" is true of a PAM module in every
// image, because nothing has a DT_NEEDED on one; what decided this row is that
// no libpam was reachable to open it either. That is a stronger claim and a
// more falsifiable one -- a reader who thinks the image does run PAM knows
// exactly which library to go looking for -- so it is said rather than left
// implied by a sentence about DT_NEEDED.
//
// Grouped by family and loader, because the pam package installs fifty-odd
// modules and one line per module would bury the finding.
func (e evaluator) gated(elfFiles []string) []ecosystem.Evidence {
	byPath := map[string]elfgraph.GatedPlugin{}
	for _, gp := range e.g.GatedPlugins() {
		byPath[gp.Path] = gp
	}
	if len(byPath) == 0 {
		return nil
	}

	type group struct {
		gp    elfgraph.GatedPlugin
		paths []string
	}
	var order []string
	groups := map[string]*group{}
	for _, f := range elfFiles {
		gp, ok := byPath[f]
		if !ok {
			continue
		}
		key := gp.What + "\x00" + gp.Loader
		if groups[key] == nil {
			groups[key] = &group{gp: gp}
			order = append(order, key)
		}
		groups[key].paths = append(groups[key].paths, f)
	}

	var out []ecosystem.Evidence
	for _, key := range order {
		g := groups[key]
		detail := fmt.Sprintf("%s is %s, and the closure reaches no %s that could open it",
			g.paths[0], g.gp.What, g.gp.Loader)
		if n := len(g.paths); n > 1 {
			detail = fmt.Sprintf("%d of those are %s (%s, %s%s), and the closure reaches no %s that could open them",
				n, g.gp.Plural, g.paths[0], g.paths[1], ellipsis(n), g.gp.Loader)
		}
		out = append(out, ecosystem.Evidence{Origin: MethodClosure, Detail: detail})
	}
	return out
}

// ellipsis is ", ..." once a list has more than the two entries prose names.
func ellipsis(n int) string {
	if n > 2 {
		return ", ..."
	}
	return ""
}

// taints maps the recorded taints in scope for this package to evidence. When
// cleared is non-nil, a blocking static-elf taint whose entrypoint path it names
// is skipped: the cgo static-symbol discharge answered it for this finding.
func (e evaluator) taints(elfFiles []string, blocking bool, cleared map[string]string) []ecosystem.Evidence {
	return e.taintsWhere(elfFiles, blocking, cleared, nil)
}

// taintsWhere is taints narrowed to the kinds keep accepts. A nil keep takes
// every kind.
func (e evaluator) taintsWhere(elfFiles []string, blocking bool, cleared map[string]string, keep func(elfgraph.TaintKind) bool) []ecosystem.Evidence {
	sonames := map[string]bool{}
	for _, f := range elfFiles {
		sonames[path.Base(f)] = true
		if n, ok := e.g.Node(f); ok && n.Info.Soname != "" {
			sonames[n.Info.Soname] = true
		}
	}

	var out []ecosystem.Evidence
	for _, t := range e.g.Taints() {
		if t.Blocking != blocking {
			continue
		}
		if keep != nil && !keep(t.Kind) {
			continue
		}
		if t.Kind == elfgraph.TaintStaticELF && cleared[t.Path] != "" {
			continue
		}
		// A scoped taint is a claim about one soname. It belongs to this
		// finding only when the soname is one this package provides -- meaning
		// something needed a library the package installs and the resolver did
		// not find it, so the resolver, not the image, is what came up empty.
		if !t.Global && !sonames[t.Soname] {
			continue
		}
		out = append(out, ecosystem.Evidence{
			Origin:   MethodClosure,
			Detail:   t.Detail,
			Blocking: t.Blocking,
		})
	}
	return out
}

// staticSymbolDischarges is the cgo analogue of #24's structural discharge,
// resolved per finding. For the validated symbols this advisory yielded, it asks
// of every blocking static-elf entrypoint whether its own symbol table proves
// the vulnerable code was not linked in, and returns the ones it can clear:
// keyed by entrypoint path, valued by the evidence detail that says why.
//
// It fires only with a validated symbol in hand, which means only under
// --mine-advisories. Without one there is no CVE-specific question to ask of the
// binary, and a blanket "this cgo binary looks clean" is exactly the false
// removal the whole package exists to refuse. A nil return leaves every blocker
// standing, so the conservative default is what an absent discharge falls back
// to.
func (e evaluator) staticSymbolDischarges(sym symbolCheck) map[string]string {
	if !sym.Usable || len(sym.Validated) == 0 {
		return nil
	}
	var out map[string]string
	for _, t := range e.g.Taints() {
		if t.Kind != elfgraph.TaintStaticELF || !t.Blocking || t.Path == "" {
			continue
		}
		if detail, ok := e.proveStaticAbsent(t.Path, sym.Validated); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[t.Path] = detail
		}
	}
	return out
}

// proveStaticAbsent decides whether the static entrypoint at path provably does
// not carry the vulnerable code named by validated, reusing mine.go's namespace
// discipline so the two symbol tests stay consistent.
//
// Every branch that cannot prove absence returns false and leaves the taint
// blocking, because the promise is one-directional: a check may narrow the
// conservative default, never loosen it.
//
//   - cgo off/unknown, stripped, or unreadable: nothing to reason over. (An
//     off build was already discharged structurally at graph time and is no
//     longer a blocking taint, so it does not reach here in practice; declining
//     it costs nothing and states the intent.)
//   - a validated symbol present in the table: that is the vulnerable code
//     linked in. Stays blocking.
//   - a validated symbol absent while its namespace is also absent: the binary
//     does not visibly use the library family at all, so its absence is not
//     evidence -- the family may be there under localised or stripped names.
//     Stays blocking. This is the open-world rule from checkSymbols, applied to
//     the entrypoint's own table.
//   - every validated symbol absent, every namespace present: the family is
//     linked and the vulnerable function is not, so it was not compiled into
//     this build. Discharged.
func (e evaluator) proveStaticAbsent(path string, validated []string) (string, bool) {
	defined, stripped, cgo, err := e.readStatic(path)
	if err != nil || !cgo || stripped {
		return "", false
	}

	bin := make(map[string]bool, len(defined))
	for _, s := range defined {
		bin[s] = true
	}

	for _, v := range validated {
		if bin[v] {
			return "", false
		}
	}
	for _, v := range validated {
		if !hasNamespace(bin, v) {
			return "", false
		}
	}

	return fmt.Sprintf("%s is a cgo binary, but its static symbol table carries the %s namespace and not %s, "+
		"so the vulnerable code is not statically linked into it",
		path, strings.Join(namespacesOf(validated), ", "), strings.Join(validated, ", ")), true
}

// readStatic reads one static entrypoint's symbol table, once per image. The
// same binary is asked about for every finding whose blocker it is, so without
// the cache its table -- and the buildinfo read behind the cgo test -- would be
// parsed once per advisory.
func (e evaluator) readStatic(path string) (defined []string, stripped, cgo bool, err error) {
	e.sym.mu.Lock()
	if c, ok := e.sym.static[path]; ok {
		e.sym.mu.Unlock()
		return c.defined, c.stripped, c.cgo, c.err
	}
	e.sym.mu.Unlock()

	read := e.sym.readStatic
	if read == nil {
		read = readStaticEntrypoint
	}
	defined, stripped, cgo, err = read(e.sym.fsys, path)

	e.sym.mu.Lock()
	e.sym.static[path] = staticEntry{defined: defined, stripped: stripped, cgo: cgo, err: err}
	e.sym.mu.Unlock()
	return defined, stripped, cgo, err
}

// namespacesOf is the deduplicated set of library namespaces the symbols carry,
// for the evidence line -- SSL_free_buffers and SSL_read collapse to SSL_.
func namespacesOf(syms []string) []string {
	var out []string
	for _, s := range syms {
		if ns := namespace(s); ns != "" {
			out = append(out, ns)
		}
	}
	return sortedUnique(out)
}

// mapKeys returns a map's keys, for a deterministic ordering pass through
// sortedUnique.
func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// loadedBy explains a reachable object by naming what pulls it in.
func (e evaluator) loadedBy(reachable []string) []ecosystem.Evidence {
	var out []ecosystem.Evidence
	for _, p := range reachable {
		n, ok := e.g.Node(p)
		if !ok {
			continue
		}
		switch {
		case n.Root:
			out = append(out, ecosystem.Evidence{
				Origin: MethodClosure,
				Detail: fmt.Sprintf("%s is %s", p, n.Why),
			})
		case len(n.NeededBy) > 0:
			out = append(out, ecosystem.Evidence{
				Origin: MethodClosure,
				Detail: fmt.Sprintf("%s is loaded by %s", p, strings.Join(sortedUnique(n.NeededBy), ", ")),
			})
		}
		// Three explanations is enough to establish reachability; a package
		// like glibc is reached by hundreds of objects and listing them all
		// would bury the finding.
		if len(out) == 3 {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, ecosystem.Evidence{
			Origin: MethodClosure,
			Detail: fmt.Sprintf("the closure reaches %s", objects(reachable)),
		})
	}
	return out
}

// entrypoint names what the closure was rooted at, for evidence prose.
func (e evaluator) entrypoint() string {
	roots := e.g.Roots()
	switch {
	case len(roots) == 0:
		return "the image entrypoint"
	case len(roots) == 1:
		return roots[0]
	default:
		return fmt.Sprintf("%s and %d other roots", roots[0], len(roots)-1)
	}
}

// objects renders a file list for evidence prose, naming a couple of examples
// rather than a screenful.
func objects(files []string) string {
	switch len(files) {
	case 1:
		return "1 ELF object (" + files[0] + ")"
	case 2:
		return fmt.Sprintf("2 ELF objects (%s, %s)", files[0], files[1])
	default:
		return fmt.Sprintf("%d ELF objects (%s, %s, ...)", len(files), files[0], files[1])
	}
}
