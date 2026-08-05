package ospkg

import (
	"fmt"
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
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
)

// ReasonNoReachabilityTest is the reason on every finding a metadata-only scan
// could not decide. It is exported because the report counts them to write its
// caveat, and a caveat that disagreed with the rows it explains would be worse
// than none.
const ReasonNoReachabilityTest = "no_reachability_test_possible"

// evaluator holds what every finding for one component needs.
type evaluator struct {
	g     *elfgraph.Graph
	st    *state
	sym   *symbolCache
	trust bool // --trust-import-absence
	// meta is set when the inventory was handed in rather than read out of a
	// tree, and g is nil. See evaluateMetadata.
	meta bool
	logf func(string, ...any)
}

func (p *Plugin) evaluator(pr *prepared, g *elfgraph.Graph, st *state) evaluator {
	return evaluator{g: g, st: st, sym: pr.syms, trust: p.TrustImportAbsence, meta: pr.metadataOnly, logf: p.Logf}
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
		return e.evaluateMetadata(f)
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

	// The mined-symbol layer runs before the closure is consulted, because it
	// answers a stronger question: whether the vulnerable function is in this
	// build at all. It is gated on there being no blocking taint for the same
	// reason the closure is -- a statically linked entrypoint may hold a copy
	// of the vulnerable code, and the package's own export tables say nothing
	// about what is inside it.
	if sym := e.checkSymbols(req.Advisory, req.Hints, files.ELF); sym.Usable {
		f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: sym.Why})
		switch {
		case len(sym.Defined) == 0 && len(blockers) == 0:
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Method = MethodDynsymAbsent
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

// evaluateMetadata decides one advisory against a package file, with no
// filesystem behind it.
//
// Two answers are available and the third one is not. A package whose header
// lists no ELF object installs no code that could execute, and that is the
// same evidence MethodNoCode rests on when it is read out of an image -- so it
// is reused verbatim rather than given a weaker name for having come from a
// file. Everything else is undetermined.
//
// It is never linked and never not_in_path. Both of those are claims about
// what the dynamic linker would load, no closure ran, and there is nothing to
// have run one over. An honest undetermined is the whole reason this mode can
// be trusted at all: what it cannot see, it says it cannot see.
func (e evaluator) evaluateMetadata(f ecosystem.Finding) ecosystem.Finding {
	pkg, meta := e.st.pkg, e.st.meta

	if !meta.HasELF() {
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

	f.Status = ecosystem.StatusUndetermined
	f.Reason = ReasonNoReachabilityTest
	f.Evidence = []ecosystem.Evidence{{
		Origin: MethodRPMFile,
		Detail: fmt.Sprintf("%s would install %s, but this scan read a package file and not a system, so nothing can be said about whether they would be loaded",
			pkg.Name, objects(meta.ELF)),
	}}
	return f
}

// blockers are the taints that stop this package's objects being declared
// unreachable: every global one, plus any scoped to a library it installs.
func (e evaluator) blockers(elfFiles []string) []ecosystem.Evidence {
	sonames := map[string]bool{}
	for _, f := range elfFiles {
		sonames[path.Base(f)] = true
		if n, ok := e.g.Node(f); ok && n.Info.Soname != "" {
			sonames[n.Info.Soname] = true
		}
	}

	var out []ecosystem.Evidence
	for _, t := range e.g.Taints() {
		if !t.Blocking {
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
			Blocking: true,
		})
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
