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
)

// evaluator holds what every finding for one component needs.
type evaluator struct {
	g    *elfgraph.Graph
	st   *state
	logf func(string, ...any)
}

func (p *Plugin) evaluator(g *elfgraph.Graph, st *state) evaluator {
	return evaluator{g: g, st: st, logf: p.Logf}
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

	switch {
	case len(files.Reachable) == 0 && len(blockers) == 0:
		f.Status = ecosystem.StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = MethodClosure
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodClosure,
			Detail: fmt.Sprintf("%s installs %s, and the dynamic linker would load none of them starting from %s",
				pkg.Name, objects(files.ELF), e.entrypoint()),
		}}

	case len(files.Reachable) == 0:
		// Unreachable, but something about this image makes the closure an
		// incomplete account of what gets loaded. The evidence records both
		// halves: a reader can see the closure found nothing and see exactly
		// what stopped that from being the answer.
		f.Status = ecosystem.StatusLinked
		f.Method = MethodClosure
		f.Evidence = append([]ecosystem.Evidence{{
			Origin: MethodClosure,
			Detail: fmt.Sprintf("%s installs %s and the closure reaches none of them, but this image cannot be closed over",
				pkg.Name, objects(files.ELF)),
		}}, blockers...)
		f.Reachability = "installed but not reached by the shared-library closure, which this image blocks from being conclusive"

	default:
		f.Status = ecosystem.StatusLinked
		f.Method = MethodClosure
		f.Evidence = append(e.loadedBy(files.Reachable), blockers...)
		f.Reachability = fmt.Sprintf("loaded: the dynamic linker reaches %s from %s (whether the vulnerable function is called is not asserted)",
			objects(files.Reachable), e.entrypoint())
	}
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
