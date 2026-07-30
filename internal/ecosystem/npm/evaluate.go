package npm

import (
	"fmt"
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/modgraph"
)

// Methods name the deterministic test behind a status, and appear in the
// output. They are part of the tool's published vocabulary.
const (
	// MethodInventory: the node_modules tree was consulted and nothing else.
	MethodInventory = "npmdist-inventory"
	// MethodNoCode: the package is installed but ships nothing Node can load.
	MethodNoCode = "npmdist-no-code"
	// MethodGraph: the static require graph, rooted at what the image runs,
	// was resolved and consulted.
	MethodGraph = "npm-require-graph"
)

// jsCodeExts are the extensions that carry executable JavaScript.
//
// ".json" is deliberately absent, and so is ".ts". A package that ships only
// data or only type declarations -- the whole @types/* family, and the many
// packages that are one big JSON table -- has nothing Node can execute, and
// that is the clearest case this plugin can decide today.
var jsCodeExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".node": true,
}

// evaluator holds what every finding for one component needs.
type evaluator struct {
	st *state

	// g is the require closure, or nil when no component in this run needed
	// one and it was never built.
	g *modgraph.Graph

	// node resolves a mined subpath to the files it names.
	node *node

	trust bool // --trust-import-absence
}

// evaluate decides one advisory against one installed package.
//
// The order of the cases is the order of increasing cost and decreasing
// certainty, the same order the OS and PyPI plugins use: whether the package
// exists, whether it ships code, and whether anything the image runs requires
// that code.
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
		if len(e.st.unreadable) > 0 {
			// Something under node_modules could not be identified, so "no
			// package here is named X" is not a claim this scan is entitled to
			// make: the unnamed one could be X.
			f.Status = ecosystem.StatusUndetermined
			f.Reason = "unreadable_package_manifest"
			f.Evidence = []ecosystem.Evidence{{
				Origin:   MethodInventory,
				Detail:   fmt.Sprintf("no installed package is named %s, but %s could not be parsed", c.Name, manifests(e.st.unreadable)),
				Blocking: true,
			}}
			return f
		}
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "component_not_present"
		f.Method = MethodInventory
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodInventory,
			Detail: fmt.Sprintf("no node_modules directory in this image contains a package named %s", c.Name),
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

	files := e.st.files()
	code := codeFiles(files)

	if len(code) == 0 {
		// A package directory always holds at least the package.json the
		// inventory read to find it, so a file list with nothing in it is not
		// a package that ships nothing -- it is a walk that could not read the
		// directory. "We could not look" must never render as "there is
		// nothing there".
		if !e.st.filesKnown() || len(files) == 0 {
			f.Status = ecosystem.StatusLinked
			f.Method = MethodInventory
			f.Evidence = []ecosystem.Evidence{{
				Origin:   MethodInventory,
				Detail:   fmt.Sprintf("%s is installed and its directory could not be listed, so what it ships is unknown", c.Name),
				Blocking: true,
			}}
			f.Reachability = "installed, with no readable directory to say what it contains"
			return f
		}
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		f.Method = MethodNoCode
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodNoCode,
			Detail: fmt.Sprintf("%s ships %d files and none of them is JavaScript Node can load",
				c.Name, len(files)),
		}}
		return f
	}

	f.Evidence = []ecosystem.Evidence{{
		Origin: MethodInventory,
		Detail: fmt.Sprintf("%s is installed in %s and ships %s",
			c.Name, strings.Join(c.Locations, ", "), modules(code)),
	}}

	// The mined-subpath layer runs before the closure, because it answers a
	// stronger question: whether the vulnerable module is in this build at
	// all. Both of its conclusions defer to a blocking taint, the same as the
	// closure's do.
	f, done := e.mined(f, c, req)
	if done {
		return f
	}

	// Everything above answers "is the code here". What follows answers "does
	// anything require it", which is the only remaining lever: npm strips no
	// dead code at install time, so an installed package's modules are on disk
	// whether or not they ever run.
	return e.reachability(f, c)
}

// reachability applies the require graph to a package known to ship code.
func (e evaluator) reachability(f ecosystem.Finding, c ecosystem.Component) ecosystem.Finding {
	linked := func(reason string) ecosystem.Finding {
		f.Status = ecosystem.StatusLinked
		if f.Method == "" {
			f.Method = MethodInventory
		}
		f.Reachability = reason
		return f
	}

	if e.g == nil {
		return linked("installed: the package's code is on disk and loadable (whether anything requires it is not asserted)")
	}

	files := e.g.Classify(e.st.files())
	if len(files.Module) == 0 {
		// The graph can only speak about files it would recognise as modules.
		// A package whose tree holds none has nothing to be unreached, and
		// silence there is not evidence.
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin:   MethodGraph,
			Detail:   fmt.Sprintf("%s ships code the require graph cannot address, so reachability was not decided for it", c.Name),
			Blocking: true,
		})
		return linked("installed, with no loadable module the graph could follow")
	}

	blockers := e.blockers()

	switch {
	case len(files.Reachable) > 0:
		f.Method = MethodGraph
		f.Evidence = append(f.Evidence, e.requiredBy(files.Reachable)...)
		f.Evidence = append(f.Evidence, blockers...)
		return linked(fmt.Sprintf("required: the closure from %s reaches %s (whether the vulnerable code is called is not asserted)",
			e.entrypoint(), modules(files.Reachable)))

	case len(blockers) > 0:
		// Unreached, but something about this image makes the closure an
		// incomplete account of what gets required. Both halves are recorded:
		// a reader can see that nothing reached it and see exactly what
		// stopped that from being the answer.
		f.Method = MethodGraph
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodGraph,
			Detail: fmt.Sprintf("nothing reachable from %s requires %s, but this image's requires cannot be fully resolved",
				e.entrypoint(), c.Name),
		})
		f.Evidence = append(f.Evidence, blockers...)
		return linked("installed but not reached by the require graph, which this image blocks from being conclusive")

	case !e.st.filesKnown():
		f.Method = MethodGraph
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin:   MethodGraph,
			Detail:   fmt.Sprintf("nothing requires the modules found for %s, but which files it installs was inferred rather than read", c.Name),
			Blocking: true,
		})
		return linked("installed but not reached, with no manifest to say that is the whole package")
	}

	f.Status = ecosystem.StatusNotInPath
	f.Justification = "vulnerable_code_not_in_execute_path"
	f.Method = MethodGraph
	f.Evidence = append(f.Evidence, ecosystem.Evidence{
		Origin: MethodGraph,
		Detail: fmt.Sprintf("%s ships %s, and nothing reachable from %s requires any of them",
			c.Name, modules(files.Module), e.entrypoint()),
	})
	return f
}

// blockers are the taints that stop this package's modules being declared
// unrequired: every global one, plus any scoped to a name it is required by.
func (e evaluator) blockers() []ecosystem.Evidence {
	var out []ecosystem.Evidence
	for _, t := range e.g.TaintsFor(e.st.importNames()) {
		if !t.Blocking {
			continue
		}
		out = append(out, ecosystem.Evidence{
			Origin:   MethodGraph,
			Detail:   t.Detail,
			Blocking: true,
		})
	}
	return out
}

// requiredBy explains a reached module by naming what requires it.
func (e evaluator) requiredBy(reachable []string) []ecosystem.Evidence {
	var out []ecosystem.Evidence
	for _, p := range reachable {
		n, ok := e.g.Node(p)
		if !ok {
			continue
		}
		switch {
		case n.Root:
			out = append(out, ecosystem.Evidence{
				Origin: MethodGraph,
				Detail: fmt.Sprintf("%s is %s", p, n.Why),
			})
		case len(n.ImportedBy) > 0:
			out = append(out, ecosystem.Evidence{
				Origin: MethodGraph,
				Detail: fmt.Sprintf("%s is required by %s", p, strings.Join(n.ImportedBy, ", ")),
			})
		}
		// Three explanations establish reachability; a package like debug is
		// required from hundreds of places and listing them all buries the
		// finding.
		if len(out) == 3 {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, ecosystem.Evidence{
			Origin: MethodGraph,
			Detail: fmt.Sprintf("the require graph reaches %s", modules(reachable)),
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

// codeFiles picks the loadable files out of an installed file list.
func codeFiles(files []string) []string {
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, ".d.ts") {
			continue
		}
		if jsCodeExts[strings.ToLower(path.Ext(f))] {
			out = append(out, f)
			continue
		}
		// A bin shim has no extension at all, and it is as much the package's
		// executable code as its modules are.
		if path.Base(path.Dir(f)) == "bin" {
			out = append(out, f)
		}
	}
	return out
}

// modules renders a file list for evidence prose, naming a couple of examples
// rather than a screenful.
func modules(files []string) string {
	switch len(files) {
	case 1:
		return "1 loadable file (" + files[0] + ")"
	case 2:
		return fmt.Sprintf("2 loadable files (%s, %s)", files[0], files[1])
	default:
		return fmt.Sprintf("%d loadable files (%s, %s, ...)", len(files), files[0], files[1])
	}
}

// manifests renders a list of unparseable package.json files.
func manifests(paths []string) string {
	if len(paths) == 1 {
		return paths[0]
	}
	return fmt.Sprintf("%s and %d others", paths[0], len(paths)-1)
}
