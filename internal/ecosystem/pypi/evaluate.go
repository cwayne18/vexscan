package pypi

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
	// MethodInventory: the installed-distribution metadata was consulted and
	// nothing else.
	MethodInventory = "pydist-inventory"
	// MethodNoCode: the distribution is installed but its own manifest lists no
	// importable code.
	MethodNoCode = "pydist-no-code"
	// MethodGraph: the static import graph, rooted at what the image runs, was
	// resolved and consulted.
	MethodGraph = "py-import-graph"
)

// pyCodeExts are the file extensions that carry executable Python.
//
// ".pyi" is deliberately absent: a stub file is type information, never
// imported at runtime, and a stubs-only distribution -- the whole types-*
// family on PyPI -- is the clearest case this plugin can decide today.
var pyCodeExts = map[string]bool{
	".py": true, ".pyc": true, ".pyo": true,
	".so": true, ".pyd": true, ".dylib": true,
}

// evaluator holds what every finding for one component needs.
type evaluator struct {
	st *state

	// g is the import closure, or nil when no component in this run needed one
	// and it was never built.
	g *modgraph.Graph

	// meta is set when the inventory was handed in rather than read out of a
	// tree, and g is nil for that reason rather than for want of a component
	// that needed it. The two are not interchangeable: a nil graph on its own
	// still leaves the file list to conclude from, and there is no file list
	// here. See ecosystem.SBOMFinding.
	meta bool

	trust bool // --trust-import-absence
}

// evaluate decides one advisory against one installed distribution.
//
// The order of the cases is the order of increasing cost and decreasing
// certainty, the same order the OS plugin uses: whether the distribution
// exists, whether it ships code, and whether anything the image runs imports
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
	// image does not contain the distribution the id was asked about.
	if e.st.absent {
		if e.meta {
			return ecosystem.SBOMAbsent(f, c.Name, MethodInventory)
		}
		if len(e.st.unreadable) > 0 {
			// Something in a site-packages directory could not be identified, so
			// "no distribution here is named X" is not a claim this scan is
			// entitled to make: the unnamed one could be X.
			f.Status = ecosystem.StatusUndetermined
			f.Reason = "unreadable_dist_metadata"
			f.Evidence = []ecosystem.Evidence{{
				Origin:   MethodInventory,
				Detail:   fmt.Sprintf("no installed distribution is named %s, but %s could not be identified", c.Name, dists(e.st.unreadable)),
				Blocking: true,
			}}
			return f
		}
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "component_not_present"
		f.Method = MethodInventory
		f.Evidence = []ecosystem.Evidence{{
			Origin: MethodInventory,
			Detail: fmt.Sprintf("no site-packages directory in this image contains a distribution named %s", c.Name),
		}}
		return f
	}

	if req.Advisory == nil {
		// An explicitly requested id that OSV could not map to this
		// distribution. Reported rather than dropped: a missing finding reads as
		// a clean one.
		f.Status = ecosystem.StatusUndetermined
		f.Reason = "no_osv_package_mapping"
		return f
	}

	// Before the file list, because there is not one. Everything below reads
	// e.st.files() as an account of what the distribution installs, and a
	// component out of a bill of materials installs nothing as far as this
	// process can see -- which would take the empty list for the manifest of a
	// distribution that ships no code.
	if e.meta {
		return ecosystem.SBOMFinding(f, c.Name)
	}

	files := e.st.files()
	code := codeFiles(files)

	if len(code) == 0 {
		// Only the distribution's own manifest can support this. A file list
		// reconstructed by walking directories can be empty because the
		// directories were not where the guessed import name said they were,
		// and "we looked in the wrong place" must never render as "ships no
		// code".
		if e.st.filesKnown() {
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Method = MethodNoCode
			f.Evidence = []ecosystem.Evidence{{
				Origin: MethodNoCode,
				Detail: fmt.Sprintf("%s installs %d files and none of them is importable Python",
					c.Name, len(files)),
			}}
			return f
		}
		f.Status = ecosystem.StatusLinked
		f.Method = MethodInventory
		f.Evidence = []ecosystem.Evidence{{
			Origin:   MethodInventory,
			Detail:   fmt.Sprintf("%s installs no importable Python that could be found, but it ships no RECORD, so its file list was reconstructed rather than read", c.Name),
			Blocking: true,
		}}
		f.Reachability = "installed, with no readable installation manifest to say what it contains"
		return f
	}

	f.Evidence = []ecosystem.Evidence{{
		Origin: MethodInventory,
		Detail: fmt.Sprintf("%s is installed in %s and ships %s",
			c.Name, strings.Join(c.Locations, ", "), modules(code)),
	}}

	// The mined-module layer runs before the closure, because it answers a
	// stronger question: whether the vulnerable module is in this build at
	// all. Both of its conclusions defer to a blocking taint, the same as the
	// closure's do.
	f, done := e.mined(f, c, code, req)
	if done {
		return f
	}

	// Everything above answers "is the code here". What follows answers "does
	// anything import it", which is the only remaining lever: Python strips no
	// dead code at build time, so an installed distribution's modules are on
	// disk whether or not they ever run.
	return e.reachability(f, c, code)
}

// mined applies the mined-module layer, returning done when it decided the
// finding on its own.
//
// It changes nothing without --mine-advisories, and nothing when validation
// rejected every hint -- but it records what it did either way, because a
// reader has to be able to tell "the model found nothing usable" from "the
// model was never asked".
func (e evaluator) mined(f ecosystem.Finding, c ecosystem.Component, code []string, req ecosystem.Request) (ecosystem.Finding, bool) {
	m := e.checkModules(req.Advisory, req.Hints, code)
	if !m.Usable {
		if req.Hints != nil {
			f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: m.Why})
		}
		return f, false
	}
	f.Evidence = append(f.Evidence, ecosystem.Evidence{Origin: MethodMined, Detail: m.Why})

	var blockers []ecosystem.Evidence
	if e.g != nil {
		blockers = e.blockers()
	}

	if len(m.Present) == 0 {
		// The advisory's own module is not among the files this distribution
		// installed. A reconstructed file list cannot support that -- it can
		// be missing a module because the walk looked in the wrong place --
		// and neither can a run whose graph is already blocked, since whatever
		// blocked it may equally be loading a copy of the code.
		if e.st.filesKnown() && len(blockers) == 0 {
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Method = MethodModuleAbsent
			f.Evidence = append(f.Evidence, ecosystem.Evidence{
				Origin: MethodModuleAbsent,
				Detail: fmt.Sprintf("%s installs %d files and none of them provides %s",
					c.Name, len(e.st.files()), strings.Join(m.Validated, ", ")),
			})
			return f, true
		}
		f.Evidence = append(f.Evidence, blockers...)
		return f, false
	}

	// The vulnerable module is installed. Whether anything imports *it* is a
	// sharper question than whether anything imports the distribution, and it
	// is the one case where a distribution the closure reaches can still be
	// concluded on.
	if e.g == nil {
		return f, false
	}
	// Only interesting while the distribution itself is reached: if nothing
	// imports any of it, the ordinary closure row already says so, and saying
	// it again about one module adds nothing.
	if len(e.g.Classify(code).Reachable) == 0 {
		return f, false
	}
	if files := e.g.Classify(m.Files); len(files.Module) > 0 && len(files.Reachable) == 0 {
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodImportAbsent,
			Detail: fmt.Sprintf("nothing reachable from %s imports %s, though other modules of %s are reached",
				e.entrypoint(), strings.Join(m.Present, ", "), c.Name),
		})
		if e.trust && len(blockers) == 0 {
			f.Status = ecosystem.StatusNotInPath
			f.Justification = "vulnerable_code_not_in_execute_path"
			f.Method = MethodImportAbsent
			return f, true
		}
	}
	return f, false
}

// reachability applies the import graph to a distribution known to ship code.
func (e evaluator) reachability(f ecosystem.Finding, c ecosystem.Component, code []string) ecosystem.Finding {
	linked := func(reason string) ecosystem.Finding {
		f.Status = ecosystem.StatusLinked
		if f.Method == "" {
			f.Method = MethodInventory
		}
		f.Reachability = reason
		return f
	}

	if e.g == nil {
		return linked("installed: the distribution's code is on disk and importable (whether anything imports it is not asserted)")
	}

	files := e.g.Classify(e.st.files())
	if len(files.Module) == 0 {
		// The graph can only speak about files it would recognise as modules.
		// A distribution whose manifest lists none -- console scripts only, or
		// a file list that was reconstructed and found nothing -- has no
		// modules to be unreached, and silence there is not evidence.
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin:   MethodGraph,
			Detail:   fmt.Sprintf("%s ships code the import graph cannot address, so reachability was not decided for it", c.Name),
			Blocking: true,
		})
		return linked("installed, with no importable module the graph could follow")
	}

	blockers := e.blockers()

	switch {
	case len(files.Reachable) > 0:
		f.Method = MethodGraph
		f.Evidence = append(f.Evidence, e.importedBy(files.Reachable)...)
		f.Evidence = append(f.Evidence, blockers...)
		return linked(fmt.Sprintf("imported: the closure from %s reaches %s (whether the vulnerable code is called is not asserted)",
			e.entrypoint(), modules(files.Reachable)))

	case len(blockers) > 0:
		// Unreached, but something about this image makes the closure an
		// incomplete account of what gets imported. Both halves are recorded:
		// a reader can see that nothing reached it and see exactly what stopped
		// that from being the answer.
		f.Method = MethodGraph
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodGraph,
			Detail: fmt.Sprintf("nothing reachable from %s imports %s, but this image's imports cannot be fully resolved",
				e.entrypoint(), c.Name),
		})
		f.Evidence = append(f.Evidence, blockers...)
		return linked("installed but not reached by the import graph, which this image blocks from being conclusive")

	case !e.st.filesKnown():
		// The graph reached none of the modules the file list names -- but the
		// list was reconstructed by guessing where the code lives, so the
		// modules that were checked may not be the ones the distribution
		// installs. That is the wrong place to conclude anything from.
		f.Method = MethodGraph
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin:   MethodGraph,
			Detail:   fmt.Sprintf("nothing imports the modules found for %s, but it ships no RECORD, so which files it installs was inferred rather than read", c.Name),
			Blocking: true,
		})
		return linked("installed but not reached, with no installation manifest to say that is the whole distribution")
	}

	f.Status = ecosystem.StatusNotInPath
	f.Justification = "vulnerable_code_not_in_execute_path"
	f.Method = MethodGraph
	f.Evidence = append(f.Evidence, ecosystem.Evidence{
		Origin: MethodGraph,
		Detail: fmt.Sprintf("%s installs %s, and nothing reachable from %s imports any of them",
			c.Name, modules(files.Module), e.entrypoint()),
	})
	return f
}

// blockers are the taints that stop this distribution's modules being declared
// unimported: every global one, plus any scoped to a name it is imported by.
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

// importedBy explains a reached module by naming what imports it.
func (e evaluator) importedBy(reachable []string) []ecosystem.Evidence {
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
				Detail: fmt.Sprintf("%s is imported by %s", p, strings.Join(n.ImportedBy, ", ")),
			})
		}
		// Three explanations establish reachability; a distribution like six is
		// imported from hundreds of places and listing them all buries the
		// finding.
		if len(out) == 3 {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, ecosystem.Evidence{
			Origin: MethodGraph,
			Detail: fmt.Sprintf("the import graph reaches %s", modules(reachable)),
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

// codeFiles picks the importable files out of an installed file list.
func codeFiles(files []string) []string {
	var out []string
	for _, f := range files {
		if pyCodeExts[strings.ToLower(path.Ext(f))] {
			out = append(out, f)
			continue
		}
		// A console script is generated Python with no extension at all, and it
		// is as much the distribution's executable code as its modules are.
		if d := path.Base(path.Dir(f)); d == "bin" || d == "sbin" || d == "Scripts" {
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
		return "1 importable file (" + files[0] + ")"
	case 2:
		return fmt.Sprintf("2 importable files (%s, %s)", files[0], files[1])
	default:
		return fmt.Sprintf("%d importable files (%s, %s, ...)", len(files), files[0], files[1])
	}
}

// dists renders a list of unidentifiable metadata directories.
func dists(dirs []string) string {
	if len(dirs) == 1 {
		return dirs[0]
	}
	return fmt.Sprintf("%s and %d other directories", dirs[0], len(dirs)-1)
}
