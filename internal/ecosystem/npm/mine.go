package npm

import (
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
)

// Methods for the mined-subpath layer. All three only ever appear under
// --mine-advisories.
const (
	// MethodModuleAbsent: the subpath the advisory names is not among the
	// files this package ships, so this build does not contain it.
	MethodModuleAbsent = "npm-module-absent"
	// MethodImportAbsent: the subpath is installed, but nothing the closure
	// reaches requires it.
	MethodImportAbsent = "npm-import-absent"
	// MethodMined marks an observation from the mining layer that changed no
	// status -- including every case where validation rejected a hint.
	MethodMined = "llm-mined"
)

// subpathCheck is what the mined-subpath layer concluded about one advisory
// against one installed package.
type subpathCheck struct {
	// Validated are the mined subpaths that survived every gate.
	Validated []string
	// Present are the validated subpaths this package actually ships, and
	// Files are the files they resolve to.
	Present []string
	Files   []string
	// Why records what happened, for the evidence line. Always set.
	Why string
	// Usable reports whether the check may influence a status at all.
	Usable bool
}

// checkSubpaths applies the hallucination containment rule to the mined module
// paths and then resolves the survivors inside the installed package.
//
// It is the same shape as pypi.checkModules and ospkg.checkSymbols, and it is
// the easiest of the three, for one reason: JavaScript writes a module with a
// slash and a property with a dot. "lodash/template" can only be a file;
// "lodash.template" can only be an expression, or the separate package of that
// name. Python's central hazard -- yaml.cyaml and yaml.load being written
// identically -- simply does not arise, so the gate that has to guess in the
// Python plugin is a syntax check here.
//
// Three gates remain, and a hint that fails any of them is inert: recorded as
// an observation, never as a reason.
//
// The first is that a mined subpath must appear *literally* in the advisory's
// own text. The model was told to extract rather than infer, and this is where
// that instruction stops being trusted and starts being enforced.
//
// The second is that it must name this package: its leading segments, scope
// included, must be the package's own name. A multi-package advisory naming
// "@babel/traverse/lib/path" is not checkable against @babel/types, and the
// absence of that file from @babel/types means only that they are different
// packages.
//
// The third is that what is left after the package name has to be a subpath at
// all. A bare package name is installed by definition, so there is no absence
// to report.
func (e evaluator) checkSubpaths(adv *osv.Advisory, hints *llm.Hints) subpathCheck {
	if hints == nil {
		return subpathCheck{Why: "advisory mining was not run for this advisory"}
	}
	if len(hints.Modules) == 0 {
		note := hints.Note
		if note == "" {
			note = "the advisory text names no module"
		}
		return subpathCheck{Why: "no module could be mined: " + note}
	}

	text := advisoryText(adv)
	var literal []string
	for _, m := range hints.Modules {
		if strings.Contains(text, m) {
			literal = append(literal, m)
		}
	}
	if len(literal) == 0 {
		return subpathCheck{Why: "every mined module (" + strings.Join(hints.Modules, ", ") +
			") is absent from the advisory's own text, so it was invented rather than extracted"}
	}

	owned := map[string]bool{}
	for _, n := range e.st.importNames() {
		owned[n] = true
	}

	c := subpathCheck{}
	var rejected []string
	for _, m := range literal {
		pkg, sub := splitSpecifier(strings.TrimPrefix(m, "./"))
		if !owned[pkg] {
			rejected = append(rejected, m+" (names "+quoteOr(pkg, "no package")+" rather than "+e.st.name()+")")
			continue
		}
		if sub == "" {
			// A bare package name that gate two accepted is installed by
			// definition, so there is no absence to report.
			rejected = append(rejected, m+" (the package name itself, which is installed by definition)")
			continue
		}
		c.Validated = append(c.Validated, m)
		if fs := e.subpathFiles(sub); len(fs) > 0 {
			c.Present = append(c.Present, m)
			c.Files = append(c.Files, fs...)
		}
	}
	if len(c.Validated) == 0 {
		return subpathCheck{Why: "every mined module was rejected: " + strings.Join(rejected, "; ")}
	}

	c.Usable = true
	if len(c.Present) == 0 {
		c.Why = strings.Join(c.Validated, ", ") + " named by the advisory, shipped by nothing " +
			e.st.name() + " installs"
	} else {
		c.Why = strings.Join(c.Present, ", ") + " named by the advisory, shipped by " + e.st.name()
	}
	return c
}

// subpathFiles resolves a subpath inside every installed instance of this
// package, through the same resolver the graph uses.
//
// Going through the resolver rather than matching strings against the file
// list is what makes "lodash/template" find template.js, and what makes a
// subpath the package's "exports" map redirects elsewhere find the file it
// actually redirects to.
func (e evaluator) subpathFiles(sub string) []string {
	var out []string
	for _, dir := range e.st.dirs() {
		out = append(out, e.node.resolveInPackage(dir, sub)...)
	}
	return dedupe(out)
}

// mined applies the mined-subpath layer, returning done when it decided the
// finding on its own.
//
// It changes nothing without --mine-advisories, and nothing when validation
// rejected every hint -- but it records what it did either way, because a
// reader has to be able to tell "the model found nothing usable" from "the
// model was never asked".
func (e evaluator) mined(f ecosystem.Finding, c ecosystem.Component, req ecosystem.Request) (ecosystem.Finding, bool) {
	m := e.checkSubpaths(req.Advisory, req.Hints)
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
		// The advisory's own module is not among the files this package
		// ships. A file list that could not be read cannot support that, and
		// neither can a run whose graph is already blocked, since whatever
		// blocked it may equally be loading a copy of the code.
		if e.st.filesKnown() && len(blockers) == 0 {
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Method = MethodModuleAbsent
			f.Evidence = append(f.Evidence, ecosystem.Evidence{
				Origin: MethodModuleAbsent,
				Detail: fmt.Sprintf("%s ships %d files and none of them provides %s",
					c.Name, len(e.st.files()), strings.Join(m.Validated, ", ")),
			})
			return f, true
		}
		f.Evidence = append(f.Evidence, blockers...)
		return f, false
	}

	// The vulnerable module is installed. Whether anything requires *it* is a
	// sharper question than whether anything requires the package, and it is
	// the one case where a package the closure reaches can still be concluded
	// on.
	if e.g == nil {
		return f, false
	}
	// Only interesting while the package itself is reached: if nothing
	// requires any of it, the ordinary closure row already says so, and saying
	// it again about one module adds nothing.
	if len(e.g.Classify(codeFiles(e.st.files())).Reachable) == 0 {
		return f, false
	}
	if files := e.g.Classify(m.Files); len(files.Module) > 0 && len(files.Reachable) == 0 {
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: MethodImportAbsent,
			Detail: fmt.Sprintf("nothing reachable from %s requires %s, though other modules of %s are reached",
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

// advisoryText is everything the advisory says, for the literal-substring gate.
func advisoryText(adv *osv.Advisory) string {
	if adv == nil {
		return ""
	}
	return adv.Summary + "\n" + adv.Details
}

// quoteOr renders a name, or a stand-in when there is none to render.
func quoteOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
