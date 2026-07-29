package pypi

import (
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
)

// Methods for the mined-module layer. All three only ever appear under
// --mine-advisories.
const (
	// MethodModuleAbsent: the module the advisory names is not among the files
	// this distribution installed, so this build does not contain it.
	MethodModuleAbsent = "py-module-absent"
	// MethodImportAbsent: the module is installed, but nothing the closure
	// reaches imports it.
	MethodImportAbsent = "py-import-absent"
	// MethodMined marks an observation from the mining layer that changed no
	// status -- including every case where validation rejected a hint.
	MethodMined = "llm-mined"
)

// moduleCheck is what the mined-module layer concluded about one advisory
// against one installed distribution.
type moduleCheck struct {
	// Validated are the mined module paths that survived every gate.
	Validated []string
	// Present are the validated modules this distribution actually installs,
	// and Files are the files they install them as.
	Present []string
	Files   []string
	// Why records what happened, for the evidence line. Always set.
	Why string
	// Usable reports whether the check may influence a status at all.
	Usable bool
}

// checkModules applies the hallucination containment rule to the mined module
// paths and then looks the survivors up in the distribution's file list.
//
// The rule is the same shape as ospkg.checkSymbols, adapted to the one way
// Python is harder. There are three gates, and a hint that fails any of them
// is inert -- recorded as an observation, never as a reason.
//
// The first gate is that a mined module must appear *literally* in the
// advisory's own text. The model was told to extract rather than infer, and
// this is where that instruction stops being trusted and starts being
// enforced.
//
// The second gate is that the module must belong to this distribution: its
// top-level name must be one the distribution is imported by. "yaml.cyaml" is
// checkable against PyYAML; "django.http" named in the same advisory is not,
// and its absence from PyYAML means only that PyYAML is not Django.
//
// The third gate is the awkward one, and it exists because Python writes a
// module path and an attribute path identically. "yaml.cyaml" is a module;
// "yaml.load" is a function reached through one. Nothing in the string says
// which, so the parent has to be a package this distribution installs -- the
// analog of the C namespace gate -- and the leaf must not also have been mined
// as a symbol, which is how a model that listed a function in both places
// tells us it is a function.
//
// What survives is a dotted name the advisory really used, under a package
// this distribution really ships. It is still possible for that to be an
// attribute the model put in the wrong list, which is why this whole layer is
// opt-in, why the absence conclusion additionally requires a file list read
// from the distribution's own RECORD, and why the README says plainly that a
// mined result is weaker than an inventoried one.
func (e evaluator) checkModules(adv *osv.Advisory, hints *llm.Hints, code []string) moduleCheck {
	if hints == nil {
		return moduleCheck{Why: "advisory mining was not run for this advisory"}
	}
	if len(hints.Modules) == 0 {
		note := hints.Note
		if note == "" {
			note = "the advisory text names no module"
		}
		return moduleCheck{Why: "no module could be mined: " + note}
	}

	text := advisoryText(adv)
	var literal []string
	for _, m := range hints.Modules {
		if strings.Contains(text, m) {
			literal = append(literal, m)
		}
	}
	if len(literal) == 0 {
		return moduleCheck{Why: "every mined module (" + strings.Join(hints.Modules, ", ") +
			") is absent from the advisory's own text, so it was invented rather than extracted"}
	}

	owned := map[string]bool{}
	for _, n := range e.st.importNames() {
		owned[langdb.NormalizePyPI(n)] = true
	}
	var mine []string
	for _, m := range literal {
		if owned[langdb.NormalizePyPI(topName(m))] {
			mine = append(mine, m)
		}
	}
	if len(mine) == 0 {
		return moduleCheck{Why: "no mined module (" + strings.Join(literal, ", ") +
			") is under a top-level name this distribution installs, so its absence is not evidence"}
	}

	symbols := map[string]bool{}
	for _, s := range hints.Symbols {
		symbols[s] = true
	}

	c := moduleCheck{}
	var rejected []string
	for _, m := range mine {
		parent := parentModule(m)
		if parent == "" {
			// A bare top-level name that gate two accepted is installed by
			// definition, so there is no absence to report and no package
			// above it to check.
			rejected = append(rejected, m+" (a top-level name, which this distribution installs by definition)")
			continue
		}
		if symbols[leafName(m)] {
			rejected = append(rejected, m+" (its last component was also mined as a function, so it is an attribute rather than a module)")
			continue
		}
		if len(moduleFiles(parent, code)) == 0 {
			rejected = append(rejected, m+" (this distribution installs no package "+parent+" for it to be missing from)")
			continue
		}
		c.Validated = append(c.Validated, m)
		if fs := moduleFiles(m, code); len(fs) > 0 {
			c.Present = append(c.Present, m)
			c.Files = append(c.Files, fs...)
		}
	}
	if len(c.Validated) == 0 {
		return moduleCheck{Why: "every mined module was rejected: " + strings.Join(rejected, "; ")}
	}

	c.Usable = true
	switch {
	case len(c.Present) == 0:
		c.Why = strings.Join(c.Validated, ", ") + " named by the advisory, installed by nothing " +
			e.st.name() + " ships"
	default:
		c.Why = strings.Join(c.Present, ", ") + " named by the advisory, installed by " + e.st.name()
	}
	return c
}

// moduleFiles finds the files a dotted module path is installed as.
//
// A module is a file, a package directory's __init__, or a compiled extension
// whose name carries an ABI tag that varies per build -- so the comparison is
// against the path with its extension and any __init__ removed, and the tag
// stripped from an extension module's base name.
func moduleFiles(dotted string, files []string) []string {
	want := "/" + strings.ReplaceAll(dotted, ".", "/")
	var out []string
	for _, f := range files {
		if strings.HasSuffix(modulePath(f), want) {
			out = append(out, f)
		}
	}
	return out
}

// modulePath reduces an installed file to the module path it provides.
func modulePath(file string) string {
	dir, base := path.Split(file)
	// _yaml.cpython-312-x86_64-linux-gnu.so -> _yaml, loader.py -> loader.
	if i := strings.Index(base, "."); i > 0 {
		base = base[:i]
	}
	if base == "__init__" {
		return strings.TrimSuffix(dir, "/")
	}
	return dir + base
}

// leafName is the last component of a dotted module path.
func leafName(dotted string) string {
	if i := strings.LastIndex(dotted, "."); i >= 0 {
		return dotted[i+1:]
	}
	return dotted
}

// parentModule is everything above the last component, or "" for a top-level
// name.
func parentModule(dotted string) string {
	if i := strings.LastIndex(dotted, "."); i > 0 {
		return dotted[:i]
	}
	return ""
}

// advisoryText is everything the advisory says, for the literal-substring gate.
func advisoryText(adv *osv.Advisory) string {
	if adv == nil {
		return ""
	}
	return adv.Summary + "\n" + adv.Details
}
