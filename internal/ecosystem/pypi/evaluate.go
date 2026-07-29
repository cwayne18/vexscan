package pypi

import (
	"fmt"
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
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
}

// evaluate decides one advisory against one installed distribution.
//
// The order of the cases is the order of increasing cost and decreasing
// certainty, the same order the OS plugin uses: whether the distribution
// exists, and whether it ships code. The third question -- whether that code
// is ever imported -- needs the import graph, and until it exists everything
// that survives the first two reports linked.
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

	f.Status = ecosystem.StatusLinked
	f.Method = MethodInventory
	f.Evidence = []ecosystem.Evidence{{
		Origin: MethodInventory,
		Detail: fmt.Sprintf("%s is installed in %s and ships %s",
			c.Name, strings.Join(c.Locations, ", "), modules(code)),
	}}
	f.Reachability = "installed: the distribution's code is on disk and importable (whether anything imports it is not asserted)"
	return f
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
