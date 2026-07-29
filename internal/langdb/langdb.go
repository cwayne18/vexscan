// Package langdb reads the installed-package layouts of the two language
// ecosystems that ship inside container images: Python's site-packages and
// Node's node_modules.
//
// It is the language-ecosystem counterpart of internal/pkgdb, and answers the
// same two questions: which distributions are installed at which versions, and
// which files each one owns. It answers a third that pkgdb does not need --
// which names the code imports itself by -- because a Python distribution's
// project name and its import name are routinely different (PyYAML installs
// "yaml"), and the import name is what an import graph can be rooted at.
//
// It differs from pkgdb in one structural way. A dpkg or rpm database is a
// single file at a known path, so pkgdb's Reader can Detect by stat'ing it.
// site-packages and node_modules can be anywhere and there can be many of
// them, so finding them means walking the tree. Scan therefore does one walk
// for every format at once, rather than giving each Reader its own Detect.
//
// Nothing here talks to OSV or to the network. Readers parse a filesystem and
// return what they found, or an error -- never a partial answer.
package langdb

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// Format identifies a language ecosystem's installed-package layout.
type Format string

const (
	FormatPyPI Format = "pypi"
	FormatNPM  Format = "npm"
)

// Package is one installed distribution.
type Package struct {
	Format Format `json:"format"`

	// Name is the package name *as OSV keys it*: the PEP 503 normalized
	// project name for PyPI, the manifest name verbatim (scope included) for
	// npm.
	Name string `json:"name"`

	// AltNames are other names worth querying OSV under -- for PyPI, the
	// un-normalized project name as the metadata spells it. Same reasoning as
	// pkgdb.Package.OSVNames: a name that matches nothing costs one entry in a
	// batch query, while missing the right one reports a vulnerable package as
	// clean.
	AltNames []string `json:"alt_names,omitempty"`

	Version string `json:"version,omitempty"`

	// ImportNames are the top-level names the code is imported by: "yaml" and
	// "_yaml" for PyYAML, and just the package name for npm.
	ImportNames []string `json:"import_names,omitempty"`

	// ImportNamesKnown reports whether ImportNames came from the
	// distribution's own metadata rather than being guessed from its project
	// name.
	//
	// It exists because the two failure directions are not symmetric. A guessed
	// import name that is wrong makes the distribution unreachable in the
	// import graph, and an unreachable distribution reads as
	// vulnerable_code_not_in_execute_path -- a false clean. A consumer must be
	// able to refuse that conclusion, so the provenance travels with the data.
	ImportNamesKnown bool `json:"import_names_known"`

	// Files are the tree-absolute paths the distribution installs.
	Files []string `json:"files,omitempty"`

	// FilesKnown reports whether Files came from the distribution's own
	// manifest (RECORD, installed-files.txt) rather than being reconstructed
	// by walking its directories.
	//
	// Same asymmetry as ImportNamesKnown: an empty file list means "this
	// distribution ships no code", which is a not_present conclusion. Only a
	// manifest can support it.
	FilesKnown bool `json:"files_known"`

	// Dir is the tree-absolute directory the distribution's metadata lives in:
	// the .dist-info/.egg-info directory, or the package directory under
	// node_modules. The import resolver needs it to know which nested
	// node_modules an instance sees.
	Dir string `json:"dir,omitempty"`

	// DB is the site-packages or node_modules directory this came from, for
	// evidence and error messages.
	DB string `json:"db,omitempty"`
}

// OSVNames returns the names to query OSV with, likeliest first.
func (p Package) OSVNames() []string {
	out := make([]string, 0, 1+len(p.AltNames))
	out = append(out, p.Name)
	for _, n := range p.AltNames {
		if n != p.Name {
			out = append(out, n)
		}
	}
	return out
}

// Result is what one reader found.
type Result struct {
	Format Format `json:"format"`

	// Roots are the site-packages or node_modules directories that were found.
	Roots []string `json:"roots"`

	Packages []Package `json:"packages"`

	// Unreadable are manifests that were found and could not be parsed.
	//
	// Unlike pkgdb, this is not a fatal error. A dpkg status file is one file
	// describing every package, so failing to parse it means knowing nothing;
	// here each distribution carries its own manifest, and a node_modules tree
	// routinely contains deliberately malformed fixtures. It is never silent
	// either: a distribution whose manifest could not be read is one whose
	// absence must not be asserted, so the plugin turns this into a taint.
	Unreadable []string `json:"unreadable,omitempty"`
}

// Reader parses one language's installed-package layout out of the roots that
// Scan found for it.
type Reader interface {
	// Format names the ecosystem this reader understands.
	Format() Format
	// DirNames are the directory base names that hold this format's installed
	// packages, so one tree walk can find the roots for every reader.
	DirNames() []string
	// Read parses every root. A root that exists and cannot be listed is an
	// error; an individual manifest that will not parse is reported through
	// Result.Unreadable.
	Read(fsys target.RootFS, roots []string) (Result, error)
}

// Readers returns every backend, in a stable order.
func Readers() []Reader {
	return []Reader{&PyPI{}, &NPM{}}
}

// skipDirs are kernel filesystems. An extracted image should not contain them,
// but a tar built from a running container does, and walking them is pure cost.
var skipDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true,
}

// FindRoots walks the tree once and returns, per format, the directories that
// hold that format's installed packages.
//
// A matched directory is not descended into. Nesting is real -- npm stores a
// conflicting version in a node_modules inside a package -- but it is the npm
// reader that understands what the nesting means, and having the generic walk
// report inner directories as top-level roots would flatten exactly the
// structure the resolver needs.
func FindRoots(fsys target.RootFS) (map[Format][]string, error) {
	want := map[string]Format{}
	for _, r := range Readers() {
		for _, name := range r.DirNames() {
			want[name] = r.Format()
		}
	}

	out := map[Format][]string{}
	err := fsys.Walk("/", func(name string, d fs.DirEntry) error {
		if !d.IsDir() {
			return nil
		}
		if skipDirs[name] {
			return fs.SkipDir
		}
		format, ok := want[path.Base(name)]
		if !ok {
			return nil
		}
		out[format] = append(out[format], name)
		return fs.SkipDir
	})
	if err != nil {
		return nil, fmt.Errorf("walking filesystem for installed packages: %w", err)
	}
	for _, roots := range out {
		sort.Strings(roots)
	}
	return out, nil
}

// Scan finds every root and runs the reader that owns it.
//
// A format with no roots produces no Result at all, which is how a plugin
// learns it does not apply to this image.
func Scan(fsys target.RootFS) ([]Result, error) {
	roots, err := FindRoots(fsys)
	if err != nil {
		return nil, err
	}

	var out []Result
	for _, r := range Readers() {
		found := roots[r.Format()]
		if len(found) == 0 {
			continue
		}
		res, err := r.Read(fsys, found)
		if err != nil {
			return nil, fmt.Errorf("%s packages: %w", r.Format(), err)
		}
		out = append(out, res)
	}
	return out, nil
}

// sortPackages orders packages by name, then version, then directory, so that
// output is stable regardless of the order a tree walk happened to produce.
// The directory tie-break matters for npm, where the same name and version can
// legitimately be installed at two nesting levels.
func sortPackages(pkgs []Package) {
	sort.SliceStable(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Dir < b.Dir
	})
}

// walkFiles lists every regular file under dir, skipping the subdirectories
// named in stop. It is how a file list is reconstructed for a distribution
// whose manifest is missing.
func walkFiles(fsys target.RootFS, dir string, stop map[string]bool) []string {
	var out []string
	_ = fsys.Walk(dir, func(name string, d fs.DirEntry) error {
		if d.IsDir() {
			if name != dir && stop[path.Base(name)] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			out = append(out, name)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// dedupe returns the input with empties and repeats removed, order preserved.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
