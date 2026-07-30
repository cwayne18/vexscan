// Package lockfile reads dependency lock files out of a source checkout.
//
// A lock file is the source-mode analog of an installed-package database, and
// the analogy holds in the way that matters: both are the build's own record of
// what it resolved, not an inference drawn from it. package-lock.json names
// exactly the versions `npm ci` will install, the same way /var/lib/dpkg/status
// names exactly what is unpacked.
//
// What a lock file cannot give is the thing image mode leans on hardest. There
// is no import graph here, because resolving a specifier needs an installed
// dependency tree, and materializing one means running the target's build --
// arbitrary code from the thing being audited. So repo mode answers a narrower
// question than image mode and is built to say so rather than to guess.
package lockfile

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// Format identifies which reader produced a result.
type Format string

const (
	FormatNPM  Format = "npm"
	FormatPyPI Format = "pypi"
)

// Package is one locked dependency.
type Package struct {
	// Name is the package name as OSV keys it: the PEP 503 normalized project
	// name for PyPI, the registry name verbatim for npm.
	Name string `json:"name"`

	// Version is the locked version, or "" when the file pins a range rather
	// than a point. An unpinned entry still proves the package is *present*,
	// which is the question repo mode is best at; it just cannot be asked
	// which advisories apply to it.
	Version string `json:"version,omitempty"`

	// Dev reports that the entry is reachable only through development
	// dependencies, and so is absent from a production install by
	// construction. This is a deterministic fact the lock file states, not a
	// heuristic: `npm ci --omit=dev` will not write it to disk.
	Dev bool `json:"dev,omitempty"`
}

// Result is one lock file's contents.
type Result struct {
	Format Format `json:"format"`

	// File is the tree-absolute path this was read from, for evidence.
	File string `json:"file"`

	// DevKnown reports whether this file partitions development dependencies
	// from runtime ones at all.
	//
	// It is false for requirements.txt, which carries no such partition. The
	// distinction has to travel with the data: "Dev is false" would otherwise
	// mean both "the file says this ships in production" and "the file does
	// not say", and only the first can support a not_in_execute_path.
	DevKnown bool `json:"dev_known"`

	Packages []Package `json:"packages,omitempty"`
}

// Reader parses one family of lock file.
type Reader interface {
	Format() Format

	// Read parses every lock file of this format directly under dir.
	//
	// A directory holding none of them is not an error and yields nothing. A
	// lock file that exists and will not parse *is* an error, for the reason
	// pkgdb.Read has the same rule: an empty inventory renders as "this repo
	// depends on nothing vulnerable", which is the worst way for this tool to
	// be wrong.
	Read(fsys target.RootFS, dir string) ([]Result, error)
}

// Readers lists every lock file reader.
func Readers() []Reader { return []Reader{&NPM{}, &PyPI{}} }

// Read parses the lock files of one format under dir.
func Read(fsys target.RootFS, dir string, format Format) ([]Result, error) {
	for _, r := range Readers() {
		if r.Format() != format {
			continue
		}
		return r.Read(fsys, dir)
	}
	return nil, fmt.Errorf("no lock file reader for %q", format)
}

// Packages flattens several results, dropping duplicate coordinates.
//
// Two lock files in one directory naming the same package at the same version
// is ordinary -- a Pipfile.lock beside a requirements.txt -- and reporting it
// twice would double every finding about it. Two files disagreeing about the
// *version* is not deduplicated, because that is a real thing to have found.
func Packages(results []Result) []Package {
	at := map[string]int{}
	var out []Package
	for _, res := range results {
		for _, p := range res.Packages {
			key := p.Name + "\x00" + p.Version
			i, ok := at[key]
			if !ok {
				at[key] = len(out)
				out = append(out, p)
				continue
			}
			// One coordinate can appear many times -- once per place it is
			// installed in the tree -- and the copies need not agree about Dev.
			// A package that is a runtime dependency anywhere ships in
			// production, so the runtime answer wins. Taking whichever copy the
			// map happened to yield first would make the output depend on Go's
			// randomized iteration order.
			out[i].Dev = out[i].Dev && p.Dev
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// DevOnly reports whether the lock files declare this package as reachable
// only through development dependencies.
//
// Two things have to hold, and both are folded in here rather than left to the
// caller. Every result that names the package must mark it dev: a package that
// is dev-only in one lock file and a runtime dependency in another ships in
// production, so the runtime answer wins. And every such result must partition
// dev at all: a requirements.txt says nothing about the distinction, and "did
// not say" must never be read as "said no". A file with DevKnown false
// therefore forces the answer to false, which is why there is no second return
// value -- a true here already means the partition was declared.
func DevOnly(results []Result, name string) bool {
	found := false
	for _, res := range results {
		for _, p := range res.Packages {
			if p.Name != name {
				continue
			}
			found = true
			if !res.DevKnown || !p.Dev {
				return false
			}
		}
	}
	return found
}

// FilesFor returns the lock files that name this package, in the order they
// were read.
//
// Evidence has to name these rather than every file the scan opened. A repo
// with four requirements files reads them all, but "requirements_test.txt
// declares certifi" is a claim about that file, and it is false unless the file
// says so.
func FilesFor(results []Result, name string) []string {
	var out []string
	for _, res := range results {
		for _, p := range res.Packages {
			if p.Name == name {
				out = append(out, res.File)
				break
			}
		}
	}
	return out
}

// find returns the lock files under dir matching any of names, in the order
// given.
func find(fsys target.RootFS, dir string, names []string) []string {
	var out []string
	for _, n := range names {
		f := path.Join(dir, n)
		if info, err := fsys.Stat(f); err == nil && !info.IsDir() {
			out = append(out, f)
		}
	}
	return out
}

// findGlob returns the files under dir whose names match prefix...suffix.
func findGlob(fsys target.RootFS, dir, prefix, suffix string) []string {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, suffix) {
			continue
		}
		out = append(out, path.Join(dir, n))
	}
	sort.Strings(out)
	return out
}
