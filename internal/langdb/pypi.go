package langdb

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// PyPI reads Python distributions out of site-packages and dist-packages.
//
// The metadata it reads is standardized: PEP 376 gives every installed
// distribution a .dist-info directory holding METADATA (the project name and
// version) and RECORD (every file the installation wrote). RECORD is the exact
// analog of dpkg's /var/lib/dpkg/info/<name>.list, and is what connects a CVE
// against "PyYAML" to the .py files that would have to be imported for it to
// matter.
//
// Not every installed distribution has all of it. Distributions installed by a
// distro package manager frequently ship an older .egg-info instead, and even a
// modern .dist-info may be missing RECORD -- pip's own dist-info as Homebrew
// installs it has METADATA but no RECORD. Every fallback below exists because a
// real installation was missing the thing above it.
type PyPI struct{}

// Format implements Reader.
func (*PyPI) Format() Format { return FormatPyPI }

// DirNames implements Reader. "dist-packages" is Debian's rename of
// site-packages for distro-installed modules; both appear in the same image.
func (*PyPI) DirNames() []string { return []string{"site-packages", "dist-packages"} }

// pyMetaDirs are the directory suffixes that mark installed-distribution
// metadata, newest convention first.
var pyMetaDirs = []string{".dist-info", ".egg-info"}

// Read implements Reader.
func (r *PyPI) Read(fsys target.RootFS, roots []string) (Result, error) {
	res := Result{Format: FormatPyPI, Roots: roots}

	for _, root := range roots {
		entries, err := fsys.ReadDir(root)
		if err != nil {
			return Result{}, fmt.Errorf("listing %s: %w", root, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !hasAnySuffix(name, pyMetaDirs) {
				continue
			}
			dir := path.Join(root, name)
			pkg, ok := r.readDist(fsys, root, dir, e.IsDir())
			if !ok {
				res.Unreadable = append(res.Unreadable, dir)
				continue
			}
			res.Packages = append(res.Packages, pkg)
		}
	}

	sortPackages(res.Packages)
	sort.Strings(res.Unreadable)
	return res, nil
}

// readDist parses one .dist-info or .egg-info.
//
// isDir distinguishes the two shapes setuptools produces: a directory holding
// PKG-INFO and friends, or a single flat file that is the PKG-INFO itself.
func (r *PyPI) readDist(fsys target.RootFS, root, dir string, isDir bool) (Package, bool) {
	pkg := Package{Format: FormatPyPI, Dir: dir, DB: root}

	var meta pyMeta
	if isDir {
		meta = readPyMetadata(fsys, dir)
	} else {
		meta = parsePyMetadata(fsys, dir)
	}
	rawName, version := meta.name, meta.version
	pkg.Requires, pkg.RequiresKnown = meta.requires, meta.known
	if rawName == "" || version == "" {
		// The directory name is the last resort, and it is a real one: PEP 427
		// requires it to be "{name}-{version}.dist-info", so a distribution
		// with no readable metadata file is still identifiable.
		n, v := parsePyDistDirName(path.Base(dir))
		if rawName == "" {
			rawName = n
		}
		if version == "" {
			version = v
		}
	}
	if rawName == "" {
		return Package{}, false
	}

	pkg.Name = NormalizePyPI(rawName)
	pkg.AltNames = []string{rawName}
	pkg.Version = version

	if isDir {
		pkg.Files, pkg.FilesKnown = readPyFiles(fsys, root, dir)
		pkg.ImportNames, pkg.ImportNamesKnown = readPyTopLevel(fsys, dir)
	}

	// Import names derived from the manifest are as authoritative as the
	// manifest: they are the directories the installation actually wrote.
	if len(pkg.ImportNames) == 0 && pkg.FilesKnown {
		pkg.ImportNames = importNamesFromFiles(root, pkg.Files)
		pkg.ImportNamesKnown = len(pkg.ImportNames) > 0
	}

	// Last resort. PyYAML imports as "yaml", so this is wrong often enough
	// that ImportNamesKnown stays false and the graph refuses to conclude
	// anything from failing to reach the distribution.
	if len(pkg.ImportNames) == 0 {
		pkg.ImportNames = []string{strings.ReplaceAll(pkg.Name, "-", "_")}
		pkg.ImportNamesKnown = false
	}

	// With no RECORD there is still a real file list to be had, by walking the
	// directories the import names name. It is not the manifest, so it cannot
	// support a "ships no code" conclusion, and FilesKnown says so.
	if !pkg.FilesKnown {
		pkg.Files = pyFilesFromImportNames(fsys, root, dir, pkg.ImportNames)
	}

	return pkg, true
}

// pyMeta is what one core-metadata file says.
type pyMeta struct {
	name     string
	version  string
	requires []Requirement

	// known reports that the header block was read, which is what separates
	// "declares no dependencies" from "did not say".
	known bool
}

// readPyMetadata reads a .dist-info/.egg-info directory's core metadata,
// trying the modern spelling before the setuptools one.
func readPyMetadata(fsys target.RootFS, dir string) pyMeta {
	for _, f := range []string{"METADATA", "PKG-INFO"} {
		if m := parsePyMetadata(fsys, path.Join(dir, f)); m.name != "" {
			return m
		}
	}
	return pyMeta{}
}

// parsePyMetadata reads the RFC822 header block of a core-metadata file.
//
// Only the headers are read: everything after the first blank line is the long
// description, which on a large distribution is the whole README and can
// contain lines that look exactly like headers.
func parsePyMetadata(fsys target.RootFS, file string) pyMeta {
	f, err := fsys.Open(file)
	if err != nil {
		return pyMeta{}
	}
	defer f.Close()

	var m pyMeta
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		m.known = true
		if line[0] == ' ' || line[0] == '\t' {
			continue // a folded continuation of the previous header
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			m.name = strings.TrimSpace(value)
		case "version":
			m.version = strings.TrimSpace(value)
		case "requires-dist", "requires":
			// "Requires" is the metadata 1.1 spelling, still emitted by old
			// egg-info directories, and its value is a bare project name.
			if r, ok := parseRequirement(value); ok {
				m.requires = append(m.requires, r)
			}
		}
	}
	return m
}

// pyReqName matches the project name at the head of a PEP 508 requirement.
var pyReqName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)

// parseRequirement reads one Requires-Dist value.
//
// PEP 508 permits a great deal more than this reads -- URLs, nested marker
// expressions, arbitrary whitespace -- but everything past the name and the
// presence of a marker is version-solving, and no version is being solved
// here. The question is only which installed distributions this one may
// import, so the grammar that matters is: a name, optionally extras and a
// specifier, optionally a semicolon and a marker.
func parseRequirement(value string) (Requirement, bool) {
	expr, marker, hasMarker := strings.Cut(value, ";")
	name := pyReqName.FindString(strings.TrimSpace(expr))
	if name == "" {
		return Requirement{}, false
	}
	return Requirement{
		Name:        NormalizePyPI(name),
		Conditional: hasMarker && strings.TrimSpace(marker) != "",
	}, true
}

// pyDirVersion matches the trailing "-<version>" of a dist-info directory
// name: the last hyphen-separated component that begins with a digit.
var pyDirVersion = regexp.MustCompile(`^(.+)-([0-9][^-]*)$`)

// pyBuildTag matches the interpreter and platform components setuptools
// appends to an egg-info directory name ("foo-1.0-py3.11.egg-info").
var pyBuildTag = regexp.MustCompile(`-(?:py|cp|pypy|ip|jy)[0-9][^-]*$`)

// parsePyDistDirName splits "pyyaml-6.0.3.dist-info" into its name and version.
func parsePyDistDirName(base string) (name, version string) {
	for _, suffix := range pyMetaDirs {
		base = strings.TrimSuffix(base, suffix)
	}
	base = pyBuildTag.ReplaceAllString(base, "")
	m := pyDirVersion.FindStringSubmatch(base)
	if m == nil {
		return base, ""
	}
	return m[1], m[2]
}

// readPyFiles reads the installation manifest.
//
// RECORD paths are relative to the directory the .dist-info sits in, and may
// climb out of it: console scripts are recorded as "../../../bin/name". Joining
// against the root and cleaning is exactly what the installer did in reverse.
func readPyFiles(fsys target.RootFS, root, dir string) (files []string, known bool) {
	if rows, ok := readPyRecord(fsys, path.Join(dir, "RECORD")); ok {
		return absolutize(root, rows), true
	}
	// setuptools' equivalent, whose paths are relative to the .egg-info itself.
	if rows, ok := readPyLines(fsys, path.Join(dir, "installed-files.txt")); ok {
		return absolutize(dir, rows), true
	}
	return nil, false
}

// readPyRecord parses RECORD, which is CSV of path,hash,size.
func readPyRecord(fsys target.RootFS, file string) ([]string, bool) {
	b, err := fsys.ReadFile(file)
	if err != nil {
		return nil, false
	}
	rd := csv.NewReader(bytes.NewReader(b))
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true

	var out []string
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed row is skipped rather than failing the distribution:
			// the rows already read are still true statements about what is
			// installed, and RECORD is not the only evidence in play.
			continue
		}
		if len(rec) > 0 && strings.TrimSpace(rec[0]) != "" {
			out = append(out, rec[0])
		}
	}
	return out, len(out) > 0
}

// readPyLines reads a plain one-path-per-line manifest.
func readPyLines(fsys target.RootFS, file string) ([]string, bool) {
	b, err := fsys.ReadFile(file)
	if err != nil {
		return nil, false
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, len(out) > 0
}

// readPyTopLevel reads top_level.txt, the distribution's own statement of what
// it is imported as. It is the only place PyYAML admits to installing "yaml".
func readPyTopLevel(fsys target.RootFS, dir string) ([]string, bool) {
	lines, ok := readPyLines(fsys, path.Join(dir, "top_level.txt"))
	if !ok {
		return nil, false
	}
	return dedupe(lines), true
}

// absolutize turns manifest-relative paths into tree-absolute ones.
func absolutize(base string, rels []string) []string {
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		out = append(out, path.Join(base, strings.TrimSpace(r)))
	}
	sort.Strings(out)
	return dedupe(out)
}

// pySkipTopLevel are the top-level entries in a file manifest that are
// packaging artifacts rather than importable code.
var pySkipTopLevel = map[string]bool{
	"__pycache__": true, "__editable__": true,
}

// importNamesFromFiles derives import names from the manifest, by taking the
// distinct first path component of every installed file that landed inside the
// site-packages directory.
//
// Files outside it -- console scripts in /usr/bin, data in a .data directory --
// are not importable and are skipped.
func importNamesFromFiles(root string, files []string) []string {
	var out []string
	for _, f := range files {
		rel, ok := strings.CutPrefix(f, root+"/")
		if !ok {
			continue
		}
		first, _, _ := strings.Cut(rel, "/")
		if first == "" || hasAnySuffix(first, pyMetaDirs) || strings.HasSuffix(first, ".data") {
			continue
		}
		// A top-level module is a file, not a directory: "six.py" imports as
		// "six", and the extension module "_yaml.cpython-314-x86_64-linux-gnu.so"
		// imports as "_yaml". Both are the name up to the first dot, and a
		// top-level package directory never contains one.
		if i := strings.Index(first, "."); i >= 0 {
			first = first[:i]
		}
		if first == "" || pySkipTopLevel[first] {
			continue
		}
		out = append(out, first)
	}
	out = dedupe(out)
	sort.Strings(out)
	return out
}

// pyFilesFromImportNames reconstructs a file list by walking the directories
// the import names point at, for a distribution whose manifest is missing.
func pyFilesFromImportNames(fsys target.RootFS, root, dir string, names []string) []string {
	out := walkFiles(fsys, dir, nil)
	for _, n := range names {
		p := path.Join(root, n)
		if fi, err := fsys.Stat(p); err == nil && fi.IsDir() {
			out = append(out, walkFiles(fsys, p, map[string]bool{"__pycache__": true})...)
			continue
		}
		for _, ext := range []string{".py", ".pyi"} {
			if fi, err := fsys.Stat(p + ext); err == nil && fi.Mode().IsRegular() {
				out = append(out, p+ext)
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

// pyNormalize matches the runs of separators PEP 503 collapses.
var pyNormalize = regexp.MustCompile(`[-_.]+`)

// NormalizePyPI applies PEP 503 name normalization, which is how OSV, PyPI and
// every purl consumer key a Python project: lowercase, with runs of "-", "_"
// and "." collapsed to a single "-". "PyYAML" and "ruamel.yaml.clib" become
// "pyyaml" and "ruamel-yaml-clib".
func NormalizePyPI(name string) string {
	return pyNormalize.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
