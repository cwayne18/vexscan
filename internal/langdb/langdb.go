// Package langdb reads the installed-package layouts of the language
// ecosystems that ship inside container images: Python's site-packages, Node's
// node_modules, and Java's jar, war and ear archives.
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
// site-packages, node_modules and jars can be anywhere and there can be many of
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
	FormatPyPI  Format = "pypi"
	FormatNPM   Format = "npm"
	FormatMaven Format = "maven"
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

	// Requires are the packages this one declares it may load, named the way
	// Name is. It bounds what a computed import inside this package could
	// reach, which is the only thing that makes a dynamic-import taint able to
	// block anything narrower than the whole image.
	//
	// Only the PyPI reader fills this in. npm's resolver reads dependencies
	// from package.json itself, because for npm a name is not enough: which
	// copy of "tar" a file sees depends on the directory it is required from,
	// and that is precisely what nested node_modules means. Python's sys.path
	// is a single global search order, so a name resolves the same everywhere
	// and can be indexed once.
	Requires []Requirement `json:"requires,omitempty"`

	// RequiresKnown reports whether Requires came from readable metadata.
	//
	// Same asymmetry as FilesKnown. An empty Requires means "this package
	// depends on nothing", which narrows a taint's scope to the package
	// itself; only metadata that was actually read can support that.
	RequiresKnown bool `json:"requires_known"`

	// CoordsKnown reports whether Name came from metadata the build wrote
	// rather than from the file name or the code's own layout.
	//
	// Only the Maven reader ever sets it false. A PyPI or npm name is read from
	// a manifest that the package manager requires; a jar frequently carries no
	// statement of its own groupId at all, and the name is then reconstructed
	// from the file name and the classes' package prefixes.
	//
	// Same asymmetry as the rest of this family, one level up. A guessed
	// coordinate is still worth querying OSV with -- a name that matches nothing
	// costs one entry in a batch. It may not support a negative conclusion:
	// asserting that an artifact does not contain some class, when the artifact
	// is only what this reader thinks the jar is, stacks a guess on a guess.
	CoordsKnown bool `json:"coords_known,omitempty"`
}

// Requirement is one declared dependency.
type Requirement struct {
	Name string `json:"name"`

	// Conditional reports whether the declaration carries an environment
	// marker -- an extra, a Python version bound, a platform test.
	//
	// It exists to separate two very different kinds of absence. An
	// unconditional dependency that is not installed means the environment is
	// not what the metadata describes, and nothing about it can be trusted to
	// bound anything. A conditional one that is not installed is the marker
	// working as designed: an unselected extra is *expected* to be missing,
	// and treating that as an unknown would push nearly every Python image
	// into a global taint.
	Conditional bool `json:"conditional,omitempty"`
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

	// Roots are what the tree walk found for this format: the site-packages or
	// node_modules directories, or, for a format whose packages are files, the
	// archive paths themselves.
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

	// Unidentified are archives that opened cleanly and declare no coordinates
	// anywhere -- no META-INF/maven, no usable manifest, no conventional file
	// name.
	//
	// It is Unreadable's sibling for the Maven reader, and it exists because the
	// two are the same failure wearing different clothes: something is installed
	// here and this scan cannot say what. A plugin asked whether an artifact is
	// present must not answer no while one of these could be the artifact asked
	// about -- but each entry keeps the partial identity that could still be
	// read, so the test is "could this archive be that artifact" rather than a
	// blanket refusal.
	Unidentified []UnidentifiedArchive `json:"unidentified,omitempty"`

	// Platform are archives recognized as the Java runtime itself -- rt.jar and
	// the other JRE/JDK internal jars -- named by convention rather than by any
	// coordinate. They carry no META-INF/maven and would otherwise land in
	// Unidentified and block every absence conclusion on a JDK base image, yet
	// they are not queryable Maven artifacts and cannot be the third-party
	// artifact a scan is asked about. Recorded for transparency, never blocking.
	Platform []string `json:"platform,omitempty"`
}

// UnidentifiedArchive is a jar, war or ear that opened cleanly but declares no
// coordinates. It keeps whatever partial identity could still be read off it so
// an absence test can ask whether this particular archive could be the artifact
// in question, rather than treating every unnamed jar as a blanket blocker.
type UnidentifiedArchive struct {
	// Path is how the archive is addressed, using the JVM's nested spelling for
	// an embedded one: "/app/app.jar!/BOOT-INF/lib/mystery.jar".
	Path string `json:"path"`

	// FileArtifact is the artifactId parsed from the file name via the Maven
	// <artifact>-<version> convention, or "" when the name does not follow it.
	// A name that names a different artifact is positive evidence the archive is
	// not the one being asked about.
	FileArtifact string `json:"file_artifact,omitempty"`

	// ClassPackages are the distinct package directories the archive's compiled
	// classes live under, slash-separated ("org/springframework/aop"). They say
	// what an archive could contain even when its coordinates could not be read:
	// an archive that ships no class under an artifact's group path cannot be
	// that artifact.
	ClassPackages []string `json:"class_packages,omitempty"`

	// HasClasses reports whether the archive ships any compiled class. Its
	// central directory was read in full, so false means genuinely codeless --
	// a resource, sources or javadoc jar -- rather than unread.
	HasClasses bool `json:"has_classes"`
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

// FileReader is a Reader whose installed packages are individual files rather
// than directories.
//
// Java is the reason it exists. A jar is a single self-describing file that can
// sit anywhere -- a servlet container's lib directory, /usr/share/java, an
// application's working directory -- so there is no directory base name to key
// on the way site-packages and node_modules are keyed on. The roots handed to
// Read are then the archive paths themselves.
type FileReader interface {
	Reader
	// FileSuffixes are the file extensions that identify this format's
	// packages, lowercase and including the dot.
	FileSuffixes() []string
}

// Readers returns every backend, in a stable order.
func Readers() []Reader {
	return []Reader{&PyPI{}, &NPM{}, &Maven{}}
}

// FindRoots walks the tree once and returns, per format, what holds that
// format's installed packages: a directory for most, an archive file for a
// FileReader.
//
// A matched directory is not descended into. Nesting is real -- npm stores a
// conflicting version in a node_modules inside a package -- but it is the npm
// reader that understands what the nesting means, and having the generic walk
// report inner directories as top-level roots would flatten exactly the
// structure the resolver needs.
func FindRoots(fsys target.RootFS) (map[Format][]string, error) {
	want := map[string]Format{}
	wantSuffix := map[string]Format{}
	for _, r := range Readers() {
		for _, name := range r.DirNames() {
			want[name] = r.Format()
		}
		if fr, ok := r.(FileReader); ok {
			for _, suffix := range fr.FileSuffixes() {
				wantSuffix[suffix] = r.Format()
			}
		}
	}

	out := map[Format][]string{}
	err := fsys.Walk("/", func(name string, d fs.DirEntry) error {
		if !d.IsDir() {
			if !d.Type().IsRegular() {
				// A symlink to a jar is the same jar under a second name, and
				// counting it twice inventories one artifact as two.
				return nil
			}
			if format, ok := matchSuffix(wantSuffix, name); ok {
				out[format] = append(out[format], name)
			}
			return nil
		}
		if target.IsKernelFS(name) {
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

// matchSuffix reports which format, if any, claims a file by its extension.
// The comparison is case-insensitive because Windows-built archives and
// hand-renamed ones both show up as .JAR.
func matchSuffix(want map[string]Format, name string) (Format, bool) {
	base := strings.ToLower(path.Base(name))
	for suffix, format := range want {
		if len(base) > len(suffix) && strings.HasSuffix(base, suffix) {
			return format, true
		}
	}
	return "", false
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
