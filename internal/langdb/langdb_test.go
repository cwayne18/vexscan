package langdb

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// writeTree builds a throwaway rootfs from tree-absolute path to content.
func writeTree(t *testing.T, files map[string]string) target.RootFS {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return target.NewDirFS(root)
}

func TestFindRootsFindsEveryLayout(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/usr/local/lib/python3.12/site-packages/six.py":    "",
		"/usr/lib/python3/dist-packages/yaml/__init__.py":   "",
		"/app/node_modules/lodash/package.json":             "{}",
		"/usr/lib/node_modules/npm/package.json":            "{}",
		"/proc/1/root/usr/lib/python3.12/site-packages/x":   "",
		"/opt/thing/lib/python3.9/site-packages/pkg/mod.py": "",
	})

	roots, err := FindRoots(fsys)
	if err != nil {
		t.Fatal(err)
	}

	want := map[Format][]string{
		FormatPyPI: {
			"/opt/thing/lib/python3.9/site-packages",
			"/usr/lib/python3/dist-packages",
			"/usr/local/lib/python3.12/site-packages",
		},
		FormatNPM: {"/app/node_modules", "/usr/lib/node_modules"},
	}
	if !reflect.DeepEqual(roots, want) {
		t.Errorf("FindRoots =\n%v\nwant\n%v", roots, want)
	}
}

// A nested node_modules is not a root of its own. It is real structure -- it
// is how npm installs two versions of one package -- and reporting it here
// would flatten exactly what the resolver needs, so the npm reader walks it
// instead.
func TestFindRootsDoesNotDescendIntoAMatch(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/app/node_modules/a/package.json":                  `{"name":"a"}`,
		"/app/node_modules/a/node_modules/b/package.json":   `{"name":"b"}`,
		"/app/node_modules/a/node_modules/b/node_modules/x": "",
	})

	roots, err := FindRoots(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := roots[FormatNPM], []string{"/app/node_modules"}; !reflect.DeepEqual(got, want) {
		t.Errorf("npm roots = %v, want %v", got, want)
	}
}

func TestScanIgnoresATreeWithNeitherLayout(t *testing.T) {
	fsys := writeTree(t, map[string]string{"/etc/os-release": "ID=debian\n"})
	res, err := Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Errorf("Scan = %v, want no results", res)
	}
}

// ---------------------------------------------------------------- PyPI

const pyyamlRecord = `_yaml/__init__.py,sha256=aaa,1402
_yaml/__pycache__/__init__.cpython-312.pyc,,
yaml/__init__.py,sha256=bbb,12256
yaml/_yaml.cpython-312-x86_64-linux-gnu.so,sha256=ccc,2000
pyyaml-6.0.3.dist-info/METADATA,sha256=ddd,2351
pyyaml-6.0.3.dist-info/RECORD,,
../../../bin/yaml-tool,sha256=eee,200
`

func pyyamlTree() map[string]string {
	const sp = "/usr/lib/python3.12/site-packages"
	return map[string]string{
		sp + "/pyyaml-6.0.3.dist-info/METADATA":      "Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0.3\n\nName: NotThis\n",
		sp + "/pyyaml-6.0.3.dist-info/RECORD":        pyyamlRecord,
		sp + "/pyyaml-6.0.3.dist-info/top_level.txt": "_yaml\nyaml\n",
	}
}

func TestPyPIReadsADistInfo(t *testing.T) {
	res, err := (&PyPI{}).Read(writeTree(t, pyyamlTree()), []string{"/usr/lib/python3.12/site-packages"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(res.Packages), res.Packages)
	}
	p := res.Packages[0]

	// The name OSV keys on is normalized; the name the metadata spells is kept
	// so a query under either finds the record.
	if p.Name != "pyyaml" || p.Version != "6.0.3" {
		t.Errorf("name/version = %q/%q, want pyyaml/6.0.3", p.Name, p.Version)
	}
	if want := []string{"pyyaml", "PyYAML"}; !reflect.DeepEqual(p.OSVNames(), want) {
		t.Errorf("OSVNames = %v, want %v", p.OSVNames(), want)
	}

	// The whole reason top_level.txt is read: nothing about "pyyaml" says
	// "yaml".
	if want := []string{"_yaml", "yaml"}; !reflect.DeepEqual(p.ImportNames, want) {
		t.Errorf("ImportNames = %v, want %v", p.ImportNames, want)
	}
	if !p.ImportNamesKnown || !p.FilesKnown {
		t.Errorf("Known flags = %v/%v, want true/true", p.ImportNamesKnown, p.FilesKnown)
	}

	// RECORD paths are relative to site-packages and may climb out of it.
	if !has(p.Files, "/usr/lib/python3.12/site-packages/yaml/__init__.py") {
		t.Errorf("Files is missing the package source: %v", p.Files)
	}
	if !has(p.Files, "/usr/bin/yaml-tool") {
		t.Errorf("Files is missing the console script: %v", p.Files)
	}
}

// The long description begins after the first blank line and on a large
// distribution is the whole README, which routinely contains lines that parse
// as headers.
func TestPyPIStopsAtTheEndOfTheMetadataHeaders(t *testing.T) {
	res, _ := (&PyPI{}).Read(writeTree(t, pyyamlTree()), []string{"/usr/lib/python3.12/site-packages"})
	if got := res.Packages[0].Name; got != "pyyaml" {
		t.Errorf("name = %q, want pyyaml -- a header-shaped line in the body was read", got)
	}
}

// pip's own dist-info as Homebrew installs it has METADATA and no RECORD.
func TestPyPIWithoutARecordReportsThatFilesAreReconstructed(t *testing.T) {
	const sp = "/usr/lib/python3.12/site-packages"
	fsys := writeTree(t, map[string]string{
		sp + "/pip-26.1.dist-info/METADATA":      "Name: pip\nVersion: 26.1\n",
		sp + "/pip-26.1.dist-info/top_level.txt": "pip\n",
		sp + "/pip/__init__.py":                  "",
		sp + "/pip/_internal/cli.py":             "",
		sp + "/pip/__pycache__/__init__.pyc":     "",
	})

	res, err := (&PyPI{}).Read(fsys, []string{sp})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Packages[0]

	// FilesKnown is the whole point: an empty or partial file list means
	// "ships no code", which is a not_present conclusion, and only a manifest
	// may support that.
	if p.FilesKnown {
		t.Error("FilesKnown = true with no RECORD; a reconstructed list must not pass as a manifest")
	}
	if !p.ImportNamesKnown {
		t.Error("ImportNamesKnown = false, but top_level.txt named them")
	}
	if !has(p.Files, sp+"/pip/_internal/cli.py") {
		t.Errorf("reconstructed Files missed the package tree: %v", p.Files)
	}
	if has(p.Files, sp+"/pip/__pycache__/__init__.pyc") {
		t.Errorf("reconstructed Files should skip __pycache__: %v", p.Files)
	}
}

func TestPyPIDerivesImportNamesFromTheManifest(t *testing.T) {
	const sp = "/usr/lib/python3.12/site-packages"
	fsys := writeTree(t, map[string]string{
		sp + "/pyyaml-6.0.3.dist-info/METADATA": "Name: PyYAML\nVersion: 6.0.3\n",
		sp + "/pyyaml-6.0.3.dist-info/RECORD":   pyyamlRecord,
	})

	res, _ := (&PyPI{}).Read(fsys, []string{sp})
	p := res.Packages[0]
	if want := []string{"_yaml", "yaml"}; !reflect.DeepEqual(p.ImportNames, want) {
		t.Errorf("ImportNames = %v, want %v", p.ImportNames, want)
	}
	if !p.ImportNamesKnown {
		t.Error("ImportNamesKnown = false; names taken from RECORD are as authoritative as RECORD")
	}
}

// A top-level module or extension module is a file, and its import name is the
// part before the first dot.
func TestPyPIImportNamesFromFilesStripExtensions(t *testing.T) {
	got := importNamesFromFiles("/sp", []string{
		"/sp/six.py",
		"/sp/_cffi_backend.cpython-312-x86_64-linux-gnu.so",
		"/sp/zope/interface/__init__.py",
		"/sp/six-1.16.0.dist-info/RECORD",
		"/sp/setuptools-1.0.data/scripts/x",
		"/sp/__pycache__/six.pyc",
		"/usr/bin/console-script",
	})
	want := []string{"_cffi_backend", "six", "zope"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("importNamesFromFiles = %v, want %v", got, want)
	}
}

// With nothing to read, the name is all there is, and "pyyaml" is not "yaml".
// The guess is made anyway -- some answer beats none -- but it is flagged, so
// that failing to reach the distribution cannot be reported as unreachable.
func TestPyPIGuessedImportNamesAreFlagged(t *testing.T) {
	const sp = "/usr/lib/python3.12/site-packages"
	fsys := writeTree(t, map[string]string{
		sp + "/typing_extensions-4.9.0.dist-info/INSTALLER": "pip\n",
	})

	res, _ := (&PyPI{}).Read(fsys, []string{sp})
	if len(res.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(res.Packages))
	}
	p := res.Packages[0]
	if p.Name != "typing-extensions" || p.Version != "4.9.0" {
		t.Errorf("name/version = %q/%q, want typing-extensions/4.9.0 from the directory name", p.Name, p.Version)
	}
	if want := []string{"typing_extensions"}; !reflect.DeepEqual(p.ImportNames, want) {
		t.Errorf("ImportNames = %v, want %v", p.ImportNames, want)
	}
	if p.ImportNamesKnown {
		t.Error("ImportNamesKnown = true for a name guessed from the project name")
	}
}

func TestPyPIReadsAnEggInfo(t *testing.T) {
	const sp = "/usr/lib/python3/dist-packages"
	fsys := writeTree(t, map[string]string{
		sp + "/chardet-5.1.0.egg-info/PKG-INFO":            "Name: chardet\nVersion: 5.1.0\n",
		sp + "/chardet-5.1.0.egg-info/top_level.txt":       "chardet\n",
		sp + "/chardet-5.1.0.egg-info/installed-files.txt": "../chardet/__init__.py\n../chardet/enums.py\n",
	})

	res, err := (&PyPI{}).Read(fsys, []string{sp})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Packages[0]
	if p.Name != "chardet" || p.Version != "5.1.0" {
		t.Errorf("name/version = %q/%q", p.Name, p.Version)
	}
	// installed-files.txt is relative to the .egg-info, not to site-packages.
	if !p.FilesKnown || !has(p.Files, sp+"/chardet/enums.py") {
		t.Errorf("Files = %v (known %v)", p.Files, p.FilesKnown)
	}
}

func TestPyPIUnnameableDistIsReportedNotDropped(t *testing.T) {
	const sp = "/usr/lib/python3.12/site-packages"
	fsys := writeTree(t, map[string]string{sp + "/.dist-info/INSTALLER": "pip\n"})

	res, err := (&PyPI{}).Read(fsys, []string{sp})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 0 {
		t.Errorf("got %d packages, want 0", len(res.Packages))
	}
	if want := []string{sp + "/.dist-info"}; !reflect.DeepEqual(res.Unreadable, want) {
		t.Errorf("Unreadable = %v, want %v", res.Unreadable, want)
	}
}

func TestParsePyDistDirName(t *testing.T) {
	for _, tc := range []struct{ in, name, version string }{
		{"pyyaml-6.0.3.dist-info", "pyyaml", "6.0.3"},
		{"zope.interface-5.4.0.dist-info", "zope.interface", "5.4.0"},
		{"typing_extensions-4.9.0.dist-info", "typing_extensions", "4.9.0"},
		{"chardet-5.1.0-py3.11.egg-info", "chardet", "5.1.0"},
		{"setuptools.egg-info", "setuptools", ""},
		{"ruamel.yaml.clib-0.2.8.dist-info", "ruamel.yaml.clib", "0.2.8"},
	} {
		name, version := parsePyDistDirName(tc.in)
		if name != tc.name || version != tc.version {
			t.Errorf("parsePyDistDirName(%q) = %q/%q, want %q/%q", tc.in, name, version, tc.name, tc.version)
		}
	}
}

func TestNormalizePyPI(t *testing.T) {
	for in, want := range map[string]string{
		"PyYAML":            "pyyaml",
		"zope.interface":    "zope-interface",
		"typing_extensions": "typing-extensions",
		"ruamel.yaml.clib":  "ruamel-yaml-clib",
		"  Flask  ":         "flask",
		"a--_.-b":           "a-b",
	} {
		if got := NormalizePyPI(in); got != want {
			t.Errorf("NormalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

// ----------------------------------------------------------------- npm

func TestNPMReadsNestedAndScopedPackages(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/app/node_modules/lodash/package.json":                      `{"name":"lodash","version":"4.17.21"}`,
		"/app/node_modules/lodash/index.js":                          "",
		"/app/node_modules/express/package.json":                     `{"name":"express","version":"4.18.2"}`,
		"/app/node_modules/express/node_modules/lodash/package.json": `{"name":"lodash","version":"3.10.1"}`,
		"/app/node_modules/@babel/core/package.json":                 `{"name":"@babel/core","version":"7.23.0"}`,
		"/app/node_modules/.bin/express":                             "",
	})

	res, err := (&NPM{}).Read(fsys, []string{"/app/node_modules"})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, p := range res.Packages {
		got = append(got, p.Name+"@"+p.Version)
	}
	want := []string{"@babel/core@7.23.0", "express@4.18.2", "lodash@3.10.1", "lodash@4.17.21"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}

	// Two versions of one package is the normal case, not a duplicate: each
	// nesting level is a distinct installed instance, and which one a file
	// sees depends on where the file is.
	dirs := map[string]string{}
	for _, p := range res.Packages {
		if p.Name == "lodash" {
			dirs[p.Version] = p.Dir
		}
	}
	if dirs["4.17.21"] != "/app/node_modules/lodash" ||
		dirs["3.10.1"] != "/app/node_modules/express/node_modules/lodash" {
		t.Errorf("lodash dirs = %v", dirs)
	}
	for _, p := range res.Packages {
		if p.DB != "/app/node_modules" {
			t.Errorf("%s: DB = %q, want the top-level node_modules", p.Name, p.DB)
		}
	}
}

// A package owns its directory except for a nested node_modules, which belongs
// to the packages inside it.
func TestNPMFilesStopAtANestedNodeModules(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/app/node_modules/express/package.json":                     `{"name":"express","version":"4.18.2"}`,
		"/app/node_modules/express/lib/router.js":                    "",
		"/app/node_modules/express/node_modules/lodash/package.json": `{"name":"lodash","version":"3.10.1"}`,
		"/app/node_modules/express/node_modules/lodash/index.js":     "",
	})

	res, _ := (&NPM{}).Read(fsys, []string{"/app/node_modules"})
	for _, p := range res.Packages {
		if p.Name != "express" {
			continue
		}
		if !p.FilesKnown || !has(p.Files, "/app/node_modules/express/lib/router.js") {
			t.Errorf("express Files = %v", p.Files)
		}
		if has(p.Files, "/app/node_modules/express/node_modules/lodash/index.js") {
			t.Errorf("express claims files belonging to its nested lodash: %v", p.Files)
		}
	}
}

// A node_modules tree routinely contains deliberately malformed fixtures, so
// one bad manifest must not fail the image -- but it must not vanish either: a
// package whose manifest could not be read is one whose absence cannot be
// asserted.
func TestNPMBrokenManifestIsRecordedNotFatal(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/app/node_modules/good/package.json": `{"name":"good","version":"1.0.0"}`,
		"/app/node_modules/bad/package.json":  `{"name": `,
	})

	res, err := (&NPM{}).Read(fsys, []string{"/app/node_modules"})
	if err != nil {
		t.Fatalf("one bad manifest failed the whole read: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "good" {
		t.Errorf("packages = %+v", res.Packages)
	}
	if want := []string{"/app/node_modules/bad/package.json"}; !reflect.DeepEqual(res.Unreadable, want) {
		t.Errorf("Unreadable = %v, want %v", res.Unreadable, want)
	}
}

func TestNPMFallsBackToTheDirectoryName(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/app/node_modules/private-thing/package.json": `{"version":"0.1.0"}`,
		"/app/node_modules/@acme/widget/package.json":  `{"version":"2.0.0"}`,
		"/app/node_modules/weird/package.json":         `{"name":"weird","version":42}`,
	})

	res, _ := (&NPM{}).Read(fsys, []string{"/app/node_modules"})
	got := map[string]string{}
	for _, p := range res.Packages {
		got[p.Name] = p.Version
	}
	want := map[string]string{"private-thing": "0.1.0", "@acme/widget": "2.0.0", "weird": ""}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	// A Node package is imported by the name it declares; there is no
	// PyYAML-style divergence to guess at.
	for _, p := range res.Packages {
		if !p.ImportNamesKnown || !reflect.DeepEqual(p.ImportNames, []string{p.Name}) {
			t.Errorf("%s: ImportNames = %v (known %v)", p.Name, p.ImportNames, p.ImportNamesKnown)
		}
	}
}

func TestScanRunsBothReaders(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/usr/lib/python3.12/site-packages/six-1.16.0.dist-info/METADATA": "Name: six\nVersion: 1.16.0\n",
		"/app/node_modules/lodash/package.json":                           `{"name":"lodash","version":"4.17.21"}`,
	})

	res, err := Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var formats []string
	for _, r := range res {
		formats = append(formats, string(r.Format))
	}
	sort.Strings(formats)
	if want := []string{"npm", "pypi"}; !reflect.DeepEqual(formats, want) {
		t.Errorf("formats = %v, want %v", formats, want)
	}
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
