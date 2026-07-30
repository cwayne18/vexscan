package lockfile

import (
	"os"
	"path/filepath"
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

// read runs one reader over a tree and fails the test on error.
func read(t *testing.T, r Reader, files map[string]string) []Result {
	t.Helper()
	res, err := r.Read(writeTree(t, files), "/repo")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return res
}

// find returns the package with the given name, or fails.
func pkg(t *testing.T, pkgs []Package, name string) Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no package %q in %+v", name, pkgs)
	return Package{}
}

func absent(t *testing.T, pkgs []Package, name string) {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			t.Fatalf("package %q should not have been reported: %+v", name, p)
		}
	}
}

func TestNPMReadsTheV3PackagesMap(t *testing.T) {
	res := read(t, &NPM{}, map[string]string{
		"/repo/package-lock.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/tar": {"version": "6.1.11", "resolved": "https://r/tar"},
    "node_modules/tar/node_modules/minipass": {"version": "3.3.6"},
    "node_modules/minipass": {"version": "5.0.0"},
    "node_modules/@babel/core": {"version": "7.24.0", "dev": true},
    "node_modules/eslint": {"version": "8.57.0", "dev": true}
  }
}`,
	})
	if len(res) != 1 {
		t.Fatalf("want one result, got %d", len(res))
	}
	if !res[0].DevKnown {
		t.Error("package-lock.json partitions dev dependencies; DevKnown should be true")
	}
	pkgs := Packages(res)

	// Two versions of minipass at two nesting levels are two distinct
	// installed instances, and an advisory can apply to one and not the other.
	var minipass []string
	for _, p := range pkgs {
		if p.Name == "minipass" {
			minipass = append(minipass, p.Version)
		}
	}
	if len(minipass) != 2 {
		t.Errorf("want both nested minipass versions, got %v", minipass)
	}

	if got := pkg(t, pkgs, "@babel/core"); !got.Dev {
		t.Error("@babel/core is marked dev in the lock file")
	}
	if got := pkg(t, pkgs, "tar"); got.Dev {
		t.Error("tar is a runtime dependency")
	}
	// The root project is not a dependency of itself.
	absent(t, pkgs, "app")
}

func TestNPMResolvesAnAliasToTheRegistryName(t *testing.T) {
	// `"lodash": "npm:lodash-es@4.17.21"` installs lodash-es's code at
	// node_modules/lodash. OSV keys the advisory on lodash-es, so reading the
	// name off the install path would ask about the wrong package.
	pkgs := Packages(read(t, &NPM{}, map[string]string{
		"/repo/package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/lodash": {"name": "lodash-es", "version": "4.17.21"}
  }
}`,
	}))
	pkg(t, pkgs, "lodash-es")
	absent(t, pkgs, "lodash")
}

func TestNPMSkipsWorkspaceLinks(t *testing.T) {
	// A workspace member appears twice: once as a link under node_modules and
	// once as the real directory. Only the real one carries a version, and
	// neither is a registry package OSV can be asked about.
	pkgs := Packages(read(t, &NPM{}, map[string]string{
		"/repo/package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "monorepo"},
    "packages/ui": {"name": "@app/ui", "version": "0.1.0"},
    "node_modules/@app/ui": {"resolved": "packages/ui", "link": true},
    "node_modules/react": {"version": "18.2.0"}
  }
}`,
	}))
	pkg(t, pkgs, "react")
	absent(t, pkgs, "@app/ui")
}

func TestNPMV1InheritsTheDevFlagDownTheTree(t *testing.T) {
	// v1 marks only the top of a dev subtree. Reading the flag literally would
	// report eslint's own dependencies as production packages.
	pkgs := Packages(read(t, &NPM{}, map[string]string{
		"/repo/package-lock.json": `{
  "lockfileVersion": 1,
  "dependencies": {
    "eslint": {
      "version": "8.57.0",
      "dev": true,
      "dependencies": {
        "espree": {"version": "9.6.1"}
      }
    },
    "tar": {"version": "6.1.11"}
  }
}`,
	}))
	if got := pkg(t, pkgs, "espree"); !got.Dev {
		t.Error("espree is only reachable through a dev dependency")
	}
	if got := pkg(t, pkgs, "tar"); got.Dev {
		t.Error("tar is a runtime dependency")
	}
}

func TestNPMRuntimeUseWinsOverDevUse(t *testing.T) {
	// The same coordinate installed twice, dev in one place and runtime in
	// another, ships in production. Deduplication must not let Go's randomized
	// map iteration order decide which copy is reported.
	pkgs := Packages(read(t, &NPM{}, map[string]string{
		"/repo/package-lock.json": `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/eslint/node_modules/semver": {"version": "7.6.0", "dev": true},
    "node_modules/semver": {"version": "7.6.0"}
  }
}`,
	}))
	if got := pkg(t, pkgs, "semver"); got.Dev {
		t.Error("semver is installed as a runtime dependency too")
	}
}

func TestNPMAMalformedLockFileIsAnError(t *testing.T) {
	// An empty inventory renders as "this repo depends on nothing vulnerable",
	// so a file that exists and will not parse has to stop the scan.
	_, err := (&NPM{}).Read(writeTree(t, map[string]string{
		"/repo/package-lock.json": `{"packages": [broken`,
	}), "/repo")
	if err == nil {
		t.Fatal("want an error for an unparseable lock file")
	}
}

func TestNPMNoLockFileIsNotAnError(t *testing.T) {
	res := read(t, &NPM{}, map[string]string{"/repo/package.json": `{"name":"app"}`})
	if len(res) != 0 {
		t.Fatalf("want no results, got %+v", res)
	}
}

func TestRequirementsReadsPinsAndSkipsOptions(t *testing.T) {
	res := read(t, &PyPI{}, map[string]string{
		"/repo/requirements.txt": `# app dependencies
-r base.txt
--index-url https://pypi.org/simple

Django==5.0.1
requests[security] == 2.31.0  # comment
PyYAML==6.0.3 ; python_version >= "3.8"
flask
uvicorn>=0.20
mypkg @ https://example.invalid/mypkg-1.0.tar.gz
https://example.invalid/anonymous-1.0.tar.gz
-e .
`,
	})
	if len(res) != 1 {
		t.Fatalf("want one result, got %d", len(res))
	}
	if res[0].DevKnown {
		t.Error("requirements.txt carries no dev partition; DevKnown must be false")
	}
	pkgs := Packages(res)

	for name, want := range map[string]string{
		"django":   "5.0.1",
		"requests": "2.31.0",
		"pyyaml":   "6.0.3",
	} {
		if got := pkg(t, pkgs, name).Version; got != want {
			t.Errorf("%s version = %q, want %q", name, got, want)
		}
	}
	// An unpinned requirement still proves presence, which is the question
	// repo mode answers best; it just carries no version to match a range on.
	for _, name := range []string{"flask", "uvicorn", "mypkg"} {
		if got := pkg(t, pkgs, name).Version; got != "" {
			t.Errorf("%s should have no version, got %q", name, got)
		}
	}
	absent(t, pkgs, "base.txt")
}

func TestRequirementsJoinsHashContinuations(t *testing.T) {
	// pip-compile's output is the common case, and its hash lines are
	// continuations of the requirement above them.
	pkgs := Packages(read(t, &PyPI{}, map[string]string{
		"/repo/requirements.txt": `certifi==2024.2.2 \
    --hash=sha256:0569859f95fc761b18b45ef421b1290a0f65f147e92a1e5eb3e635f9a5e4e66f \
    --hash=sha256:dc383c07b76109f368f6106eee2b593b04a011ea4d55f652c6ca24a754d1cdd1
idna==3.6 \
    --hash=sha256:9ecdbbd083b06798ae1e86adcbfe8ab1479cf864e4ee30fe4e46a003d12491ca
`,
	}))
	if got := pkg(t, pkgs, "certifi").Version; got != "2024.2.2" {
		t.Errorf("certifi version = %q", got)
	}
	if got := pkg(t, pkgs, "idna").Version; got != "3.6" {
		t.Errorf("idna version = %q", got)
	}
	if len(pkgs) != 2 {
		t.Errorf("hash lines should not become packages: %+v", pkgs)
	}
}

func TestRequirementsReadsEveryRequirementsFile(t *testing.T) {
	res := read(t, &PyPI{}, map[string]string{
		"/repo/requirements.txt":     "django==5.0.1\n",
		"/repo/requirements-dev.txt": "pytest==8.0.0\n",
	})
	if len(res) != 2 {
		t.Fatalf("want both files, got %d", len(res))
	}
	pkgs := Packages(res)
	// requirements-dev.txt is a naming convention, not a declaration. Nothing
	// in either file says pytest is development-only, so nothing may claim it.
	if got := pkg(t, pkgs, "pytest"); got.Dev {
		t.Error("a file name must not be read as a dev partition")
	}
	if DevOnly(res, "pytest") {
		t.Error("a file that declares no dev partition cannot make a package dev-only")
	}
}

func TestPoetryLockReadsGroups(t *testing.T) {
	res := read(t, &PyPI{}, map[string]string{
		"/repo/poetry.lock": `# This file is automatically @generated by Poetry.

[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
groups = ["main"]
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:aaa"},
]

[package.dependencies]
certifi = ">=2017.4.17"

[[package]]
name = "pytest"
version = "8.0.0"
optional = false
groups = ["dev"]

[metadata]
lock-version = "2.1"
`,
	})
	if len(res) != 1 || !res[0].DevKnown {
		t.Fatalf("want one result with a dev partition, got %+v", res)
	}
	pkgs := Packages(res)
	if got := pkg(t, pkgs, "requests"); got.Version != "2.31.0" || got.Dev {
		t.Errorf("requests = %+v", got)
	}
	if got := pkg(t, pkgs, "pytest"); !got.Dev {
		t.Error("pytest is in the dev group only")
	}
	// [package.dependencies] names certifi, but the lock file resolves no
	// version for it there -- the [[package]] block for certifi would. Reading
	// the nested table as a package would invent one.
	absent(t, pkgs, "certifi")
}

func TestPoetryLockReadsTheOldCategoryKey(t *testing.T) {
	pkgs := Packages(read(t, &PyPI{}, map[string]string{
		"/repo/poetry.lock": `[[package]]
name = "black"
version = "24.1.0"
category = "dev"

[[package]]
name = "requests"
version = "2.31.0"
category = "main"
`,
	}))
	if got := pkg(t, pkgs, "black"); !got.Dev {
		t.Error("category = dev means development-only")
	}
	if got := pkg(t, pkgs, "requests"); got.Dev {
		t.Error("category = main is a runtime dependency")
	}
}

func TestPoetryLockWithoutGroupsDeclaresNoPartition(t *testing.T) {
	res := read(t, &PyPI{}, map[string]string{
		"/repo/poetry.lock": `[[package]]
name = "requests"
version = "2.31.0"
`,
	})
	if res[0].DevKnown {
		t.Error("a lock file that names no group cannot support a dev conclusion")
	}
}

func TestPipfileLockPartitionsDevelop(t *testing.T) {
	res := read(t, &PyPI{}, map[string]string{
		"/repo/Pipfile.lock": `{
  "_meta": {"hash": {"sha256": "aaa"}},
  "default": {
    "requests": {"version": "==2.31.0", "index": "pypi"},
    "gitdep": {"git": "https://example.invalid/x.git", "ref": "abc"}
  },
  "develop": {
    "pytest": {"version": "==8.0.0"}
  }
}`,
	})
	if !res[0].DevKnown {
		t.Fatal("Pipfile.lock partitions dev dependencies")
	}
	pkgs := Packages(res)
	if got := pkg(t, pkgs, "requests"); got.Version != "2.31.0" || got.Dev {
		t.Errorf("requests = %+v", got)
	}
	if got := pkg(t, pkgs, "pytest"); !got.Dev {
		t.Error("pytest is under develop")
	}
	// A git dependency has no version. It is still present.
	if got := pkg(t, pkgs, "gitdep"); got.Version != "" {
		t.Errorf("gitdep version = %q, want empty", got.Version)
	}
}

func TestDevOnlyNeedsEveryFileToAgree(t *testing.T) {
	// One repo, two lock files: the package is dev-only in one and a runtime
	// dependency in the other. It ships.
	res := read(t, &PyPI{}, map[string]string{
		"/repo/poetry.lock": `[[package]]
name = "pyyaml"
version = "6.0.3"
groups = ["dev"]
`,
		"/repo/Pipfile.lock": `{"default": {"pyyaml": {"version": "==6.0.3"}}, "develop": {}}`,
	})
	if DevOnly(res, "pyyaml") {
		t.Error("pyyaml is a runtime dependency in Pipfile.lock, so it is not dev-only")
	}
}

func TestReadDispatchesByFormat(t *testing.T) {
	fsys := writeTree(t, map[string]string{
		"/repo/package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/tar":{"version":"6.1.11"}}}`,
		"/repo/requirements.txt":  "django==5.0.1\n",
	})
	npm, err := Read(fsys, "/repo", FormatNPM)
	if err != nil {
		t.Fatal(err)
	}
	pkg(t, Packages(npm), "tar")
	absent(t, Packages(npm), "django")

	py, err := Read(fsys, "/repo", FormatPyPI)
	if err != nil {
		t.Fatal(err)
	}
	pkg(t, Packages(py), "django")
}
