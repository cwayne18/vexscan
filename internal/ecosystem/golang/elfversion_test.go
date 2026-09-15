package golang

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
)

// buildStamped compiles a linux/amd64 ELF from the given sources, stamping it
// with ldflags, and returns its path. -trimpath is always on, because that is
// the condition every test in this file is about.
//
// Real builds are the only useful fixture. What is under test is what the Go
// linker does with an -X assignment -- which symbol it creates, what it names
// it, and where it puts the bytes -- so a handwritten ELF would only test this
// package's idea of the linker.
func buildStamped(t *testing.T, ldflags string, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	src := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/proj\n\ngo 1.23\n")
	for rel, body := range files {
		write(rel, body)
	}

	dst := filepath.Join(t.TempDir(), "proj")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", dst, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable in this environment: %v: %s", err, out)
	}
	return dst
}

// mainOnly is a program whose package main declares and prints `version`, so
// the -X stamp has something to write to and the linker cannot drop it.
const mainOnly = `package main

var version = "dev"

func main() { println(version) }
`

// withVersionPackage is the shape k8s.io/ingress-nginx has: the version lives
// in the module's own version package, not in main. The import is aliased
// because package main declares a `version` of its own in some of these tests.
const withVersionPackage = `package main

import ver "example.com/proj/version"

func main() { println(ver.RELEASE) }
`

const versionPackage = `package version

var RELEASE = "dev"
`

// The bug this file exists for, stated end to end. -trimpath makes Go record no
// -ldflags at all (go.dev/issue/63432), so the flags recovery has nothing to
// read on a binary that was stamped perfectly well, and the main module falls
// back to "(devel)" -- against which OSV returns every advisory ever filed.
func TestTrimpathHidesLDFlagsButNotTheSymbol(t *testing.T) {
	bin := buildStamped(t, "-X main.version=v9.9.9", map[string]string{"main.go": mainOnly})

	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := ldflagsSetting(info.Settings); got != "" {
		t.Fatalf("-ldflags setting = %q, want empty: the premise here is that -trimpath drops it", got)
	}
	if v, _ := moduleVersionFromLDFlags("example.com/proj", info.Settings); v != "" {
		t.Fatalf("flags recovery = %q, want empty: there are no flags to read", v)
	}

	got, key := moduleVersionFromELFSymbols("example.com/proj", bin)
	if got != "v9.9.9" {
		t.Errorf("symbol recovery = %q, want v9.9.9", got)
	}
	if key != "main.version" {
		t.Errorf("key = %q, want main.version", key)
	}
}

// The name k8s.io/ingress-nginx stamps its own version under. Nothing about
// "RELEASE" is unusual except that the allowlist did not have it.
func TestReleaseVariableIsAVersion(t *testing.T) {
	bin := buildStamped(t, "-X example.com/proj/version.RELEASE=v1.15.1", map[string]string{
		"main.go":            withVersionPackage,
		"version/version.go": versionPackage,
	})

	got, key := moduleVersionFromELFSymbols("example.com/proj", bin)
	if got != "v1.15.1" {
		t.Errorf("version = %q, want v1.15.1", got)
	}
	if key != "example.com/proj/version.RELEASE" {
		t.Errorf("key = %q, want the project's own RELEASE variable", key)
	}
}

// The authority test, and the reason this does not select on the shape of the
// name. k3s stamps containerd's, cri-tools' and kube-router's versions into its
// own binary under variables named exactly like its own; reading one of those
// as k3s's version is not a near miss, it is off by an entire project.
//
// The fixture is that shape in miniature: a real second module, vendored in by
// a replace, whose version package is stamped and whose version must not be
// mistaken for the main module's.
func TestDependencyStampIsNotTheMainModulesVersion(t *testing.T) {
	bin := buildStamped(t, "-X example.com/dep/version.Version=v9.9.9", map[string]string{
		"go.mod": `module example.com/proj

go 1.23

require example.com/dep v0.0.0

replace example.com/dep => ./dep
`,
		"main.go": `package main

import dep "example.com/dep/version"

func main() { println(dep.Version) }
`,
		"dep/go.mod": "module example.com/dep\n\ngo 1.23\n",
		"dep/version/version.go": `package version

var Version = "dev"
`,
	})

	// The stamp is present and readable -- it is simply not this module's.
	if got, _ := moduleVersionFromELFSymbols("example.com/dep", bin); got != "v9.9.9" {
		t.Fatalf("dependency's own version = %q, want v9.9.9: the fixture did not stamp what it meant to", got)
	}
	if got, _ := moduleVersionFromELFSymbols("example.com/proj", bin); got != "" {
		t.Errorf("main module version = %q, want empty: that stamp states the dependency's version", got)
	}
}

// Two stamps under the main module that disagree mean the authority test did
// not actually single one out. Over-reporting beats picking the higher.
func TestDisagreeingSymbolStampsAreRefused(t *testing.T) {
	bin := buildStamped(t,
		"-X main.version=v9.9.9 -X example.com/proj/version.RELEASE=v1.0.0",
		map[string]string{
			"main.go": `package main

import ver "example.com/proj/version"

var version = "dev"

func main() { println(version, ver.RELEASE) }
`,
			"version/version.go": versionPackage,
		})

	if got, _ := moduleVersionFromELFSymbols("example.com/proj", bin); got != "" {
		t.Errorf("version = %q, want empty: the two stamps disagree", got)
	}
}

// Stripping removes the symbol table, which is the documented limit of this
// recovery rather than a defect in it. The answer must be nothing -- not a
// panic, and not a guess.
func TestStrippedBinaryYieldsNothing(t *testing.T) {
	bin := buildStamped(t, "-s -w -X main.version=v9.9.9", map[string]string{"main.go": mainOnly})

	if !binscan.IsStripped(bin) {
		t.Skip("toolchain kept the symbol table despite -s -w")
	}
	if got, _ := moduleVersionFromELFSymbols("example.com/proj", bin); got != "" {
		t.Errorf("version = %q, want empty: a stripped binary carries no .symtab", got)
	}
}

// The recovery is reached through inventory, outranks the image tag, and says
// where it got the number.
func TestGroupAllRecoversMainVersionFromSymbols(t *testing.T) {
	bin := buildStamped(t, "-X main.version=v9.9.9", map[string]string{"main.go": mainOnly})

	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// A checkout build stamps no main-module version, which is the case this
	// recovery is for. If some future toolchain starts supplying one there is
	// no gap left to fill.
	if info.Main.Version != "(devel)" {
		t.Skipf("toolchain stamped Main.Version = %q", info.Main.Version)
	}

	// The image is named after something else entirely, so the tag fallback
	// cannot be what answers this.
	p := New(Options{Image: "docker.io/somebody/unrelated:v0.0.1"})
	comps := p.groupAll(filepath.Dir(bin), []binscan.Binary{{Path: bin, Info: info}})

	c := mainComponent(comps, "example.com/proj")
	if c == nil {
		t.Fatal("no component for the main module")
	}
	if c.Version != "v9.9.9" {
		t.Fatalf("version = %q, want v9.9.9", c.Version)
	}
	st := c.Extra.(*state)
	if st.inferred.origin != "elf-symbol-version" {
		t.Errorf("origin = %q, want elf-symbol-version", st.inferred.origin)
	}
	if !strings.Contains(st.inferred.detail, "main.version.str=v9.9.9") {
		t.Errorf("detail = %q, want the symbol it was read from", st.inferred.detail)
	}
}

// Recorded flags stay ahead of the symbol table: they are the same fact, and
// the one the build itself wrote down.
func TestLDFlagsOutrankSymbols(t *testing.T) {
	bin := buildStamped(t, "-X main.version=v9.9.9", map[string]string{"main.go": mainOnly})
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Supply the flags -trimpath withheld, naming a different version, so which
	// source answered is visible in the result.
	info.Settings = append(info.Settings, ldflags("-X main.version=v1.2.3")...)

	p := New(Options{})
	got, from := p.mainModuleVersion("example.com/proj", "(devel)", binscan.Binary{Path: bin, Info: info}, false)
	if got != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3 from the flags", got)
	}
	if from.origin != "ldflags-version" {
		t.Errorf("origin = %q, want ldflags-version", from.origin)
	}
}

// This runs against every binary a walk turns up, so a shell script and a path
// that is not there at all are ordinary inputs, not errors.
func TestNonELFInputIsEmptyNotFatal(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "notelf")
	if err := os.WriteFile(text, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{text, filepath.Join(dir, "absent"), ""} {
		if got, _ := moduleVersionFromELFSymbols("example.com/proj", path); got != "" {
			t.Errorf("%q: version = %q, want empty", path, got)
		}
	}
}
