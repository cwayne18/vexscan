package elfgraph

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// The fixtures in testdata/elf are the only real object files in this package,
// and they exist to test the debug/elf reader rather than the graph. They were
// built with gcc -nostdlib and stripped, which is why they are a few kilobytes
// each instead of a megabyte:
//
//	libfixture.so.1        SONAME, two defined symbols, no dependencies
//	libfixture-arm64.so.1  the same object built for aarch64
//	app                    NEEDED libfixture.so.1, DT_RUNPATH $ORIGIN/../lib
//	app-rpath              NEEDED libfixture.so.1, DT_RPATH /opt/fixture/lib
//	libdlopener.so.1       one undefined symbol: dlopen
//	static                 no PT_INTERP, no PT_DYNAMIC

// fixtureTree lays fixtures out at the given tree paths and returns a RootFS.
func fixtureTree(t *testing.T, layout map[string]string) target.RootFS {
	t.Helper()
	root := t.TempDir()
	for treePath, fixture := range layout {
		b, err := os.ReadFile(filepath.Join("testdata", "elf", fixture))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(treePath, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return target.NewDirFS(root)
}

func TestReadELF(t *testing.T) {
	fsys := fixtureTree(t, map[string]string{
		"/bin/app":              "app",
		"/bin/app-rpath":        "app-rpath",
		"/bin/static":           "static",
		"/lib/libfixture.so.1":  "libfixture.so.1",
		"/lib/libdlopener.so.1": "libdlopener.so.1",
		"/lib/libarm.so.1":      "libfixture-arm64.so.1",
	})

	tests := []struct {
		path  string
		check func(*testing.T, *Info)
	}{
		{"/bin/app", func(t *testing.T, i *Info) {
			if i.Class != elf.ELFCLASS64 || i.Machine != elf.EM_X86_64 || i.Type != elf.ET_EXEC {
				t.Errorf("class/machine/type = %v/%v/%v", i.Class, i.Machine, i.Type)
			}
			if !strings.Contains(i.Interp, "ld-linux") {
				t.Errorf("Interp = %q, want the dynamic loader", i.Interp)
			}
			if i.Static() {
				t.Error("a binary with PT_INTERP reported as static")
			}
			if !slices.Equal(i.Needed, []string{"libfixture.so.1"}) {
				t.Errorf("Needed = %v", i.Needed)
			}
			// --enable-new-dtags produces DT_RUNPATH, which the linker does
			// not inherit; the distinction is load-bearing in resolve().
			if !slices.Equal(i.RunPath, []string{"$ORIGIN/../lib"}) {
				t.Errorf("RunPath = %v", i.RunPath)
			}
			if len(i.RPath) != 0 {
				t.Errorf("RPath = %v, want none", i.RPath)
			}
			if i.Dlopen {
				t.Error("Dlopen set on a binary that does not call it")
			}
		}},
		{"/bin/app-rpath", func(t *testing.T, i *Info) {
			if !slices.Equal(i.RPath, []string{"/opt/fixture/lib"}) {
				t.Errorf("RPath = %v", i.RPath)
			}
			if len(i.RunPath) != 0 {
				t.Errorf("RunPath = %v, want none", i.RunPath)
			}
		}},
		{"/lib/libfixture.so.1", func(t *testing.T, i *Info) {
			if i.Soname != "libfixture.so.1" {
				t.Errorf("Soname = %q", i.Soname)
			}
			if i.Type != elf.ET_DYN || !i.Dynamic {
				t.Errorf("type = %v, dynamic = %v", i.Type, i.Dynamic)
			}
			if i.Interp != "" {
				t.Errorf("a shared library has no program interpreter, got %q", i.Interp)
			}
		}},
		{"/lib/libdlopener.so.1", func(t *testing.T, i *Info) {
			if !i.Dlopen {
				t.Error("an undefined dlopen import was not detected")
			}
		}},
		{"/bin/static", func(t *testing.T, i *Info) {
			if i.Interp != "" || i.Dynamic {
				t.Errorf("Interp = %q, Dynamic = %v", i.Interp, i.Dynamic)
			}
			if !i.Static() {
				t.Error("a binary with no interpreter did not report as static")
			}
		}},
		{"/lib/libarm.so.1", func(t *testing.T, i *Info) {
			if i.Machine != elf.EM_AARCH64 {
				t.Errorf("Machine = %v, want aarch64", i.Machine)
			}
			// Same soname as the x86-64 build. Nothing but the machine
			// distinguishes them, which is why resolve() checks it.
			if i.Soname != "libfixture.so.1" {
				t.Errorf("Soname = %q", i.Soname)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			i, err := ReadELF(fsys, tt.path)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, i)
		})
	}
}

func TestReadELFOnNonELFFiles(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"script": "#!/bin/sh\necho hi\n",
		"empty":  "",
		"short":  "\x7fEL",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fsys := target.NewDirFS(root)

	for _, name := range []string{"script", "empty", "short"} {
		if _, err := ReadELF(fsys, "/"+name); !errors.Is(err, ErrNotELF) {
			t.Errorf("ReadELF(%s) = %v, want ErrNotELF", name, err)
		}
	}

	// A file that claims to be ELF and then is not is a different matter: its
	// dependencies are unknown rather than irrelevant, so it must not be
	// quietly filed alongside the shell scripts.
	if err := os.WriteFile(filepath.Join(root, "truncated"), []byte("\x7fELF\x02\x01\x01\x00garbage"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := func() error { _, err := ReadELF(fsys, "/truncated"); return err }()
	if err == nil {
		t.Fatal("a truncated ELF parsed successfully")
	}
	if errors.Is(err, ErrNotELF) {
		t.Errorf("a corrupt ELF was reported as an ordinary non-ELF file: %v", err)
	}
}

func TestSymbols(t *testing.T) {
	fsys := fixtureTree(t, map[string]string{
		"/lib/libfixture.so.1":  "libfixture.so.1",
		"/lib/libdlopener.so.1": "libdlopener.so.1",
	})

	def, undef, err := Symbols(fsys, "/lib/libfixture.so.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fixture_symbol", "fixture_other"} {
		if !slices.Contains(def, want) {
			t.Errorf("defined symbols %v are missing %s", def, want)
		}
	}
	if slices.Contains(undef, "fixture_symbol") {
		t.Errorf("a defined symbol was reported as undefined: %v", undef)
	}

	// The two lists are what the mined-symbol validation turns on: a symbol
	// found in "defined" proves the library really implements the function an
	// advisory named, and only then does its absence elsewhere mean anything.
	def, undef, err = Symbols(fsys, "/lib/libdlopener.so.1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(undef, "dlopen") {
		t.Errorf("undefined symbols %v are missing dlopen", undef)
	}
	if slices.Contains(def, "dlopen") {
		t.Errorf("dlopen was reported as defined by a library that only imports it: %v", def)
	}
	if !slices.Contains(def, "plugin_load") {
		t.Errorf("defined symbols %v are missing plugin_load", def)
	}
}

// TestClosureOverRealObjects runs the graph with the real reader. Everything
// else in the package is tested against a fake, so this is the one check that
// the two halves agree -- in particular that a $ORIGIN-relative DT_RUNPATH
// written by a real linker resolves to a real file.
func TestClosureOverRealObjects(t *testing.T) {
	fsys := fixtureTree(t, map[string]string{
		"/opt/app/bin/app":             "app",
		"/opt/app/lib/libfixture.so.1": "libfixture.so.1",
		"/usr/lib/libdlopener.so.1":    "libdlopener.so.1",
	})
	g, err := Build(fsys, Options{Config: target.ImageConfig{Entrypoint: []string{"/opt/app/bin/app"}}})
	if err != nil {
		t.Fatal(err)
	}

	if !g.Reachable("/opt/app/lib/libfixture.so.1") {
		t.Error("DT_RUNPATH $ORIGIN/../lib did not resolve against a real object")
	}
	if g.Reachable("/usr/lib/libdlopener.so.1") {
		t.Error("an unreferenced library is in the closure")
	}
	// The loader itself is not in this tree, so it is an honest hole.
	if tt := hasTaint(g, TaintUnresolvedNeeded); tt != nil {
		t.Errorf("unexpected unresolved dependency: %s", tt.Detail)
	}
}

// TestRealABIMismatch: the aarch64 build has the same soname and would be
// picked by any resolver matching on filename alone.
func TestRealABIMismatch(t *testing.T) {
	fsys := fixtureTree(t, map[string]string{
		"/opt/app/bin/app":                          "app",
		"/opt/app/lib/libfixture.so.1":              "libfixture-arm64.so.1",
		"/usr/lib/x86_64-linux-gnu/libfixture.so.1": "libfixture.so.1",
	})
	g, err := Build(fsys, Options{Config: target.ImageConfig{Entrypoint: []string{"/opt/app/bin/app"}}})
	if err != nil {
		t.Fatal(err)
	}

	// $ORIGIN/../lib is searched first and holds the aarch64 copy; the search
	// has to skip it and fall through to the default directories.
	if g.Reachable("/opt/app/lib/libfixture.so.1") {
		t.Error("an aarch64 library satisfied an x86-64 DT_NEEDED")
	}
	if !g.Reachable("/usr/lib/x86_64-linux-gnu/libfixture.so.1") {
		t.Error("the matching library was not found in the default search path")
	}
}
