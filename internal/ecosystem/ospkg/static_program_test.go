package ospkg

import (
	"debug/elf"
	"maps"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/target"
)

// staticProgram is a statically linked program: no interpreter, so the closure
// cannot see what it carries inside itself, so it raises a blocking
// static-elf taint over the whole image.
func staticProgram() *elfgraph.Info {
	return &elfgraph.Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
}

// runnableLib is glibc's libc.so.6: a shared library that also carries a
// PT_INTERP, so that running it prints the version banner. It is a library by
// every meaning that matters and a program by header alone.
func runnableLib() *elfgraph.Info {
	return &elfgraph.Info{
		Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_DYN,
		Dynamic: true, Soname: "libc.so.6", Interp: "/lib64/ld-linux-x86-64.so.2",
	}
}

// The discharge itself, and the three things that must switch it off.
//
// A static entrypoint blocks every OS conclusion in the image, because the
// libraries it links are inside it rather than on disk. That is a statement
// about linkable code: a package that installs only programs has none for the
// entrypoint to have swallowed, so the closure's finding that nothing reaches
// it is allowed to stand. Each of the other rows installs something that could
// have been linked in, and each must keep the taint blocking.
func TestStaticProgramOnlyDischarge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		files     []string
		elves     fakeELF
		discharge bool
	}{
		// cpio installs /usr/bin/cpio and nothing else. No executable is
		// linked into another executable, so the static entrypoint cannot be
		// hiding this package's code.
		{
			name:  "only programs",
			files: []string{"/usr/bin/cpio", "/usr/share/man/man1/cpio.1"},
			elves: fakeELF{"/usr/bin/cpio": exe()},

			discharge: true,
		},
		// One shared library beside the tools is exactly what a static
		// entrypoint links, so the whole package keeps the taint.
		{
			name:  "a library beside the programs",
			files: []string{"/usr/bin/cpio", "/usr/lib/libcpio.so.1"},
			elves: fakeELF{"/usr/bin/cpio": exe(), "/usr/lib/libcpio.so.1": lib("libcpio.so.1")},

			discharge: false,
		},
		// Linked without -soname, which is unusual but legal and common
		// enough in vendored trees. There is no name to link against, so the
		// SONAME test says nothing and the header has to: ET_DYN with no
		// interpreter is not something you run.
		{
			name:  "a library with no soname to give it away",
			files: []string{"/usr/bin/cpio", "/usr/lib/libcpio.so"},
			elves: fakeELF{"/usr/bin/cpio": exe(), "/usr/lib/libcpio.so": {
				Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_DYN, Dynamic: true,
			}},

			discharge: false,
		},
		// The header says program; the SONAME says library. The SONAME wins,
		// or glibc discharges its own taint.
		{
			name:  "a library that is also runnable",
			files: []string{"/usr/bin/cpio", "/usr/lib/libc.so.6"},
			elves: fakeELF{"/usr/bin/cpio": exe(), "/usr/lib/libc.so.6": runnableLib()},

			discharge: false,
		},
		// A .a is the linkable form a static binary consumes, and the graph
		// does not index it, so it is absent from the ELF set for a reason
		// that has nothing to do with the package not shipping one.
		{
			name:  "a static archive the graph cannot see",
			files: []string{"/usr/bin/cpio", "/usr/lib/libcpio.a"},
			elves: fakeELF{"/usr/bin/cpio": exe()},

			discharge: false,
		},
		{
			name:  "a loose object file the graph cannot see",
			files: []string{"/usr/bin/cpio", "/usr/lib/cpio-util.o"},
			elves: fakeELF{"/usr/bin/cpio": exe()},

			discharge: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := debianImage(t,
				target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
				[]debPkg{{name: "cpio", version: "2.13-1", files: tc.files}},
				map[string]string{"/usr/bin/app": ""})

			elves := fakeELF{"/usr/bin/app": staticProgram()}
			maps.Copy(elves, tc.elves)

			f := statuses(t, elfPlugin(elves), img, []ecosystem.Subject{{Raw: ""}})["cpio"]

			got := evidenceFrom(f, MethodStaticProgramOnly)
			if (len(got) > 0) != tc.discharge {
				t.Errorf("program-only discharge evidence = %v, want present=%v", got, tc.discharge)
			}
			want := ecosystem.StatusLinked
			if tc.discharge {
				want = ecosystem.StatusNotInPath
			}
			if f.Status != want {
				t.Errorf("status = %s, want %s", f.Status, want)
			}
			if !tc.discharge {
				return
			}
			if why := strings.Join(got, " "); !strings.Contains(why, "/usr/bin/app") ||
				!strings.Contains(why, "cpio") {
				t.Errorf("discharge evidence names neither the entrypoint it clears nor the package: %q", why)
			}
			if f.Justification != "vulnerable_code_not_in_execute_path" {
				t.Errorf("justification = %q, want vulnerable_code_not_in_execute_path", f.Justification)
			}
		})
	}
}

// elfPlugin is a plugin over one ELF table, for the rows above.
func elfPlugin(elves fakeELF) *Plugin { return New(Options{ReadELF: elves.read}) }

// The discharge answers "could the entrypoint be hiding this code", and
// nothing else. It must not answer "is this code run", because the two
// questions come apart precisely for a package of programs: a program is
// reached by being executed rather than by being linked.
//
// Without this, discharging the taint for a program-only package would clear
// the very packages whose programs the entrypoint runs -- the shell it execs,
// the tools that shell calls -- which is the worst false negative this
// discharge could produce, because those are the reachable ones.
func TestStaticProgramOnlyDischargeDoesNotClearAReachedProgram(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{
			{name: "bash", version: "5.2-1", files: []string{"/usr/bin/bash"}},
			{name: "cpio", version: "2.13-1", files: []string{"/usr/bin/cpio"}},
		},
		map[string]string{"/usr/bin/app": ""})

	plugin := New(Options{
		// The entrypoint execs the shell, so --roots names it and the closure
		// treats it as executed.
		Roots: []string{"/usr/bin/bash"},
		ReadELF: fakeELF{
			"/usr/bin/app":  staticProgram(),
			"/usr/bin/bash": exe(),
			"/usr/bin/cpio": exe(),
		}.read,
	})

	got := statuses(t, plugin, img, []ecosystem.Subject{{Raw: ""}})

	if s := got["bash"].Status; s != ecosystem.StatusLinked {
		t.Errorf("bash: status = %s, want %s: it is a root, so it is executed", s, ecosystem.StatusLinked)
	}
	// The other program-only package in the same image still clears, so the
	// row above is the reachability check doing its job rather than the
	// discharge having failed to fire.
	if s := got["cpio"].Status; s != ecosystem.StatusNotInPath {
		t.Errorf("cpio: status = %s, want %s", s, ecosystem.StatusNotInPath)
	}
}

// The discharge is a sentence about static linking, so it must be said only
// about a static-linking taint.
//
// blockersExcept drops a cleared path only when the taint at it is static-elf,
// so naming another kind here changes no status -- but it does put a line in
// the report saying a dlopen caller "being statically linked cannot be hiding
// its code", which is false about a binary that is not statically linked and
// claims a discharge that was never made. A report that lies about why a row
// is still blocked is the same failure as one that clears it wrongly, one step
// further from being noticed.
func TestStaticProgramOnlyDischargeSpeaksOnlyOfTheStaticTaint(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "cpio", version: "2.13-1", files: []string{"/usr/bin/cpio"}}},
		map[string]string{"/usr/bin/app": "", "/usr/bin/loader": ""})

	loader := exe()
	loader.Dlopen = true

	plugin := New(Options{
		// A second executed program, so the dlopen taint lands on a different
		// path from the static one and the two can be told apart.
		Roots: []string{"/usr/bin/loader"},
		ReadELF: fakeELF{
			"/usr/bin/app":    staticProgram(),
			"/usr/bin/loader": loader,
			"/usr/bin/cpio":   exe(),
		}.read,
	})

	f := statuses(t, plugin, img, []ecosystem.Subject{{Raw: ""}})["cpio"]

	got := evidenceFrom(f, MethodStaticProgramOnly)
	if len(got) != 1 {
		t.Fatalf("program-only evidence = %v, want exactly the one line about the static entrypoint", got)
	}
	if strings.Contains(got[0], "/usr/bin/loader") {
		t.Errorf("discharge claims to have cleared a taint that is not about static linking: %q", got[0])
	}
	// And the dlopen caller still blocks, because nothing here answered it.
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("status = %s, want %s: the dlopen taint was never discharged", f.Status, ecosystem.StatusLinked)
	}
}

// A taint that is not blocking has already been answered, and claiming to
// discharge it a second time credits this function with work the prober did.
//
// The fixture is #24's case: a pure-Go static entrypoint, which links no C
// library, so the prober closed the question before this function was reached.
// The row clears either way, which is why the assertion is on the evidence --
// only that can say whether the reason given for the clear is the true one.
// The prober is injected here rather than through the plugin because the
// plugin wires in the real one, and the real one wants a Go binary to read.
func TestStaticProgramOnlyDischargeSaysNothingOfAnAnsweredTaint(t *testing.T) {
	img := debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "cpio", version: "2.13-1", files: []string{"/usr/bin/cpio"}}},
		map[string]string{"/usr/bin/app": ""})

	g, err := elfgraph.Build(img.FS, elfgraph.Options{
		Config:  img.Config,
		ReadELF: fakeELF{"/usr/bin/app": staticProgram(), "/usr/bin/cpio": exe()}.read,
		StaticProber: func(target.RootFS, string) (elfgraph.StaticProbe, bool) {
			return elfgraph.StaticProbe{
				Closed: true,
				Why:    "/usr/bin/app was built with CGO_ENABLED=0, so it links no C library",
			}, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The premise: a static taint is present, and already answered.
	var found, blocking bool
	for _, tt := range g.Taints() {
		if tt.Kind == elfgraph.TaintStaticELF {
			found = true
			blocking = blocking || tt.Blocking
		}
	}
	if !found || blocking {
		t.Fatalf("fixture wanted one answered static taint, got found=%v blocking=%v", found, blocking)
	}

	e := evaluator{g: g}
	files := []string{"/usr/bin/cpio"}
	if out := e.staticProgramOnlyDischarges("cpio", files, g.Classify(files)); out != nil {
		t.Errorf("claimed a discharge of a taint that was not blocking: %v", out)
	}
}

// With no ELF objects there is no evidence that the package installs only
// programs -- there is no evidence about the package at all -- and "every
// object is a program" is vacuously true of nothing. evaluate answers a
// package with no code before reaching here, so this guards the function
// against being called from anywhere else.
func TestStaticProgramOnlyDischargeNeedsAnObjectToHaveLookedAt(t *testing.T) {
	img := debianImage(t, target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		nil, map[string]string{"/usr/bin/app": ""})

	g, err := elfgraph.Build(img.FS, elfgraph.Options{
		Config:  img.Config,
		ReadELF: fakeELF{"/usr/bin/app": staticProgram()}.read,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The premise of the test: there is a static taint here to discharge.
	var static bool
	for _, tt := range g.Taints() {
		if tt.Kind == elfgraph.TaintStaticELF && tt.Blocking {
			static = true
		}
	}
	if !static {
		t.Fatal("fixture raises no blocking static-elf taint, so it proves nothing")
	}

	e := evaluator{g: g}
	if out := e.staticProgramOnlyDischarges("manpages", []string{"/usr/share/man/man1/intro.1"},
		elfgraph.FileSet{}); out != nil {
		t.Errorf("discharged on no objects at all: %v", out)
	}
}
