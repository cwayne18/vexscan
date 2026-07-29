// Package elfgraph answers one question about a container image: which shared
// libraries would the dynamic linker actually load?
//
// It is the OS-package analog of the pclntab test the Go plugin uses, and a
// weaker one. pclntab is ground truth about what the linker removed from a
// shipped artifact; a DT_NEEDED closure is ground truth only for an image that
// is fully dynamic, does not dlopen, and has a known entrypoint. Everything
// this package does that looks like conservatism -- the taints, the
// always-rooted plugin directories, the entrypoint escalation -- exists to keep
// the gap between those two situations visible instead of silently answering
// "not reachable" for an image the closure cannot actually reason about.
package elfgraph

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// ErrNotELF reports that a file is not an ELF object. It is not a failure:
// most files in an image are not ELF, and callers walking a tree skip it.
var ErrNotELF = errors.New("not an ELF file")

// elfMagic is "\x7fELF".
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// Info is what the dynamic linker reads out of one ELF file.
//
// Symbol tables are deliberately absent. An image can hold thousands of ELF
// objects and glibc alone exports a couple of thousand symbols; holding all of
// that for a question most scans never ask would cost more memory than the rest
// of a scan combined. Dlopen is precomputed because the closure needs it for
// every object, and everything else goes through Symbols on demand.
type Info struct {
	Class   elf.Class   `json:"class"`
	Machine elf.Machine `json:"machine"`
	Type    elf.Type    `json:"type"`

	// Interp is the PT_INTERP path -- the program interpreter. Empty means the
	// kernel would load this file directly, with no dynamic linker involved.
	Interp string `json:"interp,omitempty"`

	// Dynamic reports whether the file has a PT_DYNAMIC segment.
	Dynamic bool `json:"dynamic"`

	Soname  string   `json:"soname,omitempty"`
	Needed  []string `json:"needed,omitempty"`
	RPath   []string `json:"rpath,omitempty"`
	RunPath []string `json:"runpath,omitempty"`

	// Dlopen reports that this object imports dlopen or dlmopen, so its real
	// dependency set is decided at runtime by strings this package cannot read.
	Dlopen bool `json:"dlopen,omitempty"`
}

// Static reports that nothing would be dynamically loaded on this object's
// behalf.
//
// Only ask this of something you already know is an executable. A shared
// library also has no PT_INTERP, and there is no reliable way to tell a
// static-pie executable from a library by inspection alone -- both are ET_DYN
// with no interpreter. The closure only calls it on roots, which are files it
// has already concluded would be executed.
func (i *Info) Static() bool { return i.Interp == "" }

// IsProgram reports whether this object is something the kernel executes
// rather than something the loader maps.
//
// The test is PT_INTERP, which a shared library never has and a dynamic
// executable always does, plus ET_EXEC for the classic static case. It exists
// because container images keep programs well outside the PATH -- apt's
// transport methods in /usr/lib/apt/methods, git's helpers in
// /usr/lib/git-core, anything under /usr/libexec -- and those are exactly the
// programs that pull in the libraries a PATH-only scan would call dead code.
//
// Static-pie executables are missed: they are ET_DYN with no interpreter, and
// nothing structural separates them from a plugin module. Including them would
// mean classifying every dependency-free .so as a program, which is the more
// expensive mistake -- it would mark a plugin as statically linked and taint
// every image that ships one.
func (i *Info) IsProgram() bool {
	return i.Interp != "" || i.Type == elf.ET_EXEC
}

// Reader loads ELF metadata for a tree-absolute path.
//
// It is a function type so the graph algorithm can be tested against a fake
// filesystem with no ELF files in it at all. Resolution order, class matching,
// rpath inheritance and taint propagation are the parts that get details wrong;
// none of them need a real object file to exercise.
type Reader func(fsys target.RootFS, name string) (*Info, error)

// ReadELF is the real Reader, backed by debug/elf.
func ReadELF(fsys target.RootFS, name string) (*Info, error) {
	host, err := fsys.HostPath(name)
	if err != nil {
		return nil, err
	}
	if err := checkMagic(host); err != nil {
		return nil, err
	}

	f, err := elf.Open(host)
	if err != nil {
		// The magic matched, so this is a truncated or corrupt object rather
		// than an ordinary non-ELF file. Report it as such: a library that
		// fails to parse is a library whose dependencies are unknown.
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	defer f.Close()

	info := &Info{Class: f.Class, Machine: f.Machine, Type: f.Type}

	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			b, err := io.ReadAll(io.LimitReader(p.Open(), 4096))
			if err == nil {
				info.Interp = string(bytes.TrimRight(b, "\x00"))
			}
		case elf.PT_DYNAMIC:
			info.Dynamic = true
		}
	}
	if !info.Dynamic {
		return info, nil
	}

	if v, err := f.DynString(elf.DT_SONAME); err == nil && len(v) > 0 {
		info.Soname = v[0]
	}
	if v, err := f.DynString(elf.DT_NEEDED); err == nil {
		info.Needed = v
	}
	// DT_RPATH and DT_RUNPATH hold one colon-separated list per entry.
	if v, err := f.DynString(elf.DT_RPATH); err == nil {
		info.RPath = splitPathList(v)
	}
	if v, err := f.DynString(elf.DT_RUNPATH); err == nil {
		info.RunPath = splitPathList(v)
	}

	imports, err := f.ImportedSymbols()
	if err == nil {
		for _, s := range imports {
			if s.Name == "dlopen" || s.Name == "dlmopen" {
				info.Dlopen = true
				break
			}
		}
	}
	return info, nil
}

// SymbolReader loads an object's dynamic symbol table. Like Reader it is a
// function type, so that a caller's validation logic can be exercised without
// real ELF objects to hold the symbols.
type SymbolReader func(fsys target.RootFS, name string) (defined, undefined []string, err error)

// Symbols reports the dynamic symbols an object defines and the ones it expects
// someone else to define.
//
// Only global and weak symbols are returned. A local symbol cannot satisfy
// another object's reference, so its presence says nothing about whether a
// vulnerable function is callable from outside the library that holds it.
//
// This is separate from ReadELF because it is only needed for the mined-symbol
// validation path, on the handful of libraries one package installs, rather
// than for every object in an image.
func Symbols(fsys target.RootFS, name string) (defined, undefined []string, err error) {
	host, err := fsys.HostPath(name)
	if err != nil {
		return nil, nil, err
	}
	if err := checkMagic(host); err != nil {
		return nil, nil, err
	}
	f, err := elf.Open(host)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", name, err)
	}
	defer f.Close()

	syms, err := f.DynamicSymbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("dynsym %s: %w", name, err)
	}

	defSeen, undefSeen := map[string]bool{}, map[string]bool{}
	for _, s := range syms {
		if s.Name == "" {
			continue
		}
		switch elf.ST_BIND(s.Info) {
		case elf.STB_GLOBAL, elf.STB_WEAK:
		default:
			continue
		}
		// A versioned reference reads as "memcpy@GLIBC_2.14" in tooling but the
		// symbol name here is bare, which is what an advisory would name.
		if s.Section == elf.SHN_UNDEF {
			undefSeen[s.Name] = true
		} else {
			defSeen[s.Name] = true
		}
	}
	return sortedKeys(defSeen), sortedKeys(undefSeen), nil
}

func checkMagic(host string) error {
	f, err := os.Open(host)
	if err != nil {
		return err
	}
	defer f.Close()

	var hdr [4]byte
	if n, err := io.ReadFull(f, hdr[:]); err != nil || n != 4 {
		// Too short to be an ELF file. Not an error worth reporting.
		return ErrNotELF
	}
	if !bytes.Equal(hdr[:], elfMagic) {
		return ErrNotELF
	}
	return nil
}

func splitPathList(entries []string) []string {
	var out []string
	for _, e := range entries {
		for _, p := range strings.Split(e, ":") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
