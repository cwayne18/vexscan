// Package binscan inspects Go binaries on disk. It reuses the two
// stripping-tolerant techniques from the rke2-toolbox vex_candidates.py script:
//
//  1. pclntab presence test (primary): a Go binary keeps its function-name
//     table even when fully stripped (-ldflags=-s -w). If a vulnerable
//     package's own symbols never appear, the linker dead-code-eliminated it.
//  2. govulncheck binary mode (secondary, non-stripped binaries only): a
//     linked-but-unreachable package is reported not_affected.
//
// Module versions are read directly from each binary's embedded build info, so
// no external Trivy report is required.
package binscan

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/cwayne18/vexscan/internal/target"
)

// Binary is a discovered Go binary and its embedded build info. Path is a host
// path, because the two things done with it afterwards -- reading the whole
// file for pclntab tests, and handing it to govulncheck -- are not
// tree-relative operations.
type Binary struct {
	Path string
	Info *buildinfo.BuildInfo
}

// FindGoBinaries walks the tree and returns every Go binary in it. Non-Go and
// unreadable files are skipped.
//
// It goes through RootFS rather than walking the host directory directly for
// two reasons that only show up outside image mode. A subtree this walk cannot
// enter is recorded rather than dropped -- a Go binary nobody looked at is a
// module the report never mentions, which reads exactly like a module with no
// advisories against it. And a tree captured from a running system has /proc
// in it, whose synthetic entries stat as regular files and would each be
// opened and sniffed.
func FindGoBinaries(fsys target.RootFS) []Binary {
	var out []Binary
	_ = fsys.Walk("/", func(name string, d fs.DirEntry) error {
		if d.IsDir() {
			if target.IsKernelFS(name) {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks are not followed: Walk visits every regular file exactly
		// once under its own path, so a binary reachable under three names is
		// still one binary.
		if !d.Type().IsRegular() {
			return nil
		}
		host, err := fsys.HostPath(name)
		if err != nil {
			return nil
		}
		if !looksExecutable(host) {
			return nil
		}
		info, err := buildinfo.ReadFile(host)
		if err != nil || info == nil {
			return nil
		}
		out = append(out, Binary{Path: host, Info: info})
		return nil
	})
	return out
}

// looksExecutable cheaply pre-filters by magic bytes so buildinfo.ReadFile is
// only attempted on plausible executables (ELF, Mach-O, PE).
func looksExecutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	switch {
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F': // ELF
		return true
	case magic[0] == 'M' && magic[1] == 'Z': // PE
		return true
	case magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe: // Mach-O 64 LE
		return true
	case magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && magic[3] == 0xcf: // Mach-O 64 BE
		return true
	}
	return false
}

// StdlibModule is the module name the Go vulnerability database and govulncheck
// use for the standard library. Its "version" is the Go toolchain version.
const StdlibModule = "stdlib"

// ModuleVersion returns the version of module as linked into the binary, or ""
// if the module is not a dependency. It checks the main module, direct/indirect
// deps and honours replace directives. For the standard library (StdlibModule)
// it returns the binary's Go toolchain version, since stdlib is not listed as a
// dependency.
func (b Binary) ModuleVersion(module string) string {
	if b.Info == nil {
		return ""
	}
	if module == StdlibModule || module == "std" {
		return NormalizeGoVersion(b.Info.GoVersion)
	}
	if b.Info.Main.Path == module && b.Info.Main.Version != "" {
		return b.Info.Main.Version
	}
	for _, dep := range b.Info.Deps {
		m := dep
		if dep.Replace != nil {
			m = dep.Replace
		}
		if m.Path == module {
			return m.Version
		}
		// A replace can retarget a different path to this module.
		if dep.Path == module {
			return m.Version
		}
	}
	return ""
}

// NormalizeGoVersion turns a build-info Go version string ("go1.24.0", or
// "go1.24.0 X:boringcrypto") into the numeric version OSV expects ("1.24.0").
// It returns "" for development builds whose version is not a released tag.
func NormalizeGoVersion(v string) string {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return ""
	}
	ver := fields[0]
	if !strings.HasPrefix(ver, "go") {
		return "" // e.g. "devel ..." — no released stdlib version to match
	}
	return strings.TrimPrefix(ver, "go")
}

// Symbols is a loaded copy of a binary's bytes used for pclntab presence tests.
type Symbols struct {
	blob []byte
}

// LoadSymbols reads the binary once for later presence checks.
func LoadSymbols(path string) (*Symbols, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &Symbols{blob: b}, nil
}

// PackagePresent reports whether pkg's own functions appear in the binary.
// It matches `pkg.<ident>` exactly so a parent package match does not leak from
// a child (e.g. .../ssh vs .../ssh/agent).
func (s *Symbols) PackagePresent(pkg string) bool {
	re := regexp.MustCompile(regexp.QuoteMeta(pkg) + `\.[A-Za-z(]`)
	return re.Match(s.blob)
}

// ModulePresent reports whether any part of module (root or a sub-package)
// appears in the binary. Used as a coarse fallback when OSV lists no
// package-level import paths.
func (s *Symbols) ModulePresent(module string) bool {
	re := regexp.MustCompile(regexp.QuoteMeta(module) + `[./]`)
	return re.Match(s.blob)
}

// IsStripped reports whether an ELF Go binary carries no symbol table. Non-ELF
// binaries are treated as stripped (conservative: skips govulncheck binary
// mode, which over-reports without symbols).
func IsStripped(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return true
	}
	return len(syms) == 0
}

// openVEXDoc is the subset of the OpenVEX schema govulncheck emits.
type openVEXDoc struct {
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
			ID   string `json:"@id"`
		} `json:"vulnerability"`
		Status string `json:"status"`
	} `json:"statements"`
}

// GovulncheckNotAffected runs govulncheck in binary mode and returns the set of
// vulnerability ids it marks not_affected. Best effort: returns an empty set if
// govulncheck is unavailable or errors.
func GovulncheckNotAffected(ctx context.Context, path string) map[string]struct{} {
	out := map[string]struct{}{}
	if _, err := exec.LookPath("govulncheck"); err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "govulncheck", "-mode", "binary", "-format", "openvex", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		// govulncheck exits non-zero when vulns are found; still parse stdout.
		if stdout.Len() == 0 {
			return out
		}
	}
	if strings.TrimSpace(stdout.String()) == "" {
		return out
	}
	var doc openVEXDoc
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return out
	}
	for _, st := range doc.Statements {
		if st.Status != "not_affected" {
			continue
		}
		if st.Vulnerability.Name != "" {
			out[st.Vulnerability.Name] = struct{}{}
		}
		if st.Vulnerability.ID != "" {
			out[st.Vulnerability.ID] = struct{}{}
		}
	}
	return out
}
