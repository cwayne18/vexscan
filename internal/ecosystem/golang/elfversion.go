package golang

import (
	"debug/elf"
	"strings"
)

// This file recovers a main module's version from the ELF symbol table, for the
// binaries whose build info records no linker flags to read.
//
// ldflagsversion.go is the better source and runs first, but it depends on
// build info having kept the flags -- and `-trimpath` makes Go drop them
// entirely. A build that does both, which is the norm for a reproducible
// distro rebuild, leaves ldflagsSetting nothing at all:
//
//	go build           -ldflags "-X main.version=v9.9.9"
//	  -> build -ldflags="-X main.version=v9.9.9"
//	go build -trimpath -ldflags "-X main.version=v9.9.9"
//	  -> build -trimpath=true
//
// That is go.dev/issue/63432. It is not a corner case: it silently removes the
// strongest evidence a stamped binary carries, and it does so on exactly the
// hardened rebuilds whose main module is "(devel)" to begin with. Every
// advisory ever filed against the module then lands as a false positive against
// code that is always present.
//
// The stamp itself survives. The linker materializes the string an -X
// assignment writes as a symbol named for the variable with ".str" appended --
// "main.version" is stored as "main.version.str" -- so the number is still in
// the artifact, in the symbol table rather than in the build settings. Reading
// it back is the same fact from a different place, not an inference about it,
// which is why this ranks above the image tag.
//
// The authority test is the one ldflagsversion.go already applies, for the same
// reason and through the same helpers: a big binary stamps many versions, and
// the only thing separating the main module's own from a vendored dependency's
// is whose code the variable lives in. See ownedBy. Selecting on the shape of
// the name instead would read containerd's version as k3s's.
//
// A stripped binary has no .symtab and nothing here can run. That is a real
// limit rather than an oversight -- `-ldflags "-s -w"` removes the very bytes
// this reads -- and the caller falls through to the image tag and then to
// "(devel)", which over-reports: the safe direction.

// maxVersionSymbol bounds how much of a symbol is read before deciding it is
// not a version.
//
// A stamped version is a few dozen bytes. The bound is not an optimization: the
// size comes out of the symbol table of the artifact being examined, and
// allocating whatever it asks for would be taking a number from the input on
// trust.
const maxVersionSymbol = 256

// moduleVersionFromELFSymbols returns the version modulePath's own build
// stamped into the binary at path, and the -X key it came from, both read out
// of the symbol table. Both are "" when the binary is not ELF, carries no
// symbol table, holds no such stamp, or holds more than one that disagree.
func moduleVersionFromELFSymbols(modulePath, path string) (version, key string) {
	if modulePath == "" || path == "" {
		return "", ""
	}
	stamps := elfVersionStamps(modulePath, path)
	if len(stamps) == 0 {
		return "", ""
	}
	// Same rule as moduleVersionFromLDFlags: several agreeing stamps under the
	// main module are normal, and two that disagree mean the authority test did
	// not actually single out this module's version. Choosing between them is
	// how one picks a version that is too high.
	for _, s := range stamps[1:] {
		if s.version != stamps[0].version {
			return "", ""
		}
	}
	return stamps[0].version, stamps[0].key
}

// elfVersionStamps returns every ".str" symbol in the binary that holds a
// usable version written into modulePath's own code.
func elfVersionStamps(modulePath, path string) []versionStamp {
	f, err := elf.Open(path)
	if err != nil {
		// Not an ELF file, or not a file at all. Neither is a failure worth
		// reporting: this is one of several recoveries tried in turn.
		return nil
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return nil // stripped, or otherwise carrying no .symtab
	}

	var out []versionStamp
	for i := range syms {
		sym := &syms[i]
		key, ok := strings.CutSuffix(sym.Name, ".str")
		if !ok {
			continue
		}
		pkgPath, name, ok := splitXKey(key)
		if !ok || !isVersionVar(name) || !ownedBy(pkgPath, modulePath) {
			continue
		}
		v, ok := normalizeSemver(symbolString(f, sym))
		// A project that declares `var version = "v0.0.0"` and never stamps it
		// still has the symbol; isDevelVersion catches that non-answer here as
		// it does in the flags.
		if !ok || isDevelVersion(v) {
			continue
		}
		out = append(out, versionStamp{key: key, version: v})
	}
	return out
}

// symbolString reads the string a ".str" symbol holds, or "" when the symbol
// does not describe readable data.
//
// The offset is the symbol's virtual address less its section's, the same
// arithmetic cmd/internal/objfile does. Every bound is checked rather than
// assumed -- the section index, the address falling inside the section, the
// length fitting within it -- because a symbol table is input from the artifact
// under examination, and an unreadable binary must come back empty rather than
// panic the scan.
func symbolString(f *elf.File, sym *elf.Symbol) string {
	if sym.Size == 0 || sym.Size > maxVersionSymbol {
		return ""
	}
	if int(sym.Section) >= len(f.Sections) {
		return "" // SHN_ABS, SHN_COMMON and friends index no section
	}
	sec := f.Sections[sym.Section]
	// .bss occupies no file space, so there is nothing on disk to read.
	if sec.Type == elf.SHT_NOBITS {
		return ""
	}
	if sym.Value < sec.Addr || sym.Value-sec.Addr+sym.Size > sec.Size {
		return ""
	}
	buf := make([]byte, sym.Size)
	if _, err := sec.ReadAt(buf, int64(sym.Value-sec.Addr)); err != nil {
		return ""
	}
	return strings.TrimRight(string(buf), "\x00")
}
