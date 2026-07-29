package elfgraph

import (
	"bufio"
	"debug/elf"
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// maxLdConfIncludes bounds ld.so.conf include expansion. glibc has no such
// limit and simply recurses; a crafted image should not be able to make a
// scanner recurse with it.
const maxLdConfIncludes = 32

// ldSoConf returns the directories /etc/ld.so.conf names, in file order,
// following include directives.
//
// The real linker reads /etc/ld.so.cache, a binary file built from these paths
// by ldconfig. Reading the config instead of the cache is deliberate: the cache
// is a build artifact that images routinely ship stale or not at all, while the
// config is the declaration of intent. The difference matters in one direction
// only -- a directory in the config but missing from the cache makes this
// package consider a library the runtime would not have found, which errs
// toward reachable.
func ldSoConf(fsys target.RootFS) []string {
	var dirs []string
	seen := map[string]bool{}
	includes := 0

	var read func(name string)
	read = func(name string) {
		f, err := fsys.Open(name)
		if err != nil {
			return
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line == "" {
				continue
			}
			if rest, ok := cutPrefixFold(line, "include"); ok {
				pattern := strings.TrimSpace(rest)
				if pattern == "" {
					continue
				}
				if !path.IsAbs(pattern) {
					pattern = path.Join(path.Dir(name), pattern)
				}
				for _, inc := range globOne(fsys, pattern) {
					if includes++; includes > maxLdConfIncludes {
						return
					}
					read(inc)
				}
				continue
			}
			// Anything that is not a directive is a directory. glibc also
			// accepts "hwcap" lines, long obsolete; they are not paths and are
			// dropped by the IsAbs check.
			d := path.Clean("/" + line)
			if path.IsAbs(line) && !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
		}
	}

	read("/etc/ld.so.conf")
	return dirs
}

// globOne expands a glob whose wildcards are confined to the final path
// component, which is the only form ld.so.conf uses in practice
// ("include /etc/ld.so.conf.d/*.conf").
func globOne(fsys target.RootFS, pattern string) []string {
	dir, base := path.Split(path.Clean(pattern))
	if !strings.ContainsAny(base, "*?[") {
		if _, err := fsys.Stat(pattern); err != nil {
			return nil
		}
		return []string{path.Clean(pattern)}
	}
	entries, err := fsys.ReadDir(path.Clean(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if ok, err := path.Match(base, e.Name()); err == nil && ok {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	return out
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	rest := s[len(prefix):]
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	return rest, true
}

// defaultLibDirs is where the linker looks when nothing else matched.
//
// glibc's built-in list is short (/lib, /usr/lib, plus the 64-bit pair), and on
// Debian everything else arrives through ld.so.conf.d. The multiarch triplet
// directories are included here anyway, because a slimmed image -- distroless,
// or a scratch image with libraries copied in -- often keeps the layout and
// drops the config that describes it.
func defaultLibDirs(class elf.Class, machine elf.Machine) []string {
	dirs := []string{}
	if class == elf.ELFCLASS64 {
		dirs = append(dirs, "/lib64", "/usr/lib64")
	}
	if t := triplet(class, machine); t != "" {
		dirs = append(dirs, "/lib/"+t, "/usr/lib/"+t)
	}
	return append(dirs, "/lib", "/usr/lib", "/usr/local/lib")
}

// triplet is the GNU multiarch directory name for an ELF class and machine,
// or "" for a platform that does not use one.
func triplet(class elf.Class, machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		if class == elf.ELFCLASS32 {
			return "x86_64-linux-gnux32"
		}
		return "x86_64-linux-gnu"
	case elf.EM_386:
		return "i386-linux-gnu"
	case elf.EM_AARCH64:
		return "aarch64-linux-gnu"
	case elf.EM_ARM:
		return "arm-linux-gnueabihf"
	case elf.EM_PPC64:
		return "powerpc64le-linux-gnu"
	case elf.EM_S390:
		return "s390x-linux-gnu"
	case elf.EM_RISCV:
		return "riscv64-linux-gnu"
	case elf.EM_LOONGARCH:
		return "loongarch64-linux-gnu"
	}
	return ""
}

// platformName is what $PLATFORM expands to in an rpath, matching uname -m.
func platformName(class elf.Class, machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		if class == elf.ELFCLASS32 {
			return "i686"
		}
		return "x86_64"
	case elf.EM_386:
		return "i686"
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_ARM:
		return "armv7l"
	case elf.EM_PPC64:
		return "ppc64le"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_RISCV:
		return "riscv64"
	case elf.EM_LOONGARCH:
		return "loongarch64"
	}
	return ""
}

// libName is what $LIB expands to: the bare library directory name the platform
// puts 64-bit objects in.
func libName(class elf.Class, machine elf.Machine) string {
	if class != elf.ELFCLASS64 {
		return "lib"
	}
	switch machine {
	case elf.EM_X86_64, elf.EM_PPC64, elf.EM_S390:
		return "lib64"
	}
	// aarch64, riscv64 and the rest keep plain "lib" even at 64 bits.
	return "lib"
}

// expandRunPath substitutes the three dynamic string tokens the linker
// understands and returns tree-absolute directories.
//
// origin is the directory of the object the rpath was read from, which is what
// $ORIGIN means -- so an inherited rpath has to be expanded where it was
// defined, not where it is used.
func expandRunPath(entries []string, origin string, info *Info) []string {
	if len(entries) == 0 {
		return nil
	}
	rep := strings.NewReplacer(
		"$ORIGIN", origin, "${ORIGIN}", origin,
		"$LIB", libName(info.Class, info.Machine), "${LIB}", libName(info.Class, info.Machine),
		"$PLATFORM", platformName(info.Class, info.Machine), "${PLATFORM}", platformName(info.Class, info.Machine),
	)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		e = rep.Replace(e)
		if e == "" {
			continue
		}
		if !path.IsAbs(e) {
			// A relative rpath is resolved against the current directory at
			// exec time, which is not knowable from an image. Anchoring at the
			// object's own directory is the reading that matches how these are
			// almost always written.
			e = path.Join(origin, e)
		}
		out = append(out, path.Clean(e))
	}
	return out
}
