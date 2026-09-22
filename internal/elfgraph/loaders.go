package elfgraph

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// A reachable object that imports dlopen taints globally because what it loads
// is chosen at runtime from strings this package cannot read, so the closure is
// only a lower bound. That is the right default for an arbitrary caller: an
// application binary can dlopen anything.
//
// But a handful of loaders are not arbitrary. A known library dlopens plugins
// from a fixed, documented set of directories -- and those are the very
// directories alwaysRoot already roots and the closure already walks. For such
// a caller the closure is not a lower bound at all: everything it could load is
// already in it. Its dlopen taint can be recorded rather than allowed to block,
// without asserting the blanket --dlopen-policy=assume-none over every other
// caller in the image.
//
// The entire risk of this file is a loader that is bounded in name only -- one
// that can be pointed somewhere outside its known dirs. A loaderFamily is
// therefore a claim with three parts, and the discharge is refused unless all
// three are proven for the specific image in front of us (see
// boundedDlopenReason):
//
//  1. the caller is matched by SONAME against a strict allowlist, never by a
//     path or basename heuristic -- being installed at a plugin path says
//     nothing about what a library does at runtime;
//  2. nothing redirects the loader outside its known dirs: neither an
//     environment variable set in the image config nor, for a family that can
//     be aimed by a config file alone, that file; and
//  3. at least one of those known dirs is actually present and rooted in this
//     graph, so the mechanism the discharge depends on -- alwaysRoot having
//     pulled the plugins into the closure -- demonstrably fired here rather
//     than being assumed to have.
//
// When any part cannot be shown, the caller keeps the global blocking taint. It
// is far better to discharge fewer callers with certainty than to over-claim
// one, because the one failure mode this whole package exists to prevent is a
// false "not reachable" about code that is.
//
// What a discharge claims is narrow, and worth stating so it is not read as
// more: everything this loader can *dlopen* is already in the closure. It says
// nothing about what a plugin goes on to exec -- pam_exec.so runs an arbitrary
// program, and the process tree is what TaintExec is for, not this file.
type loaderFamily struct {
	// name is what the evidence line calls the family, e.g. "OpenSSL".
	name string

	// sonames are the DT_SONAME prefixes that identify a caller in this family.
	// Prefixes rather than exact names because the soname carries the ABI
	// version -- libcrypto.so.3, libcrypto.so.1.1 -- and the loader behaviour is
	// the same across them. This is still a strict match on the soname the
	// object declares about itself, not a guess from where it sits on disk.
	sonames []string

	// pluginDirs are path fragments marking the directories this family loads
	// from. They are a subset of what alwaysRoot roots, which is what makes the
	// closure a complete account of what the loader can reach: every plugin in
	// them is already a root. Matched as a substring of a rooted plugin node's
	// path, the same way alwaysRoot recognises them.
	pluginDirs []string

	// redirectEnv are the environment variables that move the search outside
	// pluginDirs. If the image config sets any of them, the closure is no
	// longer a complete account of what the loader loads -- the plugins could
	// come from a directory nothing rooted -- so the discharge is refused and
	// the caller stays blocking. Empty for a family with no such variable.
	redirectEnv []string

	// configRedirect optionally reports an out-of-band redirect that an
	// environment variable cannot express: a config file that names a plugin by
	// absolute path. It is what keeps the env check from being a false bound --
	// OpenSSL's providers and engines can be pointed outside their dirs by
	// openssl.cnf alone, with no variable set, and the dlopen taint is exactly
	// what protects against that today. Nil means the family has no such vector.
	// It is consulted only after the env check passes, and a true result keeps
	// the caller blocking.
	configRedirect func(fsys target.RootFS) bool

	// configWhat names, for the evidence line, what configRedirect read. A
	// discharge that rests on a config scan must say which config it scanned:
	// "no openssl.cnf redirects them" is auditable, "it is bounded" is not.
	configWhat string
}

// loaderFamilies is the allowlist. It is deliberately short. A family earns a
// place only when its bound is strong and every way of escaping that bound is
// checkable from the image alone.
//
// Families deliberately excluded, and why, so the next reader does not have to
// rediscover it:
//
//   - glibc NSS and gconv are loaded by libc.so.6 internally. libc *defines*
//     dlopen rather than importing it, so it is never flagged as a dlopen
//     caller (see elf.go) and never raises the taint -- there is nothing here
//     to discharge, and their redirect vectors (nsswitch.conf, GCONV_PATH) do
//     not matter for this file.
//   - libselinux's dlopen target set is narrow but not well enough understood
//     here to bound with confidence, and an uncertain bound is not a bound.
var loaderFamilies = []loaderFamily{
	{
		// libcrypto dlopens providers from */ossl-modules/ and engines from
		// */engines-*/, both of which alwaysRoot roots. The ways to redirect it
		// -- OPENSSL_MODULES, OPENSSL_ENGINES, and OPENSSL_CONF naming an
		// alternative config -- are all environment variables this package can
		// read, plus openssl.cnf itself. libssl is listed too: it belongs to the
		// same mechanism, and on a build where it, rather than libcrypto, is the
		// object that imports dlopen, it is the caller that needs discharging.
		name:           "OpenSSL",
		sonames:        []string{"libcrypto.so.", "libssl.so."},
		pluginDirs:     []string{"/ossl-modules/", "/engines-"},
		redirectEnv:    []string{"OPENSSL_MODULES", "OPENSSL_ENGINES", "OPENSSL_CONF"},
		configRedirect: opensslConfigRedirects,
		configWhat:     "openssl.cnf",
	},
	{
		// libpam dlopens modules from */security/, which alwaysRoot roots as the
		// PAM plugin family. No environment variable moves that search: the
		// directory is compiled in. The one thing that escapes it is a pam.d
		// stanza naming a module by absolute path, which pamConfigRedirects
		// refuses to reason past.
		name:           "PAM",
		sonames:        []string{"libpam.so."},
		pluginDirs:     []string{"/security/"},
		configRedirect: pamConfigRedirects,
		configWhat:     "pam configuration",
	},
}

// opensslConfigPaths are where the active OpenSSL configuration lives when
// OPENSSL_CONF does not name one. It is the compiled-in OPENSSLDIR/openssl.cnf,
// which differs by distribution family:
//
//   - Debian, Ubuntu, SUSE and Alpine build with OPENSSLDIR=/usr/lib/ssl, and
//     ship /etc/ssl as the config dir with /usr/lib/ssl/openssl.cnf usually a
//     symlink to /etc/ssl/openssl.cnf;
//   - RHEL, CentOS, Fedora, Rocky, Alma and the UBI base images build with
//     OPENSSLDIR=/etc/pki/tls, so the active config is /etc/pki/tls/openssl.cnf
//     and those images do not ship /etc/ssl/openssl.cnf at all.
//
// Omitting the RHEL path would be a false-removal hole on the most common
// enterprise base images: both other paths miss, the scan reads nothing, and
// libcrypto discharges without ever having looked at the config OpenSSL loads.
// OPENSSL_CONF itself is not among these because it is in redirectEnv: an image
// that sets it has already failed the env check and never reaches this function.
var opensslConfigPaths = []string{
	"/etc/ssl/openssl.cnf",
	"/usr/lib/ssl/openssl.cnf",
	"/etc/pki/tls/openssl.cnf",
}

// opensslConfigRedirects reports whether the image's OpenSSL config could load a
// provider or engine from outside the rooted plugin dirs. It is deliberately a
// cheap, conservative scan rather than a parser: it does not resolve any path,
// it only refuses to reason about a config that overrides where modules come
// from.
//
// The default, name-based config -- `legacy = legacy_sect`, activate flags, no
// absolute paths -- maps provider and engine *names* into the rooted dirs, which
// is the assumption vexscan already makes by rooting exactly those dirs, so it
// clears. Anything that could point elsewhere keeps the caller blocking:
//
//   - `module = /path` sets a provider's module path explicitly;
//   - `dynamic_path = /path` / `SO_PATH = /path` name a dynamic ENGINE's .so;
//   - `MODULESDIR` overrides the provider search directory;
//   - any directive whose value is an absolute path ending in .so/.so.N;
//   - `.include` delegates to a file this scan does not read, which could carry
//     any of the above -- so a config that uses it is treated as overriding,
//     rather than followed, which would be the parser this guard avoids being.
//
// Every candidate path that exists is scanned, not just the first: a stale
// /etc/ssl/openssl.cnf left beside the RHEL config must not shadow the one
// OpenSSL actually reads, and any of them redirecting is enough to block. A
// config present but unreadable is treated as an override too -- the safe
// direction when the contents cannot be checked is to keep blocking. A config
// absent everywhere is not an override: OpenSSL falls back to name-based
// loading from the compiled-in modulesdir, which is rooted, so it clears.
func opensslConfigRedirects(fsys target.RootFS) bool {
	for _, p := range opensslConfigPaths {
		data, err := fsys.ReadFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			// Present but unreadable: cannot verify it does not override, so
			// stay blocking.
			return true
		}
		if configNamesModulePath(data) {
			return true
		}
	}
	return false
}

// pamDir is the directory of per-service PAM stanzas, and pamConf the single
// file that predates it. Both are read: a system with /etc/pam.d still honours
// /etc/pam.conf for services the directory does not cover.
const (
	pamDir  = "/etc/pam.d"
	pamConf = "/etc/pam.conf"
)

// pamConfigRedirects reports whether this image's PAM configuration could load a
// module from outside the rooted */security/ directories.
//
// The bound PAM offers is unusually clean -- the module directory is compiled
// in, and no environment variable moves it -- so the only escape is a stanza
// that names a module by absolute path, which libpam loads verbatim:
//
//	auth optional /opt/vendor/pam_vendor.so
//
// Every file under /etc/pam.d is read, plus /etc/pam.conf, and a single absolute
// module path in any of them keeps libpam blocking. Following @include would
// mean tracking which services are actually used, which is a runtime question;
// reading the whole directory answers it without having to.
//
// Absent configuration is not a redirect. A libpam with no stanzas at all loads
// no module, so there is nothing outside the closure for it to reach. A
// directory or file that exists but cannot be read is a redirect, on the same
// fail-closed rule as the OpenSSL scan: the safe direction when the contents
// cannot be checked is to keep blocking.
func pamConfigRedirects(fsys target.RootFS) bool {
	if redirects, ok := pamFileRedirects(fsys, pamConf); ok && redirects {
		return true
	}
	ents, err := fsys.ReadDir(pamDir)
	if err != nil {
		// Absent is fine; anything else means the stanzas cannot be checked.
		return !errors.Is(err, fs.ErrNotExist)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if redirects, ok := pamFileRedirects(fsys, path.Join(pamDir, e.Name())); ok && redirects {
			return true
		}
	}
	return false
}

// pamFileRedirects scans one PAM file. It reports whether the file redirects,
// and whether there was a file to scan at all -- an absent one is not a
// redirect, an unreadable one is.
func pamFileRedirects(fsys target.RootFS, p string) (redirects, present bool) {
	data, err := fsys.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, false
		}
		return true, true
	}
	for _, line := range configLogicalLines(data) {
		// A PAM stanza is `type control module-path args`, where control may be
		// a bracketed list containing spaces. Rather than parse the grammar,
		// look for what actually matters: any token that is an absolute path to
		// a shared object. A module named bare -- pam_unix.so -- resolves inside
		// the rooted security dir and is exactly what the discharge assumes.
		if valueNamesAbsoluteSharedObject(line) {
			return true, true
		}
	}
	return false, true
}

// configNamesModulePath scans an OpenSSL config for any directive that could
// load a module from an absolute path outside the rooted dirs. Comments are
// stripped, line continuations are joined the way NCONF joins them, and the
// match is case-insensitive; a false positive only costs a discharge, while a
// false negative would be a false removal, so the scan errs toward matching.
func configNamesModulePath(data []byte) bool {
	for _, line := range configLogicalLines(data) {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, ".include"):
			return true
		case strings.Contains(line, "modulesdir"),
			strings.Contains(line, "dynamic_path"),
			strings.Contains(line, "so_path"):
			return true
		}
		if key, val, found := strings.Cut(line, "="); found {
			if k := strings.TrimSpace(key); k == "module" {
				return true
			}
			// Any directive pointing at an absolute shared object, whatever the
			// key is called -- SO_PATH, module, a vendor-specific ctrl -- means
			// a plugin loaded from a path the closure did not walk.
			if valueNamesAbsoluteSharedObject(val) {
				return true
			}
		}
	}
	return false
}

// configLogicalLines splits a config into logical lines, first joining physical
// lines that a backslash continues and stripping `#` comments. Both OpenSSL's
// NCONF and PAM honour the continuation, so a directive split across two
// physical lines -- `dynamic_pa\`<newline>`th = /evil.so` -- is one directive at
// load time; a scan that only saw the physical lines would match neither half
// and wave it through.
func configLogicalLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(line[:len(line)-1])
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// valueNamesAbsoluteSharedObject reports whether a value is, or contains, an
// absolute path to a shared object. It is the catch-all behind the named
// keywords: a dynamic engine can be aimed with SO_PATH, a provider with module,
// a PAM stanza with nothing but the path, and vendors add their own ctrls, but
// they all end in an absolute .so/.so.N that the rooted plugin dirs would not
// have supplied.
func valueNamesAbsoluteSharedObject(val string) bool {
	for _, tok := range strings.FieldsFunc(val, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ':' || r == ';' || r == '"' || r == '\'' ||
			r == '[' || r == ']' || r == '='
	}) {
		if !strings.HasPrefix(tok, "/") {
			continue
		}
		if strings.HasSuffix(tok, ".so") || strings.Contains(tok, ".so.") {
			return true
		}
	}
	return false
}

// boundedLoader returns the family a soname belongs to, if any. The match is on
// the object's own DT_SONAME, which is the identity claim the library makes
// about itself, so a random .so copied into a plugin directory cannot borrow a
// discharge it did not earn.
func boundedLoader(soname string) (loaderFamily, bool) {
	if soname == "" {
		return loaderFamily{}, false
	}
	base := path.Base(soname)
	for _, fam := range loaderFamilies {
		for _, pre := range fam.sonames {
			if strings.HasPrefix(base, pre) {
				return fam, true
			}
		}
	}
	return loaderFamily{}, false
}

// redirected reports whether the image config sets any environment variable
// that moves this family's search outside its known plugin dirs. A single one
// set is enough to refuse the discharge: it means the closure can no longer be
// trusted to hold everything the loader reaches.
func (fam loaderFamily) redirected(c target.ImageConfig) bool {
	for _, key := range fam.redirectEnv {
		if _, ok := c.LookupEnv(key); ok {
			return true
		}
	}
	return false
}

// reason is the evidence clause for a discharged caller. It names the family,
// the directories the bound rests on, and what was checked to establish that
// nothing escapes them -- so a reader can see which of the two guards did the
// work, and go look at the same file.
func (fam loaderFamily) reason(dirs []string) string {
	sort.Strings(dirs)
	s := "it is " + fam.name + ", whose plugins load only from the " +
		strings.Join(dirs, ", ") + " directories this image roots and the closure already walked"
	switch {
	case len(fam.redirectEnv) > 0 && fam.configWhat != "":
		s += ", and neither " + strings.Join(fam.redirectEnv, "/") + " nor this image's " +
			fam.configWhat + " redirects them"
	case len(fam.redirectEnv) > 0:
		s += ", and no " + strings.Join(fam.redirectEnv, "/") + " redirects them"
	case fam.configWhat != "":
		s += ", and this image's " + fam.configWhat + " names no module outside them"
	}
	return s
}
