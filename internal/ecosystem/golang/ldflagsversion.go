package golang

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// This file recovers a main module's real version from the linker flags the
// build used to stamp it.
//
// A binary built from a checkout has no comparable main-module version: build
// info reports "(devel)" (see isDevelVersion), so OSV cannot range-match it and
// answers with every advisory ever filed against the module, including the ones
// fixed years before the build. The project usually does know its version -- it
// just writes it somewhere else:
//
//	go build -ldflags "-X github.com/k3s-io/k3s/pkg/version.Version=v1.36.2+k3s1"
//
// That never reaches buildinfo.Main.Version, but the flags themselves are kept
// verbatim in the "-ldflags" build setting, so the number is right there in the
// artifact. Reading it is strictly better evidence than the image tag: it was
// written by the build that produced this binary, not inferred from what
// somebody later called the image it ended up in.
//
// The hazard is the same one tagAuthority exists for. A stamp naming too high a
// version would range past a real advisory and report a vulnerable binary as
// clean, which is the one direction this tool must never go silently. Big
// binaries stamp many versions -- the k3s binary carries six that look like a
// version, for cri-tools, containerd, flannel, kube-router and cri-dockerd
// alongside its own -- and picking the wrong one is not a near miss.
//
// So the authority test is the variable's own import path: the stamp counts
// only when it writes into the main module's code, or into package main, which
// by definition belongs to the binary being built. On the k3s binary exactly
// one of the six survives that, and it is the right one. Anything short of a
// single unambiguous answer falls through to the image tag and then to
// "(devel)", which over-reports -- the safe direction.
//
// This is deliberately narrower than trivy, which selects by the *shape* of the
// variable name (a "main"/"common"/"version"/"cmd" prefix) rather than by whose
// code it lives in. Five of k3s's six stamps end in "/version.Version", so that
// rule finds five candidates, cannot choose, and gives up: trivy reports the
// k3s main module with no version at all and therefore no findings against it,
// true or false. Owning package is the discriminator that actually separates
// them.

// ldflagsX matches one -X assignment in a linker-flag string, in each of the
// spellings `go build` accepts: `-X k=v`, `-X=k=v`, and either with the pair
// wrapped in single or double quotes. The leading boundary keeps it from
// matching inside a longer flag, and the alternation captures the whole `k=v`
// token so the split below sees it with quotes already removed.
var ldflagsX = regexp.MustCompile(`(?:^|\s)-X[ =]+(?:'([^']*)'|"([^"]*)"|(\S+))`)

// versionStamp is one -X assignment that survived every authority test.
type versionStamp struct {
	key     string // the full -X key, e.g. "github.com/k3s-io/k3s/pkg/version.Version"
	version string // the normalized version it assigns
}

// moduleVersionFromLDFlags returns the version modulePath's own build stamped
// into the binary, and the -X key it came from. Both are "" when the flags
// carry no such stamp or carry more than one and disagree.
func moduleVersionFromLDFlags(modulePath string, settings []debug.BuildSetting) (version, key string) {
	if modulePath == "" {
		return "", ""
	}
	stamps := versionStamps(modulePath, ldflagsSetting(settings))
	if len(stamps) == 0 {
		return "", ""
	}
	// Several stamps under the main module are normal -- a project may write
	// both `main.version` and its own version package -- and harmless while they
	// agree. Two different answers means the rule above did not actually pick
	// out the module's version, and guessing between them is exactly the way to
	// choose one that is too high.
	for _, s := range stamps[1:] {
		if s.version != stamps[0].version {
			return "", ""
		}
	}
	return stamps[0].version, stamps[0].key
}

// versionStamps returns every -X assignment in flags that writes a usable
// version into modulePath's own code, in the order the flags list them.
func versionStamps(modulePath, flags string) []versionStamp {
	if flags == "" {
		return nil
	}
	var out []versionStamp
	for _, m := range ldflagsX.FindAllStringSubmatch(flags, -1) {
		// Exactly one of the three alternatives can have matched, so the
		// concatenation is that one; the others are empty.
		key, value, ok := strings.Cut(m[1]+m[2]+m[3], "=")
		if !ok {
			continue
		}
		// A build may quote just the value rather than the whole pair, which
		// leaves the quotes inside the token the regexp captured.
		key = strings.Trim(key, `'"`)
		value = strings.Trim(value, `'"`)

		pkgPath, name, ok := splitXKey(key)
		if !ok || !isVersionVar(name) || !ownedBy(pkgPath, modulePath) {
			continue
		}
		v, ok := normalizeSemver(value)
		// isDevelVersion catches the v0.0.0 a build with no tag falls back to,
		// which is stamped often enough to matter and is no more comparable than
		// the "(devel)" it would be replacing.
		if !ok || isDevelVersion(v) {
			continue
		}
		out = append(out, versionStamp{key: key, version: v})
	}
	return out
}

// ldflagsSetting returns the verbatim linker flags recorded in build info, or
// "" if the build recorded none.
func ldflagsSetting(settings []debug.BuildSetting) string {
	for _, s := range settings {
		if s.Key == "-ldflags" {
			return s.Value
		}
	}
	return ""
}

// splitXKey splits an -X key into the import path holding the variable and the
// variable's own name: "github.com/k3s-io/k3s/pkg/version.Version" is the
// variable Version in package .../pkg/version, and "main.version" is version in
// package main.
//
// The split is at the last '.' *after* the last '/', because a module path can
// carry dots of its own -- "k8s.io/client-go/pkg/version.gitVersion" must not
// split at the dot in "k8s.io".
func splitXKey(key string) (pkgPath, name string, ok bool) {
	slash := strings.LastIndex(key, "/")
	dot := strings.LastIndex(key[slash+1:], ".")
	if dot < 0 {
		return "", "", false
	}
	dot += slash + 1
	if dot == 0 || dot == len(key)-1 {
		return "", "", false
	}
	return key[:dot], key[dot+1:], true
}

// isVersionVar reports whether a stamped variable's name says it holds the
// project's version.
//
// Only the exact names, not everything containing "version". A build that
// stamps "goVersion" or "buildVersion" is saying something else, and a wrong
// version here reads too high and hides a real finding, so a name that is not
// unmistakably the version is left to the fallbacks.
func isVersionVar(name string) bool {
	switch strings.ToLower(name) {
	case "version", "ver":
		return true
	}
	return false
}

// ownedBy reports whether an import path is code the main module owns.
//
// This is the whole authority test. Package main is always the binary's own, so
// a "-X main.version" stamp is by construction about the thing being built.
// Otherwise the variable has to live in the main module's own tree: a stamp
// into a dependency's version package -- containerd's, flannel's, cri-tools'
// -- states that dependency's version, and reading it as the main module's
// would be off by an entire project.
func ownedBy(pkgPath, modulePath string) bool {
	return pkgPath == "main" ||
		pkgPath == modulePath ||
		strings.HasPrefix(pkgPath, modulePath+"/")
}
