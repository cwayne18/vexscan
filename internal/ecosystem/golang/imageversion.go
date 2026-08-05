package golang

import (
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// isDevelVersion reports whether v is a build-info main-module version that OSV
// cannot range-match, and so must not be sent to OSV as-is.
//
// `go build` from a checkout does not stamp a semver main-module version: build
// info reports "(devel)" (or "" for some toolchains), and a project that sets
// its version through `-ldflags -X pkg.Version=...` writes a *different*
// variable that never reaches buildinfo.Main.Version. The v0.0.0 pseudo-zero is
// the other shape of the same non-answer. Any of these, or anything that is not
// valid semver at all, is uncomparable: OSV's range check has nothing to place
// it against and returns advisories already fixed in the running version.
func isDevelVersion(v string) bool {
	switch strings.TrimSpace(v) {
	case "", "(devel)", "devel":
		return true
	}
	sv := v
	if !strings.HasPrefix(sv, "v") {
		sv = "v" + sv
	}
	if !semver.IsValid(sv) {
		return true
	}
	// v0.0.0 is valid semver but is the zero a build with no tag falls back to,
	// which is no more comparable than "(devel)".
	return semver.Canonical(sv) == "v0.0.0"
}

// dockerK3sSuffix matches the k3s/rke2 build suffix as it appears in a *Docker*
// tag. Docker tags cannot contain '+', so the git/module tag "v1.36.3+k3s1"
// ships as the image tag "v1.36.3-k3s1" (and rke2 as "v1.31.5-rke2r1"). The
// anchor keeps it from touching an ordinary semver prerelease like "-rc1".
var dockerK3sSuffix = regexp.MustCompile(`-(k3s\d+|rke2r?\d+)$`)

// imageTag returns the tag portion of an image reference, or "" if it carries
// none. A digest ("@sha256:...") is stripped first, and the registry host and
// port are skipped by isolating the final path component before splitting on
// ':' -- so "registry:5000/rancher/k3s:v1.36.3-k3s1" yields "v1.36.3-k3s1", not
// "5000/rancher/k3s:v1.36.3-k3s1".
func imageTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	name := ref
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// moduleVersionFromImageTag derives a comparable Go module version from an image
// reference's tag, returning the version, the raw tag it came from, and whether
// a version could be derived at all.
//
// It is deliberately conservative: a wrong-but-higher version would mark a
// genuinely vulnerable finding as fixed, the one failure direction this tool
// must never take silently. So it infers only when the tag is a plausible
// semver -- "latest", a bare digest, an empty tag, or a date-stamp yields
// ok=false and no guess. The k3s/rke2 suffix is converted back to its '+' form
// so it matches the versions those advisories are actually filed under.
func moduleVersionFromImageTag(ref string) (version, tag string, ok bool) {
	tag = imageTag(ref)
	if tag == "" || tag == "latest" {
		return "", tag, false
	}
	v := dockerK3sSuffix.ReplaceAllString(tag, "+$1")
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return "", tag, false
	}
	// semver.IsValid accepts partials ("v1", "v1.2") and a bare major, so a
	// date-stamp tag like "20240101" would pass as "v20240101". A module
	// version that could be mistaken for something newer than it is is exactly
	// the under-report risk this must avoid, so require a full MAJOR.MINOR.PATCH
	// core before trusting the tag.
	core := v[1:]
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	if strings.Count(core, ".") != 2 {
		return "", tag, false
	}
	return v, tag, true
}
