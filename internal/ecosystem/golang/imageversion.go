package golang

import (
	"fmt"
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

// imageRepo returns the repository name of an image reference with the registry
// host, path prefix, tag and digest stripped: "rancher/k3s:v1.36.3-k3s1" and
// "registry:5000/rancher/k3s" both yield "k3s".
func imageRepo(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	name := ref
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i >= 0 {
		name = name[:i]
	}
	return name
}

// majorSuffix matches the major-version element a module path takes from v2 on:
// "github.com/foo/bar/v2" is the module "bar", not a module called "v2".
var majorSuffix = regexp.MustCompile(`^v[0-9]+$`)

// moduleName is the last meaningful element of a module path -- the project's
// own name, which is what an image is usually named after.
func moduleName(modulePath string) string {
	parts := strings.Split(strings.Trim(modulePath, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && !majorSuffix.MatchString(parts[i]) {
			return parts[i]
		}
	}
	return ""
}

// projectBuildSuffix matches a k3s/rke2 build-metadata suffix on an already
// normalized version ("v1.36.3+k3s1"). Those strings appear in no version but
// those projects' own.
var projectBuildSuffix = regexp.MustCompile(`\+(k3s\d+|rke2r?\d+)$`)

// tagAuthority reports why an image tag may be read as this main module's own
// version, and "" when it may not be.
//
// This is the gate that keeps the fallback from guessing. An image tag is the
// main module's version only when the image is that project's own image; there
// is nothing about "python:3.12.1" that makes 3.12.1 the version of a Go binary
// that happens to be inside it. Inferring one anyway can read *too high*, which
// marks a genuinely vulnerable finding as fixed -- the one direction this tool
// must never take. So a plausible semver tag is necessary and not sufficient,
// and one of two things has to establish that the tag is talking about the
// module in hand:
//
//   - The tag carries a k3s/rke2 build suffix. "+k3s1" and "+rke2r1" are not
//     general semver decoration; they are those projects' own release marker,
//     and a tag carrying one is that project's version whatever the image is
//     called -- including a private mirror or a retag.
//   - The image is named after the module. "rancher/k3s" for
//     github.com/k3s-io/k3s, "prom/prometheus" for github.com/prometheus/
//     prometheus. A dash-separated token counts, so rancher's
//     "hardened-kubernetes" still names k8s.io/kubernetes.
//
// Neither is proof, and the second is the weaker: an image can be named after
// the project and still be tagged with something other than the binary's
// version. That residual risk is what the provenance note on every inferred
// finding is for. What this rules out is the case where there was never any
// reason to connect the two at all.
func tagAuthority(modulePath, ref, version string) string {
	if projectBuildSuffix.MatchString(version) {
		return "the tag carries that project's own build suffix"
	}
	name := moduleName(modulePath)
	repo := imageRepo(ref)
	if name == "" || repo == "" {
		return ""
	}
	if strings.EqualFold(repo, name) {
		return fmt.Sprintf("the image is named after the module (%s)", name)
	}
	for _, tok := range strings.Split(repo, "-") {
		if strings.EqualFold(tok, name) {
			return fmt.Sprintf("the image name contains the module name (%s)", name)
		}
	}
	return ""
}

// normalizeTagVersion turns an image tag into a comparable Go module version,
// or reports that it is not one.
//
// "latest", a bare digest, an empty tag and a date-stamp all yield ok=false and
// no guess. The k3s/rke2 suffix is converted back to its '+' form so it matches
// the versions those advisories are actually filed under.
func normalizeTagVersion(tag string) (string, bool) {
	if tag == "" || tag == "latest" {
		return "", false
	}
	v := dockerK3sSuffix.ReplaceAllString(tag, "+$1")
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return "", false
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
		return "", false
	}
	return v, true
}

// moduleVersionFromImageTag derives a comparable Go module version for
// modulePath from an image reference's tag, returning the version, the raw tag
// it came from, and why the tag was trusted ("" when it was not, and so no
// version could be derived).
//
// Two independent conditions have to hold, and both exist for the same reason:
// a wrong-but-higher version would mark a genuinely vulnerable finding as
// fixed, the one failure direction this tool must never take silently. The tag
// has to *be* a version (normalizeTagVersion), and it has to be a version of
// *this module* (tagAuthority). A clean semver tag on an image that has nothing
// to do with the module -- a Go binary sitting inside python:3.12.1 -- passes
// the first and fails the second.
func moduleVersionFromImageTag(modulePath, ref string) (version, tag, why string) {
	tag = imageTag(ref)
	v, ok := normalizeTagVersion(tag)
	if !ok {
		return "", tag, ""
	}
	why = tagAuthority(modulePath, ref, v)
	if why == "" {
		return "", tag, ""
	}
	return v, tag, why
}
