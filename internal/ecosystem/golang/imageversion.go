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
// variable that never reaches buildinfo.Main.Version -- see ldflagsversion.go,
// which reads that variable back. The v0.0.0 pseudo-zero is the other shape of
// the same non-answer. Any of these, or anything that is not valid semver at
// all, is uncomparable: OSV's range check has nothing to place it against and
// returns advisories already fixed in the running version.
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

// dockerRelSuffix matches a distro packaging release on the end of a *Docker*
// tag. SUSE ships KubeVirt 1.8.4 as "1.8.4-11.14": 1.8.4 is the upstream
// version the binary was built from and 11.14 is SUSE's package release, the
// same two-part spelling an RPM uses.
//
// Semver reads that suffix as a *prerelease*, and a prerelease sorts BELOW the
// release it hangs off: "v1.8.4-11.14" < "v1.8.4". So an advisory fixed in the
// very version the tag names still matches a build that already contains the
// fix. Rewriting the suffix as build metadata is what the k3s/rke2 rule above
// already does for the same reason, and semver ignores build metadata in
// precedence, so "v1.8.4+11.14" compares equal to the version the tag names.
//
// Measured against api.osv.dev at real fix boundaries, asking the same question
// three ways -- the extra rows are advisories already fixed at that version:
//
//	kubevirt.io/kubevirt @ 1.6.1   v1.6.1 13   v1.6.1-11.14 22   v1.6.1+11.14 13
//	kubevirt.io/kubevirt @ 1.5.3   v1.5.3 15   v1.5.3-11.14 23   v1.5.3+11.14 15
//	github.com/k3s-io/k3s @ 1.33.10  v.. 2     v..-11.14     3   v..+11.14     2
//
// Note what this does *not* fix. The image that exposed it,
// virt-operator:1.8.4-11.14, reports five kubevirt.io/kubevirt findings, and
// the rewrite clears none of them: 1.8.4 sits above every published kubevirt
// fix, and those five advisories carry no fixed version at all, so no ordering
// could separate them. The bug is real and this corrects it; that image is
// simply not where it bites.
//
// Note the direction. This reads *up*, from below-1.8.4 to equal-1.8.4, and up
// is the direction that can hide a real finding -- so it is the one rule here
// that is not purely conservative, and it is fenced on both sides.
//
// Letters are excluded, which keeps it off every ordinary prerelease: "-rc1",
// "-beta.2" and "-build20260724" are all left exactly as they are.
//
// A dot inside the suffix is *required*, which is the fence that matters. The
// genuinely ambiguous spelling is a bare number: "v1.2.3-1" is a packaging
// release in Debian's hands and a first prerelease in someone else's, and
// nothing in the tag says which. Demanding the two-part "RELEASE.BUILD" shape
// an RPM actually uses -- "11.14" -- takes the case that is unambiguous and
// leaves the coin-flip alone. A bare "-1" therefore keeps sorting below the
// release: over-reporting, the safe direction, and the same answer this code
// gave before the rule existed.
//
// Then tagAuthority has already established that the tag states *this module's*
// version before any of this runs, so the blast radius is a project's own
// images rather than every image with a Go binary in it.
var dockerRelSuffix = regexp.MustCompile(`-(\d+(?:\.\d+)+)$`)

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
// and one of three things has to establish that the tag is talking about the
// module in hand:
//
//   - The image runs this module's binary. runsModule is what the image's own OCI
//     config says it exists to do, so it settles by evidence what the two tests
//     below reach for by inference. See entrypointversion.go.
//   - The tag carries a k3s/rke2 build suffix. "+k3s1" and "+rke2r1" are not
//     general semver decoration; they are those projects' own release marker,
//     and a tag carrying one is that project's version whatever the image is
//     called -- including a private mirror or a retag.
//   - The image is named after the module. "rancher/k3s" for
//     github.com/k3s-io/k3s, "prom/prometheus" for github.com/prometheus/
//     prometheus. A dash-separated token counts, so rancher's
//     "hardened-kubernetes" still names k8s.io/kubernetes.
//
// None is proof, and the last is the weakest: an image can be named after the
// project and still be tagged with something other than the binary's version.
// That residual risk is what the provenance note on every inferred finding is
// for. What this rules out is the case where there was never any reason to
// connect the two at all.
func tagAuthority(modulePath, ref, version string, runsModule bool) string {
	if runsModule {
		return "the image's own command runs this module's binary"
	}
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
	// SplitSeq rather than Split: the loop returns on the first match, so
	// materializing the whole slice allocates for tokens that are never read.
	for tok := range strings.SplitSeq(repo, "-") {
		if strings.EqualFold(tok, name) {
			return fmt.Sprintf("the image name contains the module name (%s)", name)
		}
	}
	return ""
}

// normalizeSemver puts a version string into the spelling OSV ranges against,
// or reports that it is not a version at all.
//
// The 'v' prefix is optional everywhere versions are written down and mandatory
// in x/mod/semver, so it is ensured rather than required. The MAJOR.MINOR.PATCH
// check is the load-bearing part: semver.IsValid accepts partials, so a bare
// date stamp like "20240101" would pass as "v20240101" -- a version far higher
// than anything real, which would range past every advisory and report a
// vulnerable artifact as clean. That is the under-report direction, so anything
// without a full core is refused.
func normalizeSemver(s string) (string, bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", false
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return "", false
	}
	core := v[1:]
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	if strings.Count(core, ".") != 2 {
		return "", false
	}
	return v, true
}

// normalizeTagVersion turns an image tag into a comparable Go module version,
// or reports that it is not one.
//
// "latest", a bare digest, an empty tag and a date-stamp all yield ok=false and
// no guess. Two suffixes are converted back to the '+' form before the version
// is read: the k3s/rke2 build marker, so it matches the versions those
// advisories are filed under, and a distro packaging release, so it stops
// sorting as a prerelease below the upstream version it is appended to. See
// dockerK3sSuffix and dockerRelSuffix.
//
// The k3s rewrite runs first and the two cannot both fire: "+k3s1" leaves no
// trailing "-digits" for the second to match, and a packaging release carries
// no letters for the first.
func normalizeTagVersion(tag string) (string, bool) {
	if tag == "" || tag == "latest" {
		return "", false
	}
	v := dockerK3sSuffix.ReplaceAllString(tag, "+$1")
	v = dockerRelSuffix.ReplaceAllString(v, "+$1")
	return normalizeSemver(v)
}

// moduleVersionFromImageTag derives a comparable Go module version for
// modulePath from an image reference's tag, returning the version, the raw tag
// it came from, and why the tag was trusted ("" when it was not, and so no
// version could be derived). runsModule reports whether the image's default
// command runs a binary whose main module this is.
//
// Two independent conditions have to hold, and both exist for the same reason:
// a wrong-but-higher version would mark a genuinely vulnerable finding as
// fixed, the one failure direction this tool must never take silently. The tag
// has to *be* a version (normalizeTagVersion), and it has to be a version of
// *this module* (tagAuthority). A clean semver tag on an image that has nothing
// to do with the module -- a Go binary sitting inside python:3.12.1 -- passes
// the first and fails the second.
func moduleVersionFromImageTag(modulePath, ref string, runsModule bool) (version, tag, why string) {
	tag = imageTag(ref)
	v, ok := normalizeTagVersion(tag)
	if !ok {
		return "", tag, ""
	}
	why = tagAuthority(modulePath, ref, v, runsModule)
	if why == "" {
		return "", tag, ""
	}
	return v, tag, why
}
