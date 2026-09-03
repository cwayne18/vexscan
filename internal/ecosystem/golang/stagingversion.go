package golang

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// Staging modules.
//
// imageversion.go and ldflagsversion.go both recover a version for a binary's
// own *main* module. This file recovers one for a dependency, which build info
// is supposed to state outright and for one shape of repository does not.
//
// A monorepo that publishes some of its own subdirectories as separate modules
// wires them up with a directory replace:
//
//	replace k8s.io/apimachinery => ./staging/src/k8s.io/apimachinery
//
// There is no tag on a directory, so the toolchain stamps the dependency
// "(devel)" -- the same non-answer isDevelVersion catches on a main module, in
// the one place nothing was looking for it. On rancher/hardened-kubernetes:
//
//	mod  k8s.io/kubernetes    v1.36.4+dirty
//	dep  k8s.io/apimachinery  (devel)
//	dep  k8s.io/client-go     (devel)
//	... seven more
//
// OSV cannot range-match "(devel)", so it answers with every advisory ever
// filed against the module. GO-2022-0965 was fixed in September 2019 and comes
// back against a 2026 build of Kubernetes, once per binary, for nine modules.
//
// Kubernetes is the case worth knowing by name -- it is most of the container
// images in the world -- and its convention is exact and published: the staging
// module cut alongside k8s.io/kubernetes vX.Y.Z is released as v0.Y.Z. So
// k8s.io/kubernetes v1.36.4 vendors k8s.io/apimachinery v0.36.4, which is a
// real tag on the module proxy and a version OSV ranges against cleanly.
//
// This reads *up* -- v0.36.4 is higher than the "(devel)" it replaces, and a
// version that reads too high ranges past a real advisory and calls a
// vulnerable binary clean, the one direction this tool must never take
// silently. So the mapping is fenced hard (see stagingModuleVersion) and every
// finding it touches carries the provenance. What is not recovered here is not
// guessed at either: golang.go marks the component uncomparable instead, and
// its affected verdicts come out undetermined rather than wrong.

// kubernetesModule is the only main module whose staging layout this knows.
//
// Named rather than pattern-matched because the mapping below is a fact about
// one project's release process, not a general property of monorepos, and a
// rule that fired on anything else would be inventing a version.
const kubernetesModule = "k8s.io/kubernetes"

// originStagingVersion marks a finding whose version came from the main
// module's release rather than from the dependency's own build-info entry.
//
// A distinct origin from the other two recoveries because it is a distinct
// strength of claim: ldflags reads a number out of the artifact, an image tag
// is a guess about the artifact, and this is a published convention applied to
// a number the artifact did state. A reader has to be able to tell which one
// underwrites a row.
const originStagingVersion = "staging-module-version"

// stagingModuleVersion recovers a comparable version for a dependency that
// build info stamped "(devel)" because the main module vendors it out of its
// own tree, returning "" when no such recovery is allowed.
//
// mainVersion is the main module's *resolved* version -- the one
// mainModuleVersion returned, which may itself have come from the binary's
// linker flags or the image tag. That chaining is deliberate: a k3s or rke2
// build whose main-module version was recovered from the tag has the same
// staging modules underneath it, and refusing to map them would leave the
// commonest Kubernetes images in the state this whole file exists to fix. The
// detail below names the version it derived from, so a chained recovery is
// visible as one.
//
// Four conditions, and each one closes a way of reading too high:
//
//   - The dependency's version is uncomparable to begin with. A dependency with
//     a real version is answering the question already, and overwriting it with
//     a derived one could only make it wrong.
//   - The main module is k8s.io/kubernetes. The v1.Y.Z -> v0.Y.Z mapping is that
//     project's release convention and nobody else's.
//   - The dependency is a k8s.io/* module other than k8s.io/kubernetes itself.
//     Combined with the first condition this is precisely the staging set:
//     k8s.io/klog, k8s.io/utils and k8s.io/kube-openapi live in their own
//     repositories and so carry real versions, which the first condition
//     already excluded.
//   - The main version is valid semver at major 1. Kubernetes has never shipped
//     a v2, and if it ever does the convention this encodes stops being true;
//     refusing the mapping then leaves the component undetermined, which is the
//     failing direction that cannot hide a vulnerability.
func stagingModuleVersion(mainPath, mainVersion, depPath, depVersion string) (string, inference) {
	if !isDevelVersion(depVersion) {
		return "", inference{}
	}
	if mainPath != kubernetesModule {
		return "", inference{}
	}
	if depPath == kubernetesModule || !strings.HasPrefix(depPath, "k8s.io/") {
		return "", inference{}
	}
	v, ok := normalizeSemver(mainVersion)
	if !ok || semver.Major(v) != "v1" {
		return "", inference{}
	}

	// Canonical drops build metadata ("+dirty" on an unclean tree) and keeps
	// the prerelease, which is what the convention does too: k8s.io/kubernetes
	// v1.37.0-rc.1 is cut alongside k8s.io/apimachinery v0.37.0-rc.1.
	staged := "v0." + strings.TrimPrefix(semver.Canonical(v), "v1.")

	reported := depVersion
	if reported == "" {
		reported = "(empty)"
	}
	return staged, inference{
		origin: originStagingVersion,
		detail: fmt.Sprintf("version not in build info (reported %s); %s vendors this module from its own "+
			"staging tree, and %s %s is released alongside %s %s",
			reported, kubernetesModule, kubernetesModule, mainVersion, depPath, staged),
	}
}

// uncomparableDetail is the account carried by a component whose version no
// recovery could make comparable.
//
// It has to say more than "unknown version", because the consequence is not
// obvious and is the entire reason the rows below it read the way they do: OSV
// asked about an unparseable version answers with the module's whole advisory
// history, so the finding exists at all only because nothing could rule it out.
func uncomparableDetail(modulePath, version string) string {
	reported := version
	if reported == "" {
		reported = "(empty)"
	}
	return fmt.Sprintf("build info reports %s for %s, which OSV cannot range-match; it answered with every "+
		"advisory ever filed against the module, so whether this build is already past the fix is unknown",
		reported, modulePath)
}

// OriginUncomparableVersion and ReasonUncomparableVersion mark a finding
// demoted because its component's version could not be compared. See
// ecosystem.OriginUncomparableVersion, where they are shared with the report
// that counts them.
const (
	OriginUncomparableVersion = ecosystem.OriginUncomparableVersion
	ReasonUncomparableVersion = ecosystem.ReasonUncomparableVersion
)

// uncomparableVersion demotes a finding decided against a version OSV could not
// range-match.
//
// Only the affected verdicts move, and that limit is the point. A not_present
// finding was decided by reading the binary's symbol table: the vulnerable
// package is not linked, which is a fact about the artifact and true at every
// version. Demoting it would throw away the one conclusion that survived
// unharmed and turn a report that ruled a hundred advisories out into a report
// that ruled nothing out.
//
// What cannot stand is "affected". The presence test found the vulnerable
// package, but on a module whose whole advisory history came back -- because
// OSV had no version to filter it against -- "the code is here" does not
// distinguish a vulnerable build from one that fixed this in 2019 and still
// ships the package. There is no evidence either way, and undetermined is what
// this tool says when there is no evidence either way.
func uncomparableVersion(f ecosystem.Finding, detail string) ecosystem.Finding {
	if !f.Affected() {
		return f
	}
	f.Status = ecosystem.StatusUndetermined
	f.Reason = ReasonUncomparableVersion
	f.Evidence = append(f.Evidence, ecosystem.Evidence{
		Origin: OriginUncomparableVersion,
		Detail: detail,
	})
	return f
}
