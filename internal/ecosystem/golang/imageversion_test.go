package golang

import (
	"testing"

	"golang.org/x/mod/semver"
)

// TestSemverAcceptsK3sBuildMetadata guards the gate that the whole fix depends
// on: the normalized k3s/rke2 form carries '+k3sN' build metadata, and if
// semver.IsValid rejected it moduleVersionFromImageTag would refuse the very
// case it exists to enable.
func TestSemverAcceptsK3sBuildMetadata(t *testing.T) {
	for _, v := range []string{"v1.36.3+k3s1", "v1.31.5+rke2r1"} {
		if !semver.IsValid(v) {
			t.Errorf("semver.IsValid(%q) = false; the image-tag fallback cannot work", v)
		}
	}
}

func TestIsDevelVersion(t *testing.T) {
	devel := []string{"", "(devel)", "devel", " (devel) ", "v0.0.0", "0.0.0", "garbage"}
	for _, v := range devel {
		if !isDevelVersion(v) {
			t.Errorf("isDevelVersion(%q) = false, want true (not comparable by OSV)", v)
		}
	}
	comparable := []string{"v1.36.3", "v1.36.3+k3s1", "v0.17.0", "1.2.3", "v1.2.3-rc1"}
	for _, v := range comparable {
		if isDevelVersion(v) {
			t.Errorf("isDevelVersion(%q) = true, want false (real semver)", v)
		}
	}
}

func TestImageTag(t *testing.T) {
	tests := []struct {
		ref, want string
	}{
		{"docker.io/rancher/k3s:v1.36.3-k3s1", "v1.36.3-k3s1"},
		{"registry:5000/rancher/k3s:v1.36.3-k3s1", "v1.36.3-k3s1"},
		{"rancher/rke2:v1.31.5-rke2r1", "v1.31.5-rke2r1"},
		{"alpine", ""},
		{"alpine:latest", "latest"},
		{"repo/img@sha256:deadbeef", ""},
		{"repo/img:v1.0.0@sha256:deadbeef", "v1.0.0"},
	}
	for _, tt := range tests {
		if got := imageTag(tt.ref); got != tt.want {
			t.Errorf("imageTag(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

func TestModuleVersionFromImageTag(t *testing.T) {
	tests := []struct {
		mod, ref, wantVer string
		wantOK            bool
	}{
		// k3s/rke2 Docker tags convert their '-k3sN'/'-rke2rN' suffix back to
		// the '+' form the module and its advisories use. This is the case the
		// whole fallback exists for and it must keep working.
		{"github.com/k3s-io/k3s", "docker.io/rancher/k3s:v1.36.3-k3s1", "v1.36.3+k3s1", true},
		{"github.com/rancher/rke2", "rancher/rke2:v1.31.5-rke2r1", "v1.31.5+rke2r1", true},
		// A plain semver tag is used as-is (with a 'v' ensured) when the image
		// names the module.
		{"example.com/app", "example.com/app:v1.2.3", "v1.2.3", true},
		{"example.com/app", "example.com/app:1.2.3", "v1.2.3", true},
		// An ordinary prerelease is left alone, not treated as k3s/rke2.
		{"example.com/app", "example.com/app:v1.2.3-rc1", "v1.2.3-rc1", true},
		// Non-semver, floating and digest tags yield no inference.
		{"example.com/app", "example.com/app:latest", "", false},
		{"example.com/app", "example.com/app:20240101", "", false},
		{"example.com/app", "example.com/app", "", false},
		{"example.com/app", "example.com/app@sha256:deadbeef", "", false},
		// A perfectly good semver tag on an image that has nothing to do with
		// the module infers nothing.
		{"github.com/some/tool", "python:3.12.1", "", false},
	}
	for _, tt := range tests {
		gotVer, _, why := moduleVersionFromImageTag(tt.mod, tt.ref, false)
		if gotVer != tt.wantVer || (why != "") != tt.wantOK {
			t.Errorf("moduleVersionFromImageTag(%q, %q) = (%q, %q), want (%q, ok=%v)",
				tt.mod, tt.ref, gotVer, why, tt.wantVer, tt.wantOK)
		}
	}
}

func TestNormalizeTagVersion(t *testing.T) {
	tests := []struct {
		tag, want string
		ok        bool
	}{
		// A distro packaging release becomes build metadata, so it stops
		// sorting as a prerelease below the upstream version it names.
		{"1.8.4-11.14", "v1.8.4+11.14", true},
		{"v1.8.4-11.14", "v1.8.4+11.14", true},
		{"1.8.4-11.14.2", "v1.8.4+11.14.2", true},
		// A bare number is deliberately NOT rewritten. "-1" is a packaging
		// release to one project and a first prerelease to another, and the tag
		// does not say which; left alone it keeps sorting below the release,
		// which over-reports rather than hiding a finding.
		{"1.8.4-3", "v1.8.4-3", true},
		{"v1.2.3-1", "v1.2.3-1", true},
		// k3s/rke2 keep their own rewrite, which runs first.
		{"v1.36.3-k3s1", "v1.36.3+k3s1", true},
		{"v1.31.5-rke2r1", "v1.31.5+rke2r1", true},
		// Real prereleases carry letters and are left exactly as they are.
		// Reading one of these as the release would be the under-report
		// direction, which is the whole hazard of the packaging-release rule.
		{"v1.2.3-rc1", "v1.2.3-rc1", true},
		{"v1.2.3-beta.2", "v1.2.3-beta.2", true},
		{"v1.34.10-rke2r1-build20260724", "v1.34.10-rke2r1-build20260724", true},
		// A packaging release hung off something that is not a full
		// MAJOR.MINOR.PATCH core is still not a version. bci-micro's
		// "16.0-22.17" is the case to keep refusing.
		{"16.0-22.17", "", false},
		{"1.0-1", "", false},
		// Refusals the rule must not have disturbed.
		{"", "", false},
		{"latest", "", false},
		{"20240101", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeTagVersion(tt.tag)
		if got != tt.want || ok != tt.ok {
			t.Errorf("normalizeTagVersion(%q) = (%q, %v), want (%q, %v)",
				tt.tag, got, ok, tt.want, tt.ok)
		}
	}
}

// The fence on dockerRelSuffix, stated as its consequence rather than its
// spelling. A bare numeric suffix is ambiguous -- a packaging release to one
// project, a first prerelease to another -- so it is left alone and keeps
// sorting below the release. That over-reports, which is the direction this
// tool is allowed to be wrong in.
func TestBareNumericSuffixStaysConservative(t *testing.T) {
	got, ok := normalizeTagVersion("1.2.3-1")
	if !ok || got != "v1.2.3-1" {
		t.Fatalf(`normalizeTagVersion("1.2.3-1") = (%q, %v), want ("v1.2.3-1", true)`, got, ok)
	}
	if c := semver.Compare(got, "v1.2.3"); c >= 0 {
		t.Errorf("semver.Compare(%q, v1.2.3) = %d, want < 0: an ambiguous suffix must not read up", got, c)
	}
}

// The SUSE KubeVirt case, end to end on the reference that produced it.
//
// The image's entrypoint is /usr/bin/virt-operator, so tagAuthority accepts the
// tag outright; the only question left is how to read it. "1.8.4-11.14" is
// upstream KubeVirt 1.8.4 with SUSE's package release 11.14, and reading that
// release as a semver prerelease placed the module *below* v1.8.4, where an
// advisory fixed in 1.8.4 still matches. The binary's own -ldflags agree with
// the upstream reading: gitVersion=v1.8.4.
//
// The ordering is asserted rather than the finding count, because on this
// particular image the rewrite clears nothing -- 1.8.4 is above every published
// kubevirt fix. The advisories it does suppress sit at a fix boundary, which
// 1.8.4 is not; see dockerRelSuffix for the measurements.
func TestDistroPackagingReleaseDoesNotSortBelowTheRelease(t *testing.T) {
	const (
		mod = "kubevirt.io/kubevirt"
		ref = "registry.suse.com/suse/sles/16.0/virt-operator:1.8.4-11.14"
	)
	// Guard the fixture before asserting the fix: if the old spelling ever
	// stops sorting below v1.8.4, this test is no longer reproducing the bug
	// and its passing would mean nothing.
	if semver.Compare("v1.8.4-11.14", "v1.8.4") >= 0 {
		t.Fatal("fixture no longer reproduces the bug: v1.8.4-11.14 must sort below v1.8.4")
	}

	got, tag, why := moduleVersionFromImageTag(mod, ref, true)
	if tag != "1.8.4-11.14" {
		t.Fatalf("tag = %q, want 1.8.4-11.14", tag)
	}
	if why == "" {
		t.Fatal("no authority recorded, but the image's own command runs this binary")
	}
	if got != "v1.8.4+11.14" {
		t.Fatalf("version = %q, want v1.8.4+11.14", got)
	}
	// The spelling is incidental; the ordering is the fix. Build metadata is
	// ignored in precedence, so the tag now compares equal to the upstream
	// version it names and an advisory fixed in 1.8.4 no longer matches.
	if c := semver.Compare(got, "v1.8.4"); c != 0 {
		t.Errorf("semver.Compare(%q, v1.8.4) = %d, want 0", got, c)
	}
}

// The k3s and rke2 references this fallback was written for, spelled the ways
// they actually appear -- upstream, mirrored, retagged, and with a registry
// port in the way. The build suffix is the authority in every one of them, so
// none of them depends on what the image is called.
func TestK3sAndRKE2AreAlwaysResolved(t *testing.T) {
	tests := []struct {
		mod, ref, want string
	}{
		{"github.com/k3s-io/k3s", "docker.io/rancher/k3s:v1.36.3-k3s1", "v1.36.3+k3s1"},
		{"github.com/k3s-io/k3s", "rancher/k3s:v1.36.3-k3s1", "v1.36.3+k3s1"},
		{"github.com/k3s-io/k3s", "registry:5000/mirror/k3s:v1.36.3-k3s1", "v1.36.3+k3s1"},
		// A retag under a name that says nothing about k3s. The suffix still
		// does, so the version is still recovered.
		{"github.com/k3s-io/k3s", "mycorp.example/internal/platform:v1.36.3-k3s1", "v1.36.3+k3s1"},
		{"github.com/rancher/rke2", "rancher/rke2:v1.31.5-rke2r1", "v1.31.5+rke2r1"},
		{"github.com/rancher/rke2", "rancher/rke2:v1.31.5-rke2r2", "v1.31.5+rke2r2"},
		// rke2 has shipped both the 'rke2rN' and bare 'rke2N' spellings.
		{"github.com/rancher/rke2", "rancher/rke2:v1.31.5-rke21", "v1.31.5+rke21"},
		// Rancher's hardened images are named after the module rather than
		// carrying a trailing build suffix, so the name gate is what saves them.
		{"k8s.io/kubernetes", "rancher/hardened-kubernetes:v1.34.10-rke2r1-build20260724", "v1.34.10-rke2r1-build20260724"},
	}
	for _, tt := range tests {
		got, _, why := moduleVersionFromImageTag(tt.mod, tt.ref, false)
		if got != tt.want {
			t.Errorf("moduleVersionFromImageTag(%q, %q) = %q, want %q", tt.mod, tt.ref, got, tt.want)
		}
		if why == "" {
			t.Errorf("moduleVersionFromImageTag(%q, %q) recorded no authority", tt.mod, tt.ref)
		}
	}
}

// The gate this fix adds. A semver tag says what the *image* is a version of,
// and only sometimes is that the Go module inside it. Guessing wrong reads too
// high and marks a vulnerable finding as fixed.
func TestTagAuthority(t *testing.T) {
	allowed := []struct{ mod, ref, version string }{
		// The image is the project's own image.
		{"github.com/k3s-io/k3s", "rancher/k3s:v1.36.3-k3s1", "v1.36.3+k3s1"},
		{"github.com/prometheus/prometheus", "prom/prometheus:v2.51.0", "v2.51.0"},
		// A dash-separated token counts, so rancher's hardened rebuilds work.
		{"k8s.io/kubernetes", "rancher/hardened-kubernetes:v1.34.10", "v1.34.10"},
		// A major-version suffix on the module path is not the module's name.
		{"github.com/goharbor/harbor/v2", "goharbor/harbor:v2.11.0", "v2.11.0"},
	}
	for _, tt := range allowed {
		if why := tagAuthority(tt.mod, tt.ref, tt.version, false); why == "" {
			t.Errorf("tagAuthority(%q, %q, %q) = \"\", want an authority", tt.mod, tt.ref, tt.version)
		}
	}

	refused := []struct{ mod, ref, version string }{
		// The one that motivated the gate: a Go binary that happens to live in
		// a language runtime image. 3.12.1 is Python's version, not its own,
		// and it is far higher than any version this module has ever had.
		{"github.com/some/tool", "python:3.12.1", "v3.12.1"},
		{"github.com/some/tool", "node:20.11.0", "v20.11.0"},
		// A sidecar in somebody else's application image.
		{"github.com/prometheus/node_exporter", "mycorp/payments-api:v4.2.0", "v4.2.0"},
		// Nothing to compare against.
		{"", "rancher/k3s:v1.2.3", "v1.2.3"},
		{"github.com/some/tool", "", "v1.2.3"},
	}
	for _, tt := range refused {
		if why := tagAuthority(tt.mod, tt.ref, tt.version, false); why != "" {
			t.Errorf("tagAuthority(%q, %q, %q) = %q, want refusal", tt.mod, tt.ref, tt.version, why)
		}
	}
}

func TestModuleName(t *testing.T) {
	tests := []struct{ path, want string }{
		{"github.com/k3s-io/k3s", "k3s"},
		{"k8s.io/kubernetes", "kubernetes"},
		{"github.com/goharbor/harbor/v2", "harbor"},
		{"github.com/foo/bar/v12", "bar"},
		{"standalone", "standalone"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := moduleName(tt.path); got != tt.want {
			t.Errorf("moduleName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestImageRepo(t *testing.T) {
	tests := []struct{ ref, want string }{
		{"docker.io/rancher/k3s:v1.36.3-k3s1", "k3s"},
		{"registry:5000/rancher/k3s", "k3s"},
		{"rancher/hardened-kubernetes:v1.34.10", "hardened-kubernetes"},
		{"alpine", "alpine"},
		{"alpine:latest", "alpine"},
		{"repo/img@sha256:deadbeef", "img"},
	}
	for _, tt := range tests {
		if got := imageRepo(tt.ref); got != tt.want {
			t.Errorf("imageRepo(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}
