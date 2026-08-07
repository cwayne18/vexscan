package golang

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
)

// k3sLDFlags is the verbatim "-ldflags" build setting of /usr/bin/k3s out of
// rancher/rancher:v2.15.0, whitespace and all.
//
// It is here in full rather than trimmed to a sample because the whole
// difficulty of this fallback is the noise: 25 stamps, 6 of them assigning
// something that looks exactly like a version, for cri-tools, containerd,
// flannel, kube-router, cri-dockerd and k3s itself. Any rule that picks by the
// shape of the variable name has 5 candidates here and no way to choose. A
// shortened fixture would test a problem this binary does not have.
const k3sLDFlags = `     -X github.com/k3s-io/k3s/pkg/version.Version=v1.36.2+k3s1     -X github.com/k3s-io/k3s/pkg/version.GitCommit=01b6f04a      -X k8s.io/client-go/pkg/version.gitVersion=v1.36.2+k3s1     -X k8s.io/client-go/pkg/version.gitCommit=01b6f04aaa69e8b09303f0393d4b4f1811da23aa     -X k8s.io/client-go/pkg/version.gitTreeState=clean     -X k8s.io/client-go/pkg/version.buildDate=2026-06-24T22:52:31Z      -X k8s.io/component-base/version.gitVersion=v1.36.2+k3s1     -X k8s.io/component-base/version.gitCommit=01b6f04aaa69e8b09303f0393d4b4f1811da23aa     -X k8s.io/component-base/version.gitTreeState=clean     -X k8s.io/component-base/version.buildDate=2026-06-24T22:52:31Z      -X sigs.k8s.io/cri-tools/pkg/version.Version=v1.36.0-k3s1      -X github.com/containerd/containerd/v2/version.Version=v2.3.2-k3s2     -X github.com/containerd/containerd/v2/version.Package=github.com/k3s-io/containerd/v2      -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v1.9.1-k3s1     -X github.com/containernetworking/plugins/plugins/meta/flannel.Program=flannel     -X github.com/containernetworking/plugins/plugins/meta/flannel.Version=v1.9.0-flannel1+v0.28.4     -X github.com/containernetworking/plugins/plugins/meta/flannel.Commit=HEAD     -X github.com/containernetworking/plugins/plugins/meta/flannel.buildDate=2026-06-24T22:52:31Z     -X github.com/cloudnativelabs/kube-router/v2/pkg/version.Version=v2.6.3-k3s1     -X github.com/cloudnativelabs/kube-router/v2/pkg/version.BuildDate=2026-06-24T22:52:31Z     -X github.com/Mirantis/cri-dockerd/cmd/version.Version=v0.3.19-k3s5     -X github.com/Mirantis/cri-dockerd/cmd/version.GitCommit=HEAD     -X github.com/Mirantis/cri-dockerd/cmd/version.BuildTime=2026-06-24T22:52:31Z     -X go.etcd.io/etcd/api/v3/version.GitSHA=HEAD     -X github.com/k3s-io/helm-controller/pkg/controllers/chart.DefaultJobImage=rancher/klipper-helm:v0.11.1-build20260615`

// rancherLDFlags is the same setting off /usr/bin/rancher in that image.
const rancherLDFlags = `-X github.com/rancher/rancher/pkg/version.Version=v2.15.0 -X github.com/rancher/rancher/pkg/version.GitCommit=d54b0ec5a`

func ldflags(v string) []debug.BuildSetting {
	return []debug.BuildSetting{
		{Key: "-compiler", Value: "gc"},
		{Key: "-ldflags", Value: v},
		{Key: "vcs", Value: "git"},
	}
}

// The bug this whole file exists for. rancher/rancher:v2.15.0 ships a k3s
// binary whose build info says "(devel)", so OSV cannot range-match it and
// returns every k3s advisory ever filed -- including GHSA-m4hf-6vgr-75r2, fixed
// in 1.28.1, against a 1.36.2 binary. The version is in the artifact the whole
// time.
func TestK3sVersionIsRecoveredFromItsOwnLDFlags(t *testing.T) {
	got, key := moduleVersionFromLDFlags("github.com/k3s-io/k3s", ldflags(k3sLDFlags))
	if got != "v1.36.2+k3s1" {
		t.Errorf("version = %q, want v1.36.2+k3s1", got)
	}
	if key != "github.com/k3s-io/k3s/pkg/version.Version" {
		t.Errorf("key = %q, want the k3s version variable", key)
	}
}

func TestRancherVersionIsRecoveredFromItsOwnLDFlags(t *testing.T) {
	got, _ := moduleVersionFromLDFlags("github.com/rancher/rancher", ldflags(rancherLDFlags))
	if got != "v2.15.0" {
		t.Errorf("version = %q, want v2.15.0", got)
	}
}

// The load-bearing assertion, stated on the candidate set rather than the
// result: of the 25 stamps in the k3s binary, exactly one is a candidate for
// k3s's own version.
//
// The five others that look just as much like a version -- containerd's
// v2.3.2, cri-tools' v1.36.0, kube-router's v2.6.3, cri-dockerd's v0.3.19,
// flannel's v1.9.0 -- belong to dependencies. Each would be wrong by an entire
// project if read as k3s's, and v2.3.2 in particular ranges past every k3s
// advisory there is. Note what this means for the test above: because
// disagreeing candidates are refused outright, that test could not have
// returned v1.36.2 at all unless these five had already been excluded.
func TestOnlyTheMainModulesOwnStampIsACandidate(t *testing.T) {
	got := versionStamps("github.com/k3s-io/k3s", k3sLDFlags)
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want exactly 1: %+v", len(got), got)
	}
	if got[0].key != "github.com/k3s-io/k3s/pkg/version.Version" || got[0].version != "v1.36.2+k3s1" {
		t.Errorf("candidate = %+v, want k3s's own version variable", got[0])
	}
}

// Only the main module is ever asked. A dependency's version is read straight
// out of build info, where it is always present and correct, so no stamp can
// reach it -- including the several in this binary that name a dependency
// outright.
func TestDependencyVersionsIgnoreLDFlagsEntirely(t *testing.T) {
	const root = "/tmp/extract"
	bin := mainVersionBinary(root+"/bin/k3s", "github.com/k3s-io/k3s", "(devel)")
	bin.Info.Settings = ldflags(k3sLDFlags)
	bin.Info.Deps = []*debug.Module{
		// Build info says containerd is v2.3.2-k3s2 here too, but the point is
		// that the stamp is not consulted: a dep whose build info disagreed
		// with the stamp must still report what build info says.
		{Path: "github.com/containerd/containerd/v2", Version: "v2.0.0"},
		{Path: "sigs.k8s.io/cri-tools", Version: "v1.30.0"},
	}

	comps := New(Options{}).groupAll(root, []binscan.Binary{bin})
	for _, want := range []struct{ mod, version string }{
		{"github.com/containerd/containerd/v2", "v2.0.0"},
		{"sigs.k8s.io/cri-tools", "v1.30.0"},
	} {
		c := mainComponent(comps, want.mod)
		if c == nil {
			t.Fatalf("%s missing from inventory", want.mod)
		}
		if c.Version != want.version {
			t.Errorf("%s = %q, want %q from build info", want.mod, c.Version, want.version)
		}
		if from := c.Extra.(*state).inferred; from.origin != "" {
			t.Errorf("%s carries a recovery note (%+v); its version was never in doubt", want.mod, from)
		}
	}
}

// A near-miss on the prefix test. "github.com/foo/bar" must not own
// "github.com/foo/barbaz", which is a different project whose path merely
// starts with the same bytes.
func TestOwnershipIsTestedAtAPathBoundary(t *testing.T) {
	flags := `-X github.com/foo/barbaz/version.Version=v9.9.9`
	if got, _ := moduleVersionFromLDFlags("github.com/foo/bar", ldflags(flags)); got != "" {
		t.Errorf("version = %q, want none: barbaz is not bar", got)
	}
	if got, _ := moduleVersionFromLDFlags("github.com/foo/barbaz", ldflags(flags)); got != "v9.9.9" {
		t.Errorf("version = %q, want v9.9.9 for its own module", got)
	}
}

// Package main belongs to whatever is being built, so "-X main.version" -- much
// the most common spelling in small projects -- is by construction about the
// main module.
func TestMainPackageStampCounts(t *testing.T) {
	for _, flags := range []string{
		`-X main.version=v1.2.3`,
		`-X main.Version=1.2.3`,
		`-X main.ver=v1.2.3`,
		`-s -w -X main.version=v1.2.3 -X main.commit=abc123`,
	} {
		if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "v1.2.3" {
			t.Errorf("moduleVersionFromLDFlags(_, %q) = %q, want v1.2.3", flags, got)
		}
	}
}

// A variable at the module root, with no package path under it.
func TestStampAtTheModuleRoot(t *testing.T) {
	flags := `-X example.com/app.Version=v1.2.3`
	if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3", got)
	}
}

// `go build` accepts the pair quoted, the value quoted, and '=' or a space
// after -X. All of them have to parse, because which one a project used is an
// accident of its Makefile.
func TestLDFlagsQuotingForms(t *testing.T) {
	for _, flags := range []string{
		`-X main.version=v1.2.3`,
		`-X=main.version=v1.2.3`,
		`-X 'main.version=v1.2.3'`,
		`-X='main.version=v1.2.3'`,
		`-X "main.version=v1.2.3"`,
		`-X="main.version=v1.2.3"`,
		`-X main.version='v1.2.3'`,
		`-X main.version="v1.2.3"`,
	} {
		if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "v1.2.3" {
			t.Errorf("moduleVersionFromLDFlags(_, %q) = %q, want v1.2.3", flags, got)
		}
	}
}

// -X has to be a flag, not a substring. An external linker argument like
// -Wl,-X is not a Go stamp and must not be read as the start of one.
func TestXMustBeItsOwnFlag(t *testing.T) {
	flags := `-linkmode=external -extldflags "-static -Wl,-Xmain.version=v9.9.9"`
	if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "" {
		t.Errorf("version = %q, want none: -Wl,-X is not a Go -X stamp", got)
	}
}

// Two stamps the main module owns that disagree mean the ownership test did not
// actually isolate the module's version. Choosing between them is how a
// too-high version gets picked, so neither is used.
func TestDisagreeingStampsAreRefused(t *testing.T) {
	flags := `-X main.version=v1.2.3 -X example.com/app/pkg/version.Version=v4.5.6`
	if got, key := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "" {
		t.Errorf("version = %q (from %s), want none: the stamps disagree", got, key)
	}
}

// Agreeing duplicates are ordinary -- a project may write both main.version and
// its own version package from one variable -- and say the same thing twice.
func TestAgreeingStampsAreAccepted(t *testing.T) {
	flags := `-X main.version=v1.2.3 -X example.com/app/pkg/version.Version=v1.2.3`
	if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3", got)
	}
}

// Spellings that differ only by the optional 'v' are the same version, and
// refusing them as a disagreement would lose a perfectly good answer.
func TestTheVPrefixIsNotADisagreement(t *testing.T) {
	flags := `-X main.version=1.2.3 -X example.com/app/pkg/version.Version=v1.2.3`
	if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3", got)
	}
}

// A variable whose name is not unmistakably "the version" is saying something
// else. goVersion is a toolchain, buildVersion is often a CI build number, and
// either read as the module's version is a wrong answer where no answer was
// available.
func TestOnlyUnmistakableVersionVariablesAreRead(t *testing.T) {
	for _, name := range []string{
		"goVersion", "buildVersion", "gitVersion", "VersionString",
		"GitCommit", "commit", "date", "Program",
	} {
		flags := `-X example.com/app/pkg/build.` + name + `=v1.2.3`
		if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "" {
			t.Errorf("%s was read as the module version (%q); only version/ver count", name, got)
		}
	}
}

// Everything that is not a comparable version has to be refused, because the
// point of the exercise is to stop sending OSV something it cannot range.
func TestUnusableStampedValuesAreRefused(t *testing.T) {
	for _, value := range []string{
		"dev", "unknown", "", "HEAD", "latest",
		// A bare date stamp passes semver.IsValid once a 'v' is prepended and
		// is astronomically higher than any real version, which would range
		// past every advisory: the under-report direction.
		"20240101",
		// Partials, for the same reason.
		"v1", "v1.2",
		// The zero a build with no tag falls back to. No more comparable than
		// the "(devel)" it would be replacing.
		"v0.0.0", "0.0.0",
	} {
		flags := `-X main.version=` + value
		if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != "" {
			t.Errorf("stamped value %q was accepted as %q, want refusal", value, got)
		}
	}
}

// Real versions in the shapes these projects actually publish.
func TestUsableStampedValues(t *testing.T) {
	tests := map[string]string{
		"v1.36.2+k3s1":   "v1.36.2+k3s1",
		"v1.31.5+rke2r1": "v1.31.5+rke2r1",
		"1.2.3":          "v1.2.3",
		"v1.2.3":         "v1.2.3",
		"v1.2.3-rc1":     "v1.2.3-rc1",
		"v0.1.0":         "v0.1.0",
	}
	for value, want := range tests {
		flags := `-X main.version=` + value
		if got, _ := moduleVersionFromLDFlags("example.com/app", ldflags(flags)); got != want {
			t.Errorf("stamped value %q = %q, want %q", value, got, want)
		}
	}
}

func TestNoLDFlagsAtAll(t *testing.T) {
	cases := [][]debug.BuildSetting{
		nil,
		{{Key: "-compiler", Value: "gc"}},
		ldflags(""),
		ldflags("-s -w"),
	}
	for i, settings := range cases {
		if got, _ := moduleVersionFromLDFlags("example.com/app", settings); got != "" {
			t.Errorf("case %d: version = %q, want none", i, got)
		}
	}
	// An empty module path is not something to test ownership against.
	if got, _ := moduleVersionFromLDFlags("", ldflags(k3sLDFlags)); got != "" {
		t.Errorf("version = %q for an empty module path, want none", got)
	}
}

func TestSplitXKey(t *testing.T) {
	tests := []struct {
		key, pkg, name string
		ok             bool
	}{
		{"github.com/k3s-io/k3s/pkg/version.Version", "github.com/k3s-io/k3s/pkg/version", "Version", true},
		{"main.version", "main", "version", true},
		{"example.com/app.Version", "example.com/app", "Version", true},
		// The dots in a hostname come before the last slash and must not be
		// mistaken for the package/variable split.
		{"k8s.io/client-go/pkg/version.gitVersion", "k8s.io/client-go/pkg/version", "gitVersion", true},
		// Nothing to split.
		{"version", "", "", false},
		{"github.com/foo/bar", "", "", false},
		{"main.", "", "", false},
	}
	for _, tt := range tests {
		pkg, name, ok := splitXKey(tt.key)
		if pkg != tt.pkg || name != tt.name || ok != tt.ok {
			t.Errorf("splitXKey(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.key, pkg, name, ok, tt.pkg, tt.name, tt.ok)
		}
	}
}

// End-to-end, on the case that started this: the k3s binary inside
// rancher/rancher:v2.15.0. The image tag says v2.15.0 -- rancher's version, not
// k3s's -- and tagAuthority rightly refuses it, which used to leave "(devel)"
// going to OSV and four advisories coming back where two apply.
func TestK3sInsideTheRancherImageResolvesFromLDFlags(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/k3s-io/k3s"
	bin := mainVersionBinary(root+"/bin/k3s", mod, "(devel)")
	bin.Info.Settings = ldflags(k3sLDFlags)

	p := New(Options{Image: "docker.io/rancher/rancher:v2.15.0"})
	c := mainComponent(p.groupAll(root, []binscan.Binary{bin}), mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "v1.36.2+k3s1" {
		t.Errorf("version = %q, want v1.36.2+k3s1 out of the binary's own -ldflags", c.Version)
	}
	from := c.Extra.(*state).inferred
	if from.origin != "ldflags-version" {
		t.Errorf("origin = %q, want ldflags-version", from.origin)
	}
	// The note has to name the variable, not just the number: whose version
	// variable was read is the entire question the ownership test answers, so a
	// reader has to be able to see the answer.
	for _, want := range []string{"version not in build info", "github.com/k3s-io/k3s/pkg/version.Version", "v1.36.2+k3s1"} {
		if !strings.Contains(from.detail, want) {
			t.Errorf("detail = %q, missing %q", from.detail, want)
		}
	}
}

// A stamp read out of the artifact beats a tag inferred from what somebody
// called the image around it, so it is tried first -- even when the tag would
// also have been allowed.
func TestLDFlagsBeatTheImageTag(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/k3s-io/k3s"
	bin := mainVersionBinary(root+"/bin/k3s", mod, "(devel)")
	bin.Info.Settings = ldflags(`-X github.com/k3s-io/k3s/pkg/version.Version=v1.36.2+k3s1`)

	// This tag carries the k3s build suffix, so tagAuthority would accept it --
	// at a different version. The binary's own answer wins.
	p := New(Options{Image: "docker.io/rancher/k3s:v1.20.0-k3s1"})
	c := mainComponent(p.groupAll(root, []binscan.Binary{bin}), mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "v1.36.2+k3s1" {
		t.Errorf("version = %q, want the stamped v1.36.2+k3s1 over the tagged v1.20.0+k3s1", c.Version)
	}
	if origin := c.Extra.(*state).inferred.origin; origin != "ldflags-version" {
		t.Errorf("origin = %q, want ldflags-version", origin)
	}
}

// The stamp is in the binary, so it works with no image at all -- a rootfs
// scan, or a binary handed over on its own. This is the case the image-tag
// fallback could never reach.
func TestLDFlagsWorkWithoutAnImage(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "example.com/app"
	bin := mainVersionBinary(root+"/bin/app", mod, "(devel)")
	bin.Info.Settings = ldflags(`-X main.version=v1.2.3`)

	c := mainComponent(New(Options{}).groupAll(root, []binscan.Binary{bin}), mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3", c.Version)
	}
}

// A real build-info version is the module's own statement about itself and is
// never second-guessed, whatever the flags happen to say.
func TestARealBuildInfoVersionIsNotOverriddenByAStamp(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "example.com/app"
	bin := mainVersionBinary(root+"/bin/app", mod, "v1.0.0")
	bin.Info.Settings = ldflags(`-X main.version=v9.9.9`)

	c := mainComponent(New(Options{}).groupAll(root, []binscan.Binary{bin}), mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0 from build info", c.Version)
	}
	if from := c.Extra.(*state).inferred; from.origin != "" {
		t.Errorf("recovery note %+v on a version that was never in doubt", from)
	}
}

// Nothing usable in the flags falls through to the tag, and then to "(devel)".
// Both fallbacks have to keep working or this change trades one blind spot for
// another.
func TestUnusableStampsFallThrough(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/k3s-io/k3s"

	t.Run("to the image tag", func(t *testing.T) {
		bin := mainVersionBinary(root+"/bin/k3s", mod, "(devel)")
		bin.Info.Settings = ldflags(`-X main.commit=abc123 -X main.version=dev`)
		p := New(Options{Image: "docker.io/rancher/k3s:v1.36.3-k3s1"})
		c := mainComponent(p.groupAll(root, []binscan.Binary{bin}), mod)
		if c.Version != "v1.36.3+k3s1" {
			t.Errorf("version = %q, want the tag's v1.36.3+k3s1", c.Version)
		}
		if origin := c.Extra.(*state).inferred.origin; origin != "image-tag-version" {
			t.Errorf("origin = %q, want image-tag-version", origin)
		}
	})

	t.Run("to (devel)", func(t *testing.T) {
		bin := mainVersionBinary(root+"/bin/k3s", mod, "(devel)")
		bin.Info.Settings = ldflags(`-X main.version=dev`)
		c := mainComponent(New(Options{}).groupAll(root, []binscan.Binary{bin}), mod)
		if c.Version != "(devel)" {
			t.Errorf("version = %q, want (devel): over-reporting is the safe direction", c.Version)
		}
		if from := c.Extra.(*state).inferred; from.origin != "" {
			t.Errorf("recovery note %+v when nothing was recovered", from)
		}
	})
}

// A binary with no build info at all must not panic the settings lookup.
func TestBinaryWithNoBuildInfo(t *testing.T) {
	if got := buildSettings(binscan.Binary{Path: "/bin/x"}); got != nil {
		t.Errorf("buildSettings(no info) = %v, want nil", got)
	}
}

func TestOwnedBy(t *testing.T) {
	const mod = "github.com/foo/bar"
	owned := []string{"main", mod, mod + "/version", mod + "/pkg/version", mod + "/v2/version"}
	for _, p := range owned {
		if !ownedBy(p, mod) {
			t.Errorf("ownedBy(%q, %q) = false, want true", p, mod)
		}
	}
	foreign := []string{"github.com/foo/barbaz", "github.com/foo/barbaz/version", "github.com/other/bar", "k8s.io/component-base/version", ""}
	for _, p := range foreign {
		if ownedBy(p, mod) {
			t.Errorf("ownedBy(%q, %q) = true, want false", p, mod)
		}
	}
}
