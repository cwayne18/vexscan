package golang

import (
	"debug/buildinfo"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// The case this file exists for, taken from a real image:
//
//	docker.io/rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821
//	  mod  k8s.io/kubernetes    v1.36.4+dirty
//	  dep  k8s.io/apimachinery  (devel)
//
// Without the mapping, OSV asked about "(devel)" returns every advisory ever
// filed against k8s.io/apimachinery -- including GO-2022-0965, fixed in
// September 2019 -- and every one of them lands as a HIGH against a 2026 build.
func TestStagingModuleVersionKubernetes(t *testing.T) {
	got, from := stagingModuleVersion(kubernetesModule, "v1.36.4+dirty", "k8s.io/apimachinery", "(devel)")
	if got != "v0.36.4" {
		t.Fatalf("staging version = %q, want v0.36.4", got)
	}
	if from.origin != originStagingVersion {
		t.Errorf("origin = %q, want %q", from.origin, originStagingVersion)
	}
	// The provenance has to name both versions: a reader auditing the row needs
	// to see which release the number was derived from, not just that it was.
	for _, want := range []string{"(devel)", "v1.36.4+dirty", "v0.36.4", "k8s.io/apimachinery"} {
		if !strings.Contains(from.detail, want) {
			t.Errorf("detail does not mention %q: %s", want, from.detail)
		}
	}
}

// A prerelease is cut across the staging modules the same way a release is, so
// the mapping has to carry it through rather than round it off to the .0.
func TestStagingModuleVersionKeepsPrerelease(t *testing.T) {
	got, _ := stagingModuleVersion(kubernetesModule, "v1.37.0-rc.1", "k8s.io/client-go", "(devel)")
	if got != "v0.37.0-rc.1" {
		t.Errorf("staging version = %q, want v0.37.0-rc.1", got)
	}
}

// Every one of these reads a version *up*, which is the direction that marks a
// vulnerable binary clean, so each gate gets its own row.
func TestStagingModuleVersionRefusals(t *testing.T) {
	tests := []struct {
		name                                    string
		mainPath, mainVer, depPath, depVer, why string
	}{
		{
			name:     "dependency already states a real version",
			mainPath: kubernetesModule, mainVer: "v1.36.4", depPath: "k8s.io/apimachinery", depVer: "v0.30.1",
			why: "overwriting a stated version could only make it wrong",
		},
		{
			name:     "main module is not kubernetes",
			mainPath: "github.com/k3s-io/k3s", mainVer: "v1.36.4+k3s1", depPath: "k8s.io/apimachinery", depVer: "(devel)",
			why: "v1.Y.Z -> v0.Y.Z is Kubernetes' release convention and nobody else's",
		},
		{
			name:     "dependency is outside k8s.io",
			mainPath: kubernetesModule, mainVer: "v1.36.4", depPath: "sigs.k8s.io/yaml", depVer: "(devel)",
			why: "not a staging module",
		},
		{
			name:     "dependency is kubernetes itself",
			mainPath: kubernetesModule, mainVer: "v1.36.4", depPath: kubernetesModule, depVer: "(devel)",
			why: "k8s.io/kubernetes is not published as v0.Y.Z",
		},
		{
			name:     "main module version is itself uncomparable",
			mainPath: kubernetesModule, mainVer: "(devel)", depPath: "k8s.io/apimachinery", depVer: "(devel)",
			why: "there is nothing to derive from",
		},
		{
			name:     "main module is not at major 1",
			mainPath: kubernetesModule, mainVer: "v2.0.0", depPath: "k8s.io/apimachinery", depVer: "(devel)",
			why: "the convention this encodes stops being true at v2",
		},
		{
			name:     "main module version is a bare date stamp",
			mainPath: kubernetesModule, mainVer: "20260821", depPath: "k8s.io/apimachinery", depVer: "(devel)",
			why: "normalizeSemver refuses anything without a full MAJOR.MINOR.PATCH",
		},
	}
	for _, tt := range tests {
		got, from := stagingModuleVersion(tt.mainPath, tt.mainVer, tt.depPath, tt.depVer)
		if got != "" || from.origin != "" {
			t.Errorf("%s: got (%q, %q), want no recovery -- %s", tt.name, got, from.origin, tt.why)
		}
	}
}

// depVersion is the whole contract in one place: a real version passes through
// untouched, a staging module is recovered, and anything else is kept and
// flagged rather than dropped.
func TestDepVersion(t *testing.T) {
	p := &Plugin{}

	ver, from, why := p.depVersion(kubernetesModule, "v1.36.4", "github.com/spf13/cobra", "v1.8.1")
	if ver != "v1.8.1" || from.origin != "" || why != "" {
		t.Errorf("ordinary dependency = (%q, %q, %q), want it untouched", ver, from.origin, why)
	}

	ver, from, why = p.depVersion(kubernetesModule, "v1.36.4+dirty", "k8s.io/apimachinery", "(devel)")
	if ver != "v0.36.4" || from.origin != originStagingVersion || why != "" {
		t.Errorf("staging dependency = (%q, %q, %q), want v0.36.4 recovered", ver, from.origin, why)
	}

	// The module is kept under its uncomparable version rather than dropped.
	// Dropping it would leave no component, which reads as a module with no
	// advisories against it -- a false clean, the one output this tool must
	// never produce.
	ver, from, why = p.depVersion("github.com/other/app", "v1.2.3", "example.com/vendored", "(devel)")
	if ver != "(devel)" || from.origin != "" {
		t.Errorf("unrecoverable dependency = (%q, %q), want it kept as (devel)", ver, from.origin)
	}
	if why == "" {
		t.Error("an unrecoverable dependency must be marked uncomparable, not silently accepted")
	}
	if !strings.Contains(why, "example.com/vendored") || !strings.Contains(why, "(devel)") {
		t.Errorf("uncomparable detail does not say what could not be compared: %s", why)
	}
}

// The demotion is the half of the fix that keeps the tool honest where the
// mapping cannot reach, and it has to be surgical: affected verdicts go, and
// the deterministic clean ones stay.
func TestUncomparableVersionDemotesOnlyAffected(t *testing.T) {
	detail := uncomparableDetail("k8s.io/apimachinery", "(devel)")

	for _, st := range []ecosystem.Status{ecosystem.StatusLinked, ecosystem.StatusReachable} {
		got := uncomparableVersion(ecosystem.Finding{Status: st}, detail)
		if got.Status != ecosystem.StatusUndetermined {
			t.Errorf("status %s = %s, want undetermined", st, got.Status)
		}
		if got.Reason != ReasonUncomparableVersion {
			t.Errorf("status %s: reason = %q, want %q", st, got.Reason, ReasonUncomparableVersion)
		}
		if len(got.Evidence) != 1 || got.Evidence[0].Origin != OriginUncomparableVersion {
			t.Errorf("status %s: want one %s evidence entry, got %+v", st, OriginUncomparableVersion, got.Evidence)
		}
	}

	// not_present was decided by reading the symbol table. The vulnerable
	// package is not linked, which is true at every version, so an uncomparable
	// version takes nothing away from it.
	kept := ecosystem.Finding{
		Status:        ecosystem.StatusNotPresent,
		Justification: "vulnerable_code_not_present",
		Method:        "pclntab",
	}
	got := uncomparableVersion(kept, detail)
	if got.Status != ecosystem.StatusNotPresent || got.Reason != "" || len(got.Evidence) != 0 {
		t.Errorf("a not_present verdict must survive untouched, got %+v", got)
	}

	// Same for not_in_execute_path: govulncheck answered a question about the
	// code that is there, not about which version it is.
	got = uncomparableVersion(ecosystem.Finding{Status: ecosystem.StatusNotInPath}, detail)
	if got.Status != ecosystem.StatusNotInPath {
		t.Errorf("not_in_execute_path = %s, want it untouched", got.Status)
	}
}

// kubernetesBinary is the shape rancher/hardened-kubernetes ships: a real
// main-module version, and staging modules the toolchain could not tag.
func kubernetesBinary(path, mainVersion string) binscan.Binary {
	return binscan.Binary{Path: path, Info: &buildinfo.BuildInfo{
		Main:      debug.Module{Path: kubernetesModule, Version: mainVersion},
		GoVersion: "go1.26.7",
		Deps: []*debug.Module{
			{Path: "k8s.io/apimachinery", Version: "(devel)"},
			{Path: "k8s.io/client-go", Version: "(devel)"},
			{Path: "k8s.io/klog/v2", Version: "v2.130.1"},
			{Path: "github.com/spf13/cobra", Version: "v1.8.1"},
		},
	}}
}

// The end-to-end inventory: what the plugin hands the orchestrator to look up
// in OSV. Getting these four versions right is the difference between a clean
// report and six years of fixed advisories.
func TestGroupAllRecoversStagingVersions(t *testing.T) {
	const root = "/tmp/extract"
	p := New(Options{Image: "docker.io/rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821"})
	comps := p.groupAll(root, []binscan.Binary{kubernetesBinary(root+"/usr/local/bin/kubectl", "v1.36.4+dirty")})

	want := map[string]string{
		kubernetesModule:         "v1.36.4+dirty", // stated outright, left alone
		"k8s.io/apimachinery":    "v0.36.4",       // staging, recovered
		"k8s.io/client-go":       "v0.36.4",       // staging, recovered
		"k8s.io/klog/v2":         "v2.130.1",      // its own repo, states a real version
		"github.com/spf13/cobra": "v1.8.1",
	}
	for module, wantVer := range want {
		c := mainComponent(comps, module)
		if c == nil {
			t.Errorf("%s missing from inventory", module)
			continue
		}
		if c.Version != wantVer {
			t.Errorf("%s version = %q, want %q", module, c.Version, wantVer)
		}
		if st := c.Extra.(*state).uncomparable; st != "" {
			t.Errorf("%s should be comparable, got marked: %s", module, st)
		}
	}

	// The recovered ones carry their provenance; the stated ones must not,
	// or a reader cannot tell a derived version from a declared one.
	if got := mainComponent(comps, "k8s.io/apimachinery").Extra.(*state).inferred.origin; got != originStagingVersion {
		t.Errorf("apimachinery inferred origin = %q, want %q", got, originStagingVersion)
	}
	if got := mainComponent(comps, "k8s.io/klog/v2").Extra.(*state).inferred.origin; got != "" {
		t.Errorf("klog carries a provenance note it did not earn: %q", got)
	}
}

// A "(devel)" dependency nothing can recover must still be inventoried -- under
// its uncomparable version, marked. Dropping it would leave the module out of
// the report entirely, which reads as a module with nothing filed against it.
func TestGroupAllMarksUnrecoverableDependency(t *testing.T) {
	const root = "/tmp/extract"
	bin := binscan.Binary{Path: root + "/bin/app", Info: &buildinfo.BuildInfo{
		Main:      debug.Module{Path: "example.com/app", Version: "v1.0.0"},
		GoVersion: "go1.26.7",
		Deps:      []*debug.Module{{Path: "example.com/vendored", Version: "(devel)"}},
	}}

	comps := New(Options{}).groupAll(root, []binscan.Binary{bin})

	c := mainComponent(comps, "example.com/vendored")
	if c == nil {
		t.Fatal("an uncomparable dependency was dropped from the inventory")
	}
	if c.Version != "(devel)" {
		t.Errorf("version = %q, want it kept as (devel)", c.Version)
	}
	if c.Extra.(*state).uncomparable == "" {
		t.Error("the component must be marked uncomparable so its findings are demoted")
	}
}

// The targeted path (--module) has to reach the same answer as --all, or the
// two ways of asking the same question disagree.
func TestGroupRecoversStagingVersion(t *testing.T) {
	const root = "/tmp/extract"
	p := New(Options{Image: "docker.io/rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821"})
	comps := p.group(root,
		[]binscan.Binary{kubernetesBinary(root+"/usr/local/bin/kubectl", "v1.36.4+dirty")},
		[]string{"k8s.io/apimachinery"})

	c := mainComponent(comps, "k8s.io/apimachinery")
	if c == nil {
		t.Fatal("k8s.io/apimachinery missing from a targeted inventory")
	}
	if c.Version != "v0.36.4" {
		t.Errorf("version = %q, want v0.36.4 -- --module must agree with --all", c.Version)
	}
}

// The demotion, through the real analysis path: a linked staging finding that
// no version could be compared comes out undetermined rather than affected.
func TestAnalyzeImageDemotesUncomparableFindings(t *testing.T) {
	const root = "/tmp/extract"
	bin := binscan.Binary{Path: root + "/bin/app", Info: &buildinfo.BuildInfo{
		Main:      debug.Module{Path: "example.com/app", Version: "v1.0.0"},
		GoVersion: "go1.26.7",
		Deps:      []*debug.Module{{Path: "example.com/vendored", Version: "(devel)"}},
	}}
	comps := New(Options{}).groupAll(root, []binscan.Binary{bin})

	c := mainComponent(comps, "example.com/vendored")
	if c == nil {
		t.Fatal("component missing")
	}
	f := uncomparableVersion(
		ecosystem.Finding{Module: c.Name, Version: c.Version, Status: ecosystem.StatusLinked},
		c.Extra.(*state).uncomparable)
	if f.Status != ecosystem.StatusUndetermined || f.Reason != ReasonUncomparableVersion {
		t.Errorf("finding = (%s, %s), want undetermined/%s", f.Status, f.Reason, ReasonUncomparableVersion)
	}
}
