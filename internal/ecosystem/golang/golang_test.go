package golang

import (
	"context"
	"debug/buildinfo"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/source"
	"github.com/cwayne18/vexscan/internal/target"
)

func TestNormalizeModule(t *testing.T) {
	if got := NormalizeModule("std"); got != "stdlib" {
		t.Errorf("std should normalize to stdlib, got %q", got)
	}
	if got := NormalizeModule("golang.org/x/net"); got != "golang.org/x/net" {
		t.Errorf("a real module path must be left alone, got %q", got)
	}
}

func TestPurlRoundTrip(t *testing.T) {
	tests := []struct {
		module, version, want string
	}{
		{"golang.org/x/net", "v0.17.0", "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0"},
		{"stdlib", "1.24.0", "pkg:golang/stdlib@1.24.0"},
		{"golang.org/x/net", "", "pkg:golang/golang.org%2Fx%2Fnet"},
	}
	for _, tt := range tests {
		got := purl(tt.module, tt.version)
		if got != tt.want {
			t.Errorf("purl(%q, %q) = %q, want %q", tt.module, tt.version, got, tt.want)
		}
		module, version := parsePURL(got)
		if module != tt.module || version != tt.version {
			t.Errorf("parsePURL(%q) = %q@%q, want %q@%q", got, module, version, tt.module, tt.version)
		}
	}
}

func TestWantedModules(t *testing.T) {
	p := New(Options{})

	t.Run("by name", func(t *testing.T) {
		got, all := p.wantedModules([]ecosystem.Subject{{Name: "golang.org/x/net"}})
		if all {
			t.Error("a named subject does not ask for everything")
		}
		if want := []string{"golang.org/x/net"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("std is normalized", func(t *testing.T) {
		got, _ := p.wantedModules([]ecosystem.Subject{{Name: "std"}})
		if want := []string{"stdlib"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("by purl", func(t *testing.T) {
		got, _ := p.wantedModules([]ecosystem.Subject{{PURL: "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0"}})
		if want := []string{"golang.org/x/net"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("duplicates collapse", func(t *testing.T) {
		got, _ := p.wantedModules([]ecosystem.Subject{{Name: "m"}, {Name: "m"}, {Name: "n"}})
		if want := []string{"m", "n"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("subjects for another ecosystem are ignored", func(t *testing.T) {
		got, all := p.wantedModules([]ecosystem.Subject{
			{Ecosystem: "os", Name: "openssl"},
			{Ecosystem: "golang", Name: "golang.org/x/net"},
		})
		if all {
			t.Error("a subject aimed at another plugin does not ask this one for everything")
		}
		if want := []string{"golang.org/x/net"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	// The two empty results have to stay distinguishable: "asked for
	// everything" is a question this plugin cannot answer, while "never asked"
	// is an honest empty inventory.
	t.Run("scan-everything reports itself", func(t *testing.T) {
		got, all := p.wantedModules([]ecosystem.Subject{{}})
		if !all {
			t.Error("a subject with no name asks for everything")
		}
		if len(got) != 0 {
			t.Errorf("got %v, want no named modules", got)
		}
	})

	t.Run("no subject at all selects nothing", func(t *testing.T) {
		got, all := p.wantedModules(nil)
		if all || len(got) != 0 {
			t.Errorf("got %v, all=%v; want nothing selected", got, all)
		}
	})
}

// Refusing to enumerate is deliberate: an empty inventory would render as an
// image with no Go dependencies at all. But an image with no Go code in it has
// nothing to enumerate, so --all over a distro image has to pass quietly.
func TestScanEverythingIsRefusedOnlyWhenThereIsGoCode(t *testing.T) {
	p := New(Options{Logf: func(string, ...any) {}})
	img := &target.Image{FS: target.NewDirFS(t.TempDir())}

	got, err := p.InventoryImage(context.Background(), img, []ecosystem.Subject{{}})
	if err != nil {
		t.Fatalf("--all over an image with no Go binaries should pass quietly: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want an empty inventory", got)
	}
}

// fakeBinary builds a binscan.Binary with synthesized build info, so the
// grouping can be tested without compiling real binaries.
func fakeBinary(path string, deps map[string]string) binscan.Binary {
	info := &buildinfo.BuildInfo{
		Main:      debug.Module{Path: "example.com/app", Version: "v1.0.0"},
		GoVersion: "go1.24.0",
	}
	for p, v := range deps {
		info.Deps = append(info.Deps, &debug.Module{Path: p, Version: v})
	}
	return binscan.Binary{Path: path, Info: info}
}

// mainVersionBinary is a binary whose own main module carries the given path and
// version, used to exercise the "(devel)" main-module fallback.
func mainVersionBinary(path, mainPath, mainVersion string) binscan.Binary {
	return binscan.Binary{Path: path, Info: &buildinfo.BuildInfo{
		Main:      debug.Module{Path: mainPath, Version: mainVersion},
		GoVersion: "go1.24.0",
	}}
}

// mainComponent returns the component for module out of an inventory, or nil.
func mainComponent(comps []ecosystem.Component, module string) *ecosystem.Component {
	for i := range comps {
		if comps[i].Name == module {
			return &comps[i]
		}
	}
	return nil
}

func TestGroupAllInfersMainVersionFromImageTag(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/k3s-io/k3s"
	bins := []binscan.Binary{mainVersionBinary(root+"/bin/k3s", mod, "(devel)")}

	p := New(Options{Image: "docker.io/rancher/k3s:v1.36.3-k3s1"})
	comps := p.groupAll(root, bins)

	c := mainComponent(comps, mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "v1.36.3+k3s1" {
		t.Errorf("version = %q, want v1.36.3+k3s1 (inferred from image tag)", c.Version)
	}
	note := c.Extra.(*state).inferredNote
	if note == "" || !strings.Contains(note, "v1.36.3-k3s1") {
		t.Errorf("inferredNote = %q, want a provenance note citing the image tag", note)
	}
}

func TestGroupAllKeepsDevelWhenTagNotUsable(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/k3s-io/k3s"
	bins := []binscan.Binary{mainVersionBinary(root+"/bin/k3s", mod, "(devel)")}

	// A floating tag is not a version: inference is refused and the original
	// "(devel)" is kept, which over-reports rather than guessing.
	p := New(Options{Image: "docker.io/rancher/k3s:latest"})
	comps := p.groupAll(root, bins)

	c := mainComponent(comps, mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "(devel)" {
		t.Errorf("version = %q, want (devel) unchanged", c.Version)
	}
	if note := c.Extra.(*state).inferredNote; note != "" {
		t.Errorf("inferredNote = %q, want empty (nothing was inferred)", note)
	}
}

// A Go binary that merely happens to live in somebody else's image must not
// take that image's version. python:3.12.1 is a real, clean semver tag, and
// v3.12.1 is wildly higher than anything this module has released -- so OSV
// would range it past every advisory and report the binary as clean. That is
// the under-report direction, so the tag is refused and "(devel)" is kept.
func TestGroupAllRefusesAnUnrelatedImageTag(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/some/tool"
	bins := []binscan.Binary{mainVersionBinary(root+"/bin/tool", mod, "(devel)")}

	p := New(Options{Image: "python:3.12.1"})
	comps := p.groupAll(root, bins)

	c := mainComponent(comps, mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "(devel)" {
		t.Errorf("version = %q, want (devel): python's version is not this module's", c.Version)
	}
	if note := c.Extra.(*state).inferredNote; note != "" {
		t.Errorf("inferredNote = %q, want empty (nothing was inferred)", note)
	}
}

// The note has to say why the tag was believed, not just that it was. An
// inference a reader cannot audit is barely better than a silent one.
func TestTheInferredNoteNamesItsAuthority(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "github.com/k3s-io/k3s"
	bins := []binscan.Binary{mainVersionBinary(root+"/bin/k3s", mod, "(devel)")}

	p := New(Options{Image: "docker.io/rancher/k3s:v1.36.3-k3s1"})
	c := mainComponent(p.groupAll(root, bins), mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	note := c.Extra.(*state).inferredNote
	for _, want := range []string{"version not in build info", "v1.36.3-k3s1", "build suffix"} {
		if !strings.Contains(note, want) {
			t.Errorf("inferredNote = %q, missing %q", note, want)
		}
	}
}

func TestGroupAllRealMainVersionIsUntouched(t *testing.T) {
	const root = "/tmp/extract"
	const mod = "example.com/app"
	bins := []binscan.Binary{mainVersionBinary(root+"/bin/app", mod, "v1.0.0")}

	// Even with an image tag present, a main module that already has a real
	// version must not be overwritten by the tag.
	p := New(Options{Image: "example.com/app:v9.9.9"})
	comps := p.groupAll(root, bins)

	c := mainComponent(comps, mod)
	if c == nil {
		t.Fatalf("main module %s missing from inventory", mod)
	}
	if c.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0 (build-info version preserved)", c.Version)
	}
	if note := c.Extra.(*state).inferredNote; note != "" {
		t.Errorf("inferredNote = %q, want empty", note)
	}
}

func TestGroupComponents(t *testing.T) {
	const root = "/tmp/extract"
	bins := []binscan.Binary{
		fakeBinary(root+"/usr/bin/a", map[string]string{"golang.org/x/net": "v0.17.0"}),
		fakeBinary(root+"/usr/bin/b", map[string]string{"golang.org/x/net": "v0.17.0"}),
		fakeBinary(root+"/usr/bin/c", map[string]string{"golang.org/x/net": "v0.18.0"}),
		fakeBinary(root+"/usr/bin/d", map[string]string{"golang.org/x/text": "v0.14.0"}),
	}

	got := New(Options{}).group(root, bins, []string{"golang.org/x/net"})
	if len(got) != 2 {
		t.Fatalf("got %d components, want 2 (one per version)", len(got))
	}

	// Two binaries linking the same version share one component, so the
	// orchestrator makes one OSV query and still reports per binary.
	if want := []string{"/usr/bin/a", "/usr/bin/b"}; !reflect.DeepEqual(got[0].Locations, want) {
		t.Errorf("locations = %v, want %v", got[0].Locations, want)
	}
	if got[0].Version != "v0.17.0" || got[1].Version != "v0.18.0" {
		t.Errorf("versions = %q, %q", got[0].Version, got[1].Version)
	}
	if got[0].Ecosystem != "Go" {
		t.Errorf("ecosystem = %q, want Go", got[0].Ecosystem)
	}
	if got[0].PURL != "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0" {
		t.Errorf("purl = %q", got[0].PURL)
	}
	if got[0].Key() == got[1].Key() {
		t.Error("different versions must not share a component key")
	}

	st, ok := got[0].Extra.(*state)
	if !ok || len(st.binaries) != 2 {
		t.Fatalf("Extra should carry both binaries, got %+v", got[0].Extra)
	}
	if st.binaries[0].path != root+"/usr/bin/a" {
		t.Errorf("binary path = %q", st.binaries[0].path)
	}
}

func TestGroupSkipsBinariesWithoutTheModule(t *testing.T) {
	const root = "/tmp/extract"
	bins := []binscan.Binary{fakeBinary(root+"/usr/bin/a", map[string]string{"golang.org/x/text": "v0.14.0"})}
	if got := New(Options{}).group(root, bins, []string{"golang.org/x/net"}); len(got) != 0 {
		t.Errorf("got %d components, want 0", len(got))
	}
}

// The override exists for binaries whose build info reports a version OSV
// cannot match, so it has to apply even where the module is not a listed dep.
func TestGroupHonorsVersionOverride(t *testing.T) {
	const root = "/tmp/extract"
	bins := []binscan.Binary{fakeBinary(root+"/usr/bin/a", nil)}
	got := New(Options{VersionOverride: "v0.17.0"}).group(root, bins, []string{"golang.org/x/net"})
	if len(got) != 1 || got[0].Version != "v0.17.0" {
		t.Fatalf("got %+v, want one component at v0.17.0", got)
	}
}

func TestGroupStdlibUsesTheToolchainVersion(t *testing.T) {
	const root = "/tmp/extract"
	bins := []binscan.Binary{fakeBinary(root+"/usr/bin/a", nil)}
	got := New(Options{}).group(root, bins, []string{StdlibModule})
	if len(got) != 1 || got[0].Version != "1.24.0" {
		t.Fatalf("got %+v, want stdlib at 1.24.0", got)
	}
}

func TestGroupAllEnumeratesEveryLinkedModule(t *testing.T) {
	const root = "/tmp/extract"
	bins := []binscan.Binary{
		fakeBinary(root+"/usr/bin/a", map[string]string{"golang.org/x/net": "v0.17.0"}),
		fakeBinary(root+"/usr/bin/b", map[string]string{"golang.org/x/net": "v0.17.0", "golang.org/x/text": "v0.14.0"}),
		{Path: root + "/usr/bin/not-go"}, // no build info; must not panic or appear
	}

	var got []string
	for _, c := range New(Options{}).groupAll(root, bins) {
		got = append(got, c.Name+"@"+c.Version)
	}
	sort.Strings(got)

	// The main module and the toolchain are enumerated alongside the deps:
	// both carry advisories, and neither shows up in Deps.
	want := []string{
		"example.com/app@v1.0.0",
		"golang.org/x/net@v0.17.0",
		"golang.org/x/text@v0.14.0",
		"stdlib@1.24.0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAnalyzeImageAttachesInferredVersionEvidence(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "k3s")
	if err := os.WriteFile(binPath, []byte("not a real elf, just needs to be readable"), 0o644); err != nil {
		t.Fatal(err)
	}

	const mod = "github.com/k3s-io/k3s"
	const note = "version not in build info (reported (devel)); inferred from image tag \"v1.36.3-k3s1\""
	comp := ecosystem.Component{
		Ecosystem: "Go",
		Name:      mod,
		Version:   "v1.36.3+k3s1",
		PURL:      purl(mod, "v1.36.3+k3s1"),
		Extra: &state{
			binaries:     []binary{{path: binPath, rel: "/bin/k3s", main: mod}},
			inferredNote: note,
		},
	}
	// A requested id with no advisory: evaluate returns undetermined without
	// needing a real Go binary, and we only care that provenance is attached.
	item := ecosystem.WorkItem{Component: comp, Requested: []string{"CVE-2024-0001"}, Targeted: true}

	findings, err := New(Options{}).AnalyzeImage(context.Background(), &target.Image{}, []ecosystem.WorkItem{item})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	var found bool
	for _, e := range findings[0].Evidence {
		if e.Origin == "image-tag-version" && e.Detail == note {
			found = true
		}
	}
	if !found {
		t.Errorf("finding is missing image-tag-version provenance evidence: %+v", findings[0].Evidence)
	}
}

func TestGroupAllSharesOneComponentAcrossBinaries(t *testing.T) {
	const root = "/tmp/extract"
	bins := []binscan.Binary{
		fakeBinary(root+"/usr/bin/a", map[string]string{"golang.org/x/net": "v0.17.0"}),
		fakeBinary(root+"/usr/bin/b", map[string]string{"golang.org/x/net": "v0.17.0"}),
	}
	for _, c := range New(Options{}).groupAll(root, bins) {
		if c.Name != "golang.org/x/net" {
			continue
		}
		// One component means one OSV query for both binaries, which is what
		// keeps a whole-image enumeration to a survivable number of lookups.
		if want := []string{"/usr/bin/a", "/usr/bin/b"}; !reflect.DeepEqual(c.Locations, want) {
			t.Errorf("locations = %v, want %v", c.Locations, want)
		}
		return
	}
	t.Fatal("golang.org/x/net missing from the enumeration")
}

func TestDetectSource(t *testing.T) {
	p := New(Options{})

	t.Run("a tree with go.mod is Go", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ok, err := p.DetectSource(context.Background(), &target.Source{Dir: dir, FS: target.NewDirFS(dir)})
		if err != nil || !ok {
			t.Errorf("DetectSource = %v, %v; want true, nil", ok, err)
		}
	})

	t.Run("a tree without go.mod is not", func(t *testing.T) {
		dir := t.TempDir()
		ok, err := p.DetectSource(context.Background(), &target.Source{Dir: dir, FS: target.NewDirFS(dir)})
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("DetectSource = true for a tree with no go.mod")
		}
	})
}

func TestDetectImageAlwaysApplies(t *testing.T) {
	// A Go binary can appear in any image, including one built FROM scratch, so
	// there is nothing to detect on and the inventory walk is the real test.
	ok, err := New(Options{}).DetectImage(context.Background(), &target.Image{})
	if err != nil || !ok {
		t.Errorf("DetectImage = %v, %v; want true, nil", ok, err)
	}
}

func stmt(goID, cve, module, version, status, justification string) source.Statement {
	s := source.Statement{
		GoID:          goID,
		Module:        module,
		Version:       version,
		Status:        status,
		Justification: justification,
	}
	if cve != "" {
		s.Aliases = []string{cve}
	}
	return s
}

func TestFindingsForModule(t *testing.T) {
	const module = "golang.org/x/net"
	stmts := []source.Statement{
		stmt("GO-2023-2102", "CVE-2023-39325", module, "v0.17.0", "affected", ""),
		stmt("GO-2023-1988", "CVE-2023-3978", module, "v0.17.0", "not_affected", "vulnerable_code_not_in_execute_path"),
		stmt("GO-2022-1144", "CVE-2022-41717", module, "v0.17.0", "not_affected", ""),
		stmt("GO-2024-9999", "CVE-2024-9999", "golang.org/x/text", "v0.14.0", "affected", ""),
	}

	t.Run("all mode reports one finding per advisory, other modules excluded", func(t *testing.T) {
		got := findingsForModule(module, stmts, nil, true)
		if len(got) != 3 {
			t.Fatalf("got %d findings, want 3", len(got))
		}
		want := []struct {
			cve           string
			status        ecosystem.Status
			justification string
			reachability  string
		}{
			{"CVE-2023-39325", ecosystem.StatusReachable, "", "reachable (govulncheck source mode: the vulnerable symbol is called)"},
			{"CVE-2023-3978", ecosystem.StatusNotInPath, "vulnerable_code_not_in_execute_path", ""},
			{"CVE-2022-41717", ecosystem.StatusNotPresent, "vulnerable_code_not_present", ""},
		}
		for i, w := range want {
			f := got[i]
			if f.CVE != w.cve || f.Status != w.status || f.Justification != w.justification || f.Reachability != w.reachability {
				t.Errorf("findings[%d] = %+v, want %v/%v/%v/%v", i, f, w.cve, w.status, w.justification, w.reachability)
			}
			if f.Method != "govulncheck-source" {
				t.Errorf("findings[%d].Method = %q", i, f.Method)
			}
			if f.Version != "v0.17.0" {
				t.Errorf("findings[%d].Version = %q", i, f.Version)
			}
		}
	})

	t.Run("a requested id matches its GO id as well as its CVE alias", func(t *testing.T) {
		got := findingsForModule(module, stmts, []string{"GO-2023-2102"}, true)
		if len(got) != 1 || got[0].Status != ecosystem.StatusReachable {
			t.Fatalf("got %+v", got)
		}
		if got[0].CVE != "GO-2023-2102" {
			t.Errorf("the finding should be reported under the id that was asked for, got %q", got[0].CVE)
		}
	})

	// govulncheck analyzed the module and did not flag this id: that is real
	// evidence of absence.
	t.Run("an unflagged id in an analyzed module is not_present", func(t *testing.T) {
		got := findingsForModule(module, stmts, []string{"CVE-9999-0001"}, true)
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1", len(got))
		}
		f := got[0]
		if f.Status != ecosystem.StatusNotPresent || f.Justification != "vulnerable_code_not_present" {
			t.Errorf("got %s/%s, want not_present/vulnerable_code_not_present", f.Status, f.Justification)
		}
		if f.Reason != "not flagged by govulncheck source analysis" {
			t.Errorf("Reason = %q", f.Reason)
		}
		if f.Version != "v0.17.0" {
			t.Errorf("Version = %q, want the version that was scanned", f.Version)
		}
	})

	// The module was never in the dependency graph, so nothing was analyzed.
	// Reporting that as not_present would publish a VEX statement about code
	// that was never examined.
	t.Run("an id in an unanalyzed module is undetermined", func(t *testing.T) {
		got := findingsForModule("example.com/never-seen", stmts, []string{"CVE-9999-0001"}, true)
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1", len(got))
		}
		f := got[0]
		if f.Status != ecosystem.StatusUndetermined {
			t.Errorf("status = %s, want undetermined", f.Status)
		}
		if f.Reason != "module_not_in_dependency_graph" {
			t.Errorf("Reason = %q", f.Reason)
		}
		if f.Justification != "" {
			t.Errorf("an unexamined module must carry no justification, got %q", f.Justification)
		}
	})

	t.Run("all mode over an unanalyzed module reports nothing", func(t *testing.T) {
		if got := findingsForModule("example.com/never-seen", stmts, nil, true); len(got) != 0 {
			t.Errorf("got %d findings, want 0", len(got))
		}
	})

	// Enumeration reaches every module govulncheck mentioned, so a requested id
	// belonging to some other module has already been reported by that module's
	// pass. Repeating it here as undetermined would contradict it.
	t.Run("an enumerated module drops a requested id that belongs elsewhere", func(t *testing.T) {
		if got := findingsForModule(module, stmts, []string{"CVE-2024-9999"}, false); len(got) != 0 {
			t.Errorf("got %+v, want no findings", got)
		}
	})
}

func TestFlaggedModules(t *testing.T) {
	stmts := []source.Statement{
		stmt("GO-2024-9999", "", "golang.org/x/text", "v0.14.0", "affected", ""),
		stmt("GO-2023-2102", "", "golang.org/x/net", "v0.17.0", "affected", ""),
		stmt("GO-2023-1988", "", "golang.org/x/net", "v0.17.0", "not_affected", ""),
		stmt("GO-2023-0000", "", "", "", "affected", ""),
	}
	got := flaggedModules(stmts)
	want := []string{"golang.org/x/net", "golang.org/x/text"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (distinct, sorted, no empty module)", got, want)
	}
}

func TestPrimaryID(t *testing.T) {
	if got := primaryID(source.Statement{GoID: "GO-1", Aliases: []string{"GHSA-x", "CVE-2023-1"}}); got != "CVE-2023-1" {
		t.Errorf("got %q, want the CVE alias", got)
	}
	if got := primaryID(source.Statement{GoID: "GO-1", Aliases: []string{"GHSA-x"}}); got != "GO-1" {
		t.Errorf("got %q, want the GO id", got)
	}
}

// AnalyzeImage must refuse a component it did not produce rather than silently
// analyzing nothing.
func TestAnalyzeImageRejectsForeignComponents(t *testing.T) {
	_, err := New(Options{}).AnalyzeImage(context.Background(), &target.Image{}, []ecosystem.WorkItem{
		{Component: ecosystem.Component{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"}},
	})
	if err == nil {
		t.Fatal("expected an error for a component from another plugin")
	}
	if !strings.Contains(err.Error(), "openssl") {
		t.Errorf("the error should name the component, got %v", err)
	}
}

func TestPluginIdentity(t *testing.T) {
	p := New(Options{})
	if p.ID() != "golang" {
		t.Errorf("ID = %q", p.ID())
	}
	if !reflect.DeepEqual(p.Ecosystems(), []string{"Go"}) {
		t.Errorf("Ecosystems = %v", p.Ecosystems())
	}
	if !ecosystem.MatchEcosystem(p, "Go") || !ecosystem.MatchEcosystem(p, "golang") {
		t.Error("the plugin should be selectable by both its id and its ecosystem")
	}
}

// sbomFindings runs the whole plugin over one advisory with a handed-in
// inventory and no binaries to find.
func sbomFindings(t *testing.T, mods []Module, subjects []ecosystem.Subject) []ecosystem.Finding {
	t.Helper()
	ctx := context.Background()
	// The empty tree --sbom stands up: there is nothing in it, and nothing
	// below may go looking.
	img := &target.Image{Ref: "--sbom bom.json", FS: target.NewDirFS(t.TempDir())}
	p := New(Options{Modules: mods})

	comps, err := p.InventoryImage(ctx, img, subjects)
	if err != nil {
		t.Fatalf("InventoryImage: %v", err)
	}
	adv := &osv.Advisory{ID: "CVE-2024-0001", Summary: "a hole"}
	items := make([]ecosystem.WorkItem, 0, len(comps))
	for _, c := range comps {
		items = append(items, ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{adv.ID: adv},
			Requested:  []string{adv.ID},
			Targeted:   len(subjects) > 0 && !subjects[0].MatchesAll(),
		})
	}
	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatalf("AnalyzeImage: %v", err)
	}
	return findings
}

// A handed-in inventory decides nothing. Every test this plugin makes reads a
// binary -- the symbol table, or govulncheck over it -- and there is no
// binary; without the metadata branch the loop over an empty binary list
// reports nothing at all for a module the document plainly names, which reads
// as a module with no advisories against it.
func TestSBOMModulesAreReportedAndUndetermined(t *testing.T) {
	mods := []Module{{Path: "golang.org/x/net", Version: "v0.17.0"}}

	findings := sbomFindings(t, mods, []ecosystem.Subject{{Raw: "all"}})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Module != "golang.org/x/net" || f.Version != "v0.17.0" {
		t.Errorf("coordinates = %s@%s, want golang.org/x/net@v0.17.0", f.Module, f.Version)
	}
	if f.Status != ecosystem.StatusUndetermined {
		t.Errorf("status = %q, want %q", f.Status, ecosystem.StatusUndetermined)
	}
	if f.Reason != ecosystem.ReasonNoReachabilityTest {
		t.Errorf("reason = %q, want %q -- the report sizes its caveat by counting this",
			f.Reason, ecosystem.ReasonNoReachabilityTest)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Origin != ecosystem.OriginSBOM {
		t.Fatalf("evidence = %+v, want one row from %q", f.Evidence, ecosystem.OriginSBOM)
	}
	if !strings.Contains(f.Evidence[0].Detail, "bill of materials") {
		t.Errorf("evidence does not say where it came from: %q", f.Evidence[0].Detail)
	}
}

// The same module listed twice is one thing to say, and a subject naming one
// module selects only that one -- the two filters group and groupAll apply to
// binaries, applied here to a document instead.
func TestSBOMModulesAreDedupedAndSelectable(t *testing.T) {
	mods := []Module{
		{Path: "golang.org/x/net", Version: "v0.17.0"},
		{Path: "golang.org/x/net", Version: "v0.17.0"},
		{Path: "golang.org/x/text", Version: "v0.13.0"},
	}

	if got := len(sbomFindings(t, mods, []ecosystem.Subject{{Raw: "all"}})); got != 2 {
		t.Errorf("got %d findings for --all, want 2 (the repeat is one module)", got)
	}

	one := sbomFindings(t, mods, []ecosystem.Subject{{Name: "golang.org/x/text", Raw: "golang.org/x/text"}})
	if len(one) != 1 || one[0].Module != "golang.org/x/text" {
		t.Errorf("a named module selected %+v, want only golang.org/x/text", one)
	}
}
