package golang

import (
	"context"
	"debug/buildinfo"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
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
		got, err := p.wantedModules([]ecosystem.Subject{{Name: "golang.org/x/net"}})
		if err != nil {
			t.Fatal(err)
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
		got, err := p.wantedModules([]ecosystem.Subject{{PURL: "pkg:golang/golang.org%2Fx%2Fnet@v0.17.0"}})
		if err != nil {
			t.Fatal(err)
		}
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
		got, err := p.wantedModules([]ecosystem.Subject{
			{Ecosystem: "os", Name: "openssl"},
			{Ecosystem: "golang", Name: "golang.org/x/net"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"golang.org/x/net"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	// Enumerating every dependency of every binary is a different, much larger
	// scan. Refusing is deliberate: returning an empty inventory would render
	// as an image with no Go dependencies at all.
	t.Run("scan-everything is refused, not silently empty", func(t *testing.T) {
		if _, err := p.wantedModules([]ecosystem.Subject{{}}); err == nil {
			t.Error("expected an error for a subject that matches everything")
		}
	})

	t.Run("no subject at all is an error", func(t *testing.T) {
		if _, err := p.wantedModules(nil); err == nil {
			t.Error("expected an error when nothing was selected")
		}
	})
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
		got := findingsForModule(module, stmts, nil)
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
		got := findingsForModule(module, stmts, []string{"GO-2023-2102"})
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
		got := findingsForModule(module, stmts, []string{"CVE-9999-0001"})
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
		got := findingsForModule("example.com/never-seen", stmts, []string{"CVE-9999-0001"})
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
		if got := findingsForModule("example.com/never-seen", stmts, nil); len(got) != 0 {
			t.Errorf("got %d findings, want 0", len(got))
		}
	})
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
