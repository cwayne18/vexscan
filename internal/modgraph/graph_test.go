package modgraph

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

// fakeLang is a language whose whole world is a map from file to the
// specifiers it imports, and a map from specifier to files. It exercises the
// walk without dragging in a filesystem or a real parser -- the same way
// internal/elfgraph/graph_test.go tests the closure without ELF fixtures.
type fakeLang struct {
	roots      []Root
	rootTaints []Taint
	imports    map[string][]Spec
	resolve    map[string][]string // specifier -> files
	unreadable map[string]bool
	fileTaints map[string][]Taint
}

func (f *fakeLang) ID() string { return "fake" }

func (f *fakeLang) Roots(extra []string) ([]Root, []Taint, error) {
	out := append([]Root{}, f.roots...)
	for _, e := range extra {
		out = append(out, Root{Path: e, Why: "named by --roots", Kind: RootExplicit})
	}
	return out, f.rootTaints, nil
}

func (f *fakeLang) Imports(file string) ([]Spec, []Taint, error) {
	if f.unreadable[file] {
		return nil, nil, errors.New("permission denied")
	}
	return f.imports[file], f.fileTaints[file], nil
}

func (f *fakeLang) Resolve(from string, spec Spec) ([]string, bool) {
	// A leading dot means relative: resolve against the importer's directory,
	// so the walk's handling of one specifier meaning different files in
	// different places is covered.
	if strings.HasPrefix(spec.Name, ".") {
		dir := from[:strings.LastIndex(from, "/")+1]
		t, ok := f.resolve[dir+strings.TrimPrefix(spec.Name, ".")]
		return t, ok
	}
	t, ok := f.resolve[spec.Name]
	return t, ok
}

func (f *fakeLang) IsModule(p string) bool { return strings.HasSuffix(p, ".py") }

func imports(names ...string) []Spec {
	out := make([]Spec, 0, len(names))
	for _, n := range names {
		out = append(out, Spec{Name: n})
	}
	return out
}

func build(t *testing.T, l *fakeLang, opts Options) *Graph {
	t.Helper()
	g, err := Build(nil, l, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return g
}

func TestClosureFollowsImportsTransitively(t *testing.T) {
	g := build(t, &fakeLang{
		roots: []Root{{Path: "/app/main.py", Why: "entrypoint", Kind: RootEntry}},
		imports: map[string][]Spec{
			"/app/main.py":         imports("yaml"),
			"/sp/yaml/__init__.py": imports("yaml.loader"),
			// Reached but imports nothing further.
			"/sp/yaml/loader.py": nil,
			// Installed and never imported by anything.
			"/sp/requests/__init__.py": imports("urllib3"),
		},
		resolve: map[string][]string{
			"yaml":        {"/sp/yaml/__init__.py"},
			"yaml.loader": {"/sp/yaml/loader.py"},
			"urllib3":     {"/sp/urllib3/__init__.py"},
		},
	}, Options{})

	if got := g.CountReachable(); got != 3 {
		t.Errorf("reachable = %d, want 3 (main, yaml, yaml.loader): %v", got, paths(g))
	}
	if !g.Reachable("/sp/yaml/loader.py") {
		t.Error("the transitive import is not in the closure")
	}
	if g.Reachable("/sp/requests/__init__.py") {
		t.Error("an unimported distribution is in the closure")
	}

	// The point of the whole package: an installed distribution nothing
	// imports classifies as owning modules, none of them reached.
	fs := g.Classify([]string{"/sp/requests/__init__.py", "/sp/requests/LICENSE"})
	if len(fs.Module) != 1 || len(fs.Reachable) != 0 {
		t.Errorf("Classify(requests) = %+v, want one module and no reachable", fs)
	}
	if fs := g.Classify([]string{"/sp/yaml/__init__.py", "/sp/yaml/loader.py"}); len(fs.Reachable) != 2 {
		t.Errorf("Classify(yaml) = %+v, want both reachable", fs)
	}
}

// A cycle is the normal case in Python -- a package's __init__ imports a
// submodule that imports the package -- and must terminate.
func TestCycleTerminates(t *testing.T) {
	g := build(t, &fakeLang{
		roots: []Root{{Path: "/a.py", Kind: RootEntry}},
		imports: map[string][]Spec{
			"/a.py": imports("b"),
			"/b.py": imports("a"),
		},
		resolve: map[string][]string{"a": {"/a.py"}, "b": {"/b.py"}},
	}, Options{})

	if got := g.CountReachable(); got != 2 {
		t.Errorf("reachable = %d, want 2: %v", got, paths(g))
	}
	if n, _ := g.Node("/a.py"); len(n.ImportedBy) != 1 || n.ImportedBy[0] != "/b.py" {
		t.Errorf("ImportedBy = %v, want the other half of the cycle", n.ImportedBy)
	}
}

// One specifier can resolve to several files: a PEP 420 namespace package
// merges across sys.path entries, and both halves are reachable.
func TestOneSpecifierResolvingToSeveralFiles(t *testing.T) {
	g := build(t, &fakeLang{
		roots:   []Root{{Path: "/main.py", Kind: RootEntry}},
		imports: map[string][]Spec{"/main.py": imports("ns")},
		resolve: map[string][]string{"ns": {"/sp1/ns/mod.py", "/sp2/ns/other.py"}},
	}, Options{})

	if !g.Reachable("/sp1/ns/mod.py") || !g.Reachable("/sp2/ns/other.py") {
		t.Errorf("both halves of the namespace package should be reachable: %v", paths(g))
	}
}

func TestRelativeImportsResolveAgainstTheImporter(t *testing.T) {
	g := build(t, &fakeLang{
		roots: []Root{{Path: "/pkg/__init__.py", Kind: RootEntry}},
		imports: map[string][]Spec{
			"/pkg/__init__.py": imports(".sub"),
			"/pkg/sub.py":      imports(".helper"),
		},
		resolve: map[string][]string{
			"/pkg/sub":    {"/pkg/sub.py"},
			"/pkg/helper": {"/pkg/helper.py"},
		},
	}, Options{})

	if !g.Reachable("/pkg/helper.py") {
		t.Errorf("the relative import did not resolve against the importer: %v", paths(g))
	}
}

// An unresolved specifier blocks conclusions about the name it points at, and
// nothing else. Scoping this wrongly would taint every scan on one typo.
func TestUnresolvedImportIsScopedToItsSpecifier(t *testing.T) {
	g := build(t, &fakeLang{
		roots:   []Root{{Path: "/main.py", Kind: RootEntry}},
		imports: map[string][]Spec{"/main.py": imports("missing.thing")},
	}, Options{})

	ts := g.Taints()
	if len(ts) != 1 || ts[0].Kind != TaintUnresolvedImport || !ts[0].Blocking {
		t.Fatalf("taints = %+v, want one blocking unresolved-import", ts)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Error("a scoped taint must not block every distribution in the image")
	}
	if got := g.TaintsFor([]string{"missing"}); len(got) != 1 {
		t.Errorf("the distribution owning the specifier should see it: %+v", got)
	}
	if got := g.TaintsFor([]string{"yaml"}); len(got) != 0 {
		t.Errorf("an unrelated distribution should not: %+v", got)
	}
}

// A reachable file that will not read hides everything downstream of it, so it
// blocks globally -- the graph is missing an unknown amount.
func TestUnreadableReachableModuleBlocksGlobally(t *testing.T) {
	g := build(t, &fakeLang{
		roots:      []Root{{Path: "/main.py", Kind: RootEntry}},
		unreadable: map[string]bool{"/main.py": true},
	}, Options{})

	bt := g.BlockingTaints()
	if len(bt) != 1 || bt[0].Kind != TaintUnreadable {
		t.Fatalf("blocking taints = %+v, want one unreadable-module", bt)
	}
}

// The dynamic-import policy is applied by the graph, not by each language, so
// that one flag means one thing everywhere.
func TestDynamicPolicyDemotesRatherThanDrops(t *testing.T) {
	lang := func() *fakeLang {
		return &fakeLang{
			roots:      []Root{{Path: "/main.py", Kind: RootEntry}},
			fileTaints: map[string][]Taint{"/main.py": {{Kind: TaintDynamicImport, Detail: "import_module(name)", Path: "/main.py", Scope: []string{"app"}, Blocking: true, Global: true}}},
		}
	}

	if bt := build(t, lang(), Options{}).BlockingTaints(); len(bt) != 1 {
		t.Errorf("by default a computed import blocks: %+v", bt)
	}

	g := build(t, lang(), Options{Dynamic: DynamicAssumeNone})
	if bt := g.BlockingTaints(); len(bt) != 0 {
		t.Errorf("assume-none should stop it blocking: %+v", bt)
	}
	if ts := g.Taints(); len(ts) != 1 || ts[0].Blocking {
		t.Errorf("the observation must survive as a record: %+v", ts)
	}
}

// Escalation is a Language decision; what the graph guarantees is that the
// reason travels with it.
func TestEscalatedRootsCarryTheirTaint(t *testing.T) {
	g := build(t, &fakeLang{
		roots: []Root{
			{Path: "/sp/a/__init__.py", Why: "entrypoint is not a Python interpreter", Kind: RootEscalated},
			{Path: "/sp/b/__init__.py", Why: "entrypoint is not a Python interpreter", Kind: RootEscalated},
		},
		rootTaints: []Taint{{Kind: TaintForeignEntrypoint, Detail: "argv[0] is /bin/sh", Blocking: true, Global: true}},
	}, Options{})

	if len(g.Roots()) != 2 || g.CountReachable() != 2 {
		t.Errorf("escalation should root every module: %v", paths(g))
	}
	if bt := g.BlockingTaints(); len(bt) != 1 || bt[0].Kind != TaintForeignEntrypoint {
		t.Errorf("blocking taints = %+v", bt)
	}
	if n, _ := g.Node("/sp/a/__init__.py"); n.Kind != RootEscalated {
		t.Errorf("the root kind is what tells a reader this is a guess, got %q", n.Kind)
	}
}

func TestExplicitRootsAreAdded(t *testing.T) {
	g := build(t, &fakeLang{
		roots:   []Root{{Path: "/main.py", Kind: RootEntry}},
		imports: map[string][]Spec{"/plugin.py": imports("yaml")},
		resolve: map[string][]string{"yaml": {"/sp/yaml/__init__.py"}},
	}, Options{Roots: []string{"/plugin.py"}})

	if !g.Reachable("/sp/yaml/__init__.py") {
		t.Errorf("the --roots value was not walked: %v", paths(g))
	}
	if n, _ := g.Node("/plugin.py"); n.Kind != RootExplicit {
		t.Errorf("kind = %q, want explicit", n.Kind)
	}
}

// Classify reports modules the walk never visited, because "installed and
// unreached" is the answer the whole package exists to produce. A file that is
// not code is in neither list.
func TestClassifyIgnoresNonModules(t *testing.T) {
	g := build(t, &fakeLang{roots: []Root{{Path: "/main.py", Kind: RootEntry}}}, Options{})

	fs := g.Classify([]string{"/sp/x/LICENSE", "/sp/x/data.json", "/sp/x/mod.py", "/sp/x/mod.py"})
	if len(fs.Module) != 1 || fs.Module[0] != "/sp/x/mod.py" {
		t.Errorf("Module = %v, want just the one module, deduplicated", fs.Module)
	}
	if len(fs.Reachable) != 0 {
		t.Errorf("Reachable = %v", fs.Reachable)
	}
}

func paths(g *Graph) []string {
	var out []string
	for _, n := range g.Nodes() {
		if n.Reachable {
			out = append(out, n.Path)
		}
	}
	sort.Strings(out)
	return out
}
