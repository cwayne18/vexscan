package pypi

import (
	"sort"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/target"
)

// pyGraph builds the import closure over a fake tree, the way the plugin will.
func pyGraph(t *testing.T, img *target.Image, opts modgraph.Options) (*python, *modgraph.Graph) {
	t.Helper()
	roots, err := langdb.FindRoots(img.FS)
	if err != nil {
		t.Fatalf("FindRoots: %v", err)
	}
	res, err := (&langdb.PyPI{}).Read(img.FS, roots[langdb.FormatPyPI])
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	lang := newPython(img, res, nil)
	g, err := modgraph.Build(img.FS, lang, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return lang, g
}

func specNames(specs []modgraph.Spec) []string {
	var out []string
	for _, s := range specs {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

func TestScannerReadsEveryFormOfImport(t *testing.T) {
	src := `#!/usr/bin/env python
"""A docstring mentioning import nothing_at_all."""
import os
import os.path, sys as system
from yaml import safe_load, Loader
from .relative import thing
from . import sibling
from pkg import (
    alpha,
    beta,
)
import trailing  # comment: import ignored_by_the_comment
x = "#not a comment"; import after_semicolon
from long import \
    continued
`
	sr := scanPython([]byte(src))
	got := specNames(sr.specs)
	want := []string{
		".relative", ".relative.thing", ".sibling",
		"after_semicolon", "long", "long.continued", "os", "os.path",
		"pkg", "pkg.alpha", "pkg.beta", "sys",
		"trailing", "yaml", "yaml.Loader", "yaml.safe_load",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("specs =\n  %v\nwant\n  %v", got, want)
	}

	// The submodule candidates from "from x import y" must be optional: y is
	// usually a class, and a taint that fires on ordinary code is noise.
	for _, s := range sr.specs {
		if s.Name == "yaml.safe_load" && !s.Optional {
			t.Error("from-import names must be optional specifiers")
		}
		if s.Name == "yaml" && s.Optional {
			t.Error("the package in a from-import is not optional")
		}
	}
	if len(sr.computed) != 0 {
		t.Errorf("nothing here is a computed import: %v", sr.computed)
	}
}

func TestScannerSeparatesLiteralFromComputedDynamicImports(t *testing.T) {
	sr := scanPython([]byte(`
import importlib
mod = importlib.import_module("configured.plugin")
other = importlib.import_module(name)
legacy = __import__("six")
`))
	got := specNames(sr.specs)
	want := []string{"configured.plugin", "importlib", "six"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("specs = %v, want %v", got, want)
	}
	if len(sr.computed) != 1 {
		t.Errorf("computed = %v, want exactly the non-literal call", sr.computed)
	}
}

// A file at the end of an entrypoint chain, with a distribution reached
// through two hops and another installed but never imported.
func TestGraphOverAnApplicationImage(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":                     "",
		"/app/main.py":                                  "import yaml\nfrom app import helper\n",
		"/app/app/__init__.py":                          "",
		"/app/app/helper.py":                            "import os\n",
		sp + "/PyYAML-6.0.1.dist-info/METADATA":         "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.0.1.dist-info/top_level.txt":    "yaml\n",
		sp + "/PyYAML-6.0.1.dist-info/RECORD":           record("yaml/__init__.py", "yaml/loader.py"),
		sp + "/yaml/__init__.py":                        "from .loader import Loader\n",
		sp + "/yaml/loader.py":                          "",
		sp + "/requests-2.31.0.dist-info/METADATA":      "Name: requests\nVersion: 2.31.0\n",
		sp + "/requests-2.31.0.dist-info/top_level.txt": "requests\n",
		sp + "/requests-2.31.0.dist-info/RECORD":        record("requests/__init__.py"),
		sp + "/requests/__init__.py":                    "",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})

	for _, f := range []string{"/app/main.py", "/app/app/helper.py", sp + "/yaml/__init__.py", sp + "/yaml/loader.py"} {
		if !g.Reachable(f) {
			t.Errorf("%s should be reachable: %v", f, g.Roots())
		}
	}
	if g.Reachable(sp + "/requests/__init__.py") {
		t.Error("requests is installed and never imported; it must not be reachable")
	}
	if bt := g.BlockingTaints(); len(bt) != 0 {
		t.Errorf("nothing here is unknowable: %+v", bt)
	}

	// The two conclusions the evaluator will draw from this graph.
	if fs := g.Classify([]string{sp + "/yaml/__init__.py", sp + "/yaml/loader.py"}); len(fs.Reachable) != 2 {
		t.Errorf("Classify(pyyaml) = %+v", fs)
	}
	if fs := g.Classify([]string{sp + "/requests/__init__.py"}); len(fs.Module) != 1 || len(fs.Reachable) != 0 {
		t.Errorf("Classify(requests) = %+v, want installed and unreached", fs)
	}
}

func TestStdlibImportsResolveAndBuiltinsDoNotTaint(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":     "",
		"/usr/lib/python3.12/typing.py": "",
		"/app/main.py":                  "import os, sys, typing, time\n",
		sp + "/x-1.dist-info/METADATA":  "Name: x\nVersion: 1\n",
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable("/usr/lib/python3.12/typing.py") {
		t.Errorf("the stdlib is not on the modelled sys.path: %v", g.Roots())
	}
	// "sys" and "time" are compiled into the interpreter. Reporting them as
	// missing modules would be a taint fired by correct code.
	if ts := g.Taints(); len(ts) != 0 {
		t.Errorf("taints = %+v, want none", ts)
	}
}

func TestResolverHandlesExtensionModulesAndNamespacePackages(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py": "",
		"/app/main.py":              "import _yaml\nimport ns.one\nimport ns.two\n",
		// An extension module carries an ABI tag that varies per build, so it
		// has to be found by listing rather than by guessing a name.
		sp + "/_yaml.cpython-312-x86_64-linux-gnu.so": "\x7fELF",
		// A PEP 420 namespace package: two halves in two sys.path entries,
		// neither with an __init__.py.
		sp + "/ns/one.py":                                 "",
		"/usr/lib/python3/dist-packages/ns/two.py":        "",
		"/usr/lib/python3/dist-packages/z-1.dist-info/M":  "",
		sp + "/PyYAML-6.0.1.dist-info/METADATA":           "Name: PyYAML\nVersion: 6.0.1\n",
		"/usr/lib/python3/dist-packages/ns-1.dist-info/M": "",
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable(sp + "/_yaml.cpython-312-x86_64-linux-gnu.so") {
		t.Error("the ABI-tagged extension module did not resolve")
	}
	if !g.Reachable(sp+"/ns/one.py") || !g.Reachable("/usr/lib/python3/dist-packages/ns/two.py") {
		t.Errorf("the namespace package did not merge across sys.path: %v", g.Nodes())
	}
	for _, ta := range g.Taints() {
		if ta.Spec == "ns" {
			t.Errorf("a namespace package resolves to no file legitimately: %+v", ta)
		}
	}
}

func TestConsoleScriptEntrypointIsRooted(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":                 "",
		"/usr/local/bin/gunicorn":                   "#!/usr/local/bin/python3.12\nfrom gunicorn.app import run\n",
		sp + "/gunicorn/__init__.py":                "",
		sp + "/gunicorn/app.py":                     "import yaml\n",
		sp + "/yaml/__init__.py":                    "",
		sp + "/gunicorn-21.dist-info/METADATA":      "Name: gunicorn\nVersion: 21.2.0\n",
		sp + "/PyYAML-6.0.1.dist-info/METADATA":     "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.0.1.dist-info/RECORD":       record("yaml/__init__.py"),
		sp + "/gunicorn-21.dist-info/RECORD":        record("gunicorn/__init__.py", "gunicorn/app.py"),
		sp + "/gunicorn-21.dist-info/top_level.txt": "gunicorn\n",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"gunicorn"}, Env: []string{"PATH=/usr/local/bin:/usr/bin"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable("/usr/local/bin/gunicorn") {
		t.Fatalf("the console script was not rooted: %v", g.Roots())
	}
	if !g.Reachable(sp + "/yaml/__init__.py") {
		t.Errorf("the closure did not run through the shim: %v", g.Roots())
	}
	if bt := g.BlockingTaints(); len(bt) != 0 {
		t.Errorf("a console script is a resolvable entrypoint: %+v", bt)
	}
}

func TestModuleEntrypoint(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":       "",
		sp + "/http/server.py":            "import os\n",
		sp + "/pip/__init__.py":           "",
		sp + "/pip/__main__.py":           "import os\n",
		sp + "/pip-24.dist-info/METADATA": "Name: pip\nVersion: 24.0\n",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "-W", "ignore", "-m", "pip"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable(sp+"/pip/__init__.py") || !g.Reachable(sp+"/pip/__main__.py") {
		t.Errorf("-m should root the package and its __main__: %v", g.Roots())
	}
	if g.Reachable(sp + "/http/server.py") {
		t.Error("an unrelated module is in the closure")
	}
}

// The honest worst case: nothing in the config says what Python code runs, so
// everything installed is treated as reachable and the reason is recorded.
func TestForeignEntrypointEscalatesAndSaysSo(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":         "",
		"/bin/sh":                           "\x7fELF",
		sp + "/yaml/__init__.py":            "",
		sp + "/PyYAML-6.dist-info/METADATA": "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.dist-info/RECORD":   record("yaml/__init__.py"),
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"/bin/sh", "-c", "something"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable(sp + "/yaml/__init__.py") {
		t.Error("escalation must make every installed module reachable")
	}
	bt := g.BlockingTaints()
	if len(bt) != 1 || bt[0].Kind != modgraph.TaintForeignEntrypoint {
		t.Fatalf("blocking taints = %+v, want foreign-entrypoint", bt)
	}
	for _, n := range g.Nodes() {
		if n.Root && n.Kind != modgraph.RootEscalated {
			t.Errorf("root %s kind = %q, want escalated", n.Path, n.Kind)
		}
	}
}

func TestNoEntrypointEscalates(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":         "",
		sp + "/yaml/__init__.py":            "",
		sp + "/PyYAML-6.dist-info/METADATA": "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.dist-info/RECORD":   record("yaml/__init__.py"),
	})

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable(sp + "/yaml/__init__.py") {
		t.Error("with no entrypoint everything installed is reachable")
	}
	if bt := g.BlockingTaints(); len(bt) != 1 || bt[0].Kind != modgraph.TaintNoEntrypoint {
		t.Errorf("blocking taints = %+v, want no-entrypoint", bt)
	}
}

// A computed import inside one distribution taints that distribution, not the
// image. Getting this wrong makes every scan of a real application useless.
func TestComputedImportIsScopedToItsDistribution(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":                 "",
		"/app/main.py":                              "import loader\n",
		"/usr/lib/python3.12/importlib/__init__.py": "",
		sp + "/loader/__init__.py":                  "import importlib\nx = importlib.import_module(chosen)\n",
		sp + "/loader-1.dist-info/METADATA":         "Name: loader\nVersion: 1.0\n",
		sp + "/loader-1.dist-info/RECORD":           record("loader/__init__.py"),
		sp + "/yaml/__init__.py":                    "",
		sp + "/PyYAML-6.dist-info/METADATA":         "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.dist-info/RECORD":           record("yaml/__init__.py"),
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("one distribution's plugin loader must not taint the image: %+v", g.BlockingTaints())
	}
	if got := g.TaintsFor([]string{"loader"}); len(got) != 1 || got[0].Kind != modgraph.TaintDynamicImport {
		t.Errorf("the distribution that computes an import must see the taint: %+v", got)
	}
	if got := g.TaintsFor([]string{"yaml"}); len(got) != 0 {
		t.Errorf("an unrelated distribution must not: %+v", got)
	}
}

// A computed import in application code, which no distribution owns, could
// load anything installed -- so it blocks globally.
func TestComputedImportInApplicationCodeBlocksGlobally(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":                 "",
		"/usr/lib/python3.12/importlib/__init__.py": "",
		"/app/main.py":                              "import importlib\nimportlib.import_module(name)\n",
		sp + "/PyYAML-6.dist-info/METADATA":         "Name: PyYAML\nVersion: 6.0.1\n",
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if bt := g.BlockingTaints(); len(bt) != 1 || bt[0].Kind != modgraph.TaintDynamicImport {
		t.Fatalf("blocking taints = %+v, want a global dynamic-import", bt)
	}
	// And the flag that lets a user assert it away still records it.
	_, g2 := pyGraph(t, img, modgraph.Options{Dynamic: modgraph.DynamicAssumeNone})
	if len(g2.BlockingTaints()) != 0 || len(g2.Taints()) != 1 {
		t.Errorf("assume-none should demote, not drop: %+v", g2.Taints())
	}
}

// Plugin discovery resolves rather than surrenders: entry_points.txt is on
// disk, so the plugins it could load are rooted instead of the whole image
// being written off.
func TestEntryPointDiscoveryFollowsDeclaredPlugins(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":               "",
		"/app/main.py":                            "from importlib.metadata import entry_points\nfor ep in entry_points(group='myapp.plugins'):\n    ep.load()\n",
		sp + "/plug/__init__.py":                  "import yaml\n",
		sp + "/plug-1.dist-info/METADATA":         "Name: plug\nVersion: 1.0\n",
		sp + "/plug-1.dist-info/RECORD":           record("plug/__init__.py"),
		sp + "/plug-1.dist-info/entry_points.txt": "[myapp.plugins]\nthing = plug:Thing\n",
		sp + "/yaml/__init__.py":                  "",
		sp + "/PyYAML-6.dist-info/METADATA":       "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.dist-info/RECORD":         record("yaml/__init__.py"),
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	if !g.Reachable(sp + "/plug/__init__.py") {
		t.Fatalf("the declared plugin was not rooted: %v", g.Nodes())
	}
	if !g.Reachable(sp + "/yaml/__init__.py") {
		t.Error("the closure did not continue through the plugin")
	}
	// Recorded, but not blocking: the plugins were enumerable.
	var found bool
	for _, ta := range g.Taints() {
		if ta.Kind == modgraph.TaintPluginDiscovery {
			found = true
			if ta.Blocking {
				t.Errorf("discovery that resolved should not block: %+v", ta)
			}
		}
	}
	if !found {
		t.Error("discovery must still be recorded, since plugins can register other ways")
	}
}

func TestPthFileExtendsSysPathAndRootsStartupImports(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":             "",
		"/app/main.py":                          "import extra\n",
		sp + "/vendor.pth":                      "../vendored\n",
		sp + "/startup.pth":                     "import hookmod\n",
		"/usr/lib/python3.12/vendored/extra.py": "",
		sp + "/hookmod.py":                      "import yaml\n",
		sp + "/yaml/__init__.py":                "",
		sp + "/PyYAML-6.dist-info/METADATA":     "Name: PyYAML\nVersion: 6.0.1\n",
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	lang, g := pyGraph(t, img, modgraph.Options{})
	if !contains(lang.SearchPath(), "/usr/lib/python3.12/vendored") {
		t.Errorf("the .pth path was not added to sys.path: %v", lang.SearchPath())
	}
	if !g.Reachable("/usr/lib/python3.12/vendored/extra.py") {
		t.Error("an import resolving through a .pth path did not resolve")
	}
	if !g.Reachable(sp+"/hookmod.py") || !g.Reachable(sp+"/yaml/__init__.py") {
		t.Errorf("a .pth startup import must be rooted: %v", g.Roots())
	}
}

func TestPthCodeThatIsNotAPlainImportTaints(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":         "",
		"/app/main.py":                      "",
		sp + "/evil.pth":                    "import os; os.system('curl x')\n",
		sp + "/PyYAML-6.dist-info/METADATA": "Name: PyYAML\nVersion: 6.0.1\n",
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{})
	bt := g.BlockingTaints()
	if len(bt) != 1 || bt[0].Kind != modgraph.TaintDynamicImport {
		t.Fatalf("blocking taints = %+v, want the .pth startup code", bt)
	}
}

func TestExplicitRootAcceptsAModuleName(t *testing.T) {
	img := pyImage(t, map[string]string{
		"/usr/lib/python3.12/os.py":         "",
		"/app/main.py":                      "",
		sp + "/yaml/__init__.py":            "import os\n",
		sp + "/PyYAML-6.dist-info/METADATA": "Name: PyYAML\nVersion: 6.0.1\n",
	})
	img.Config = target.ImageConfig{Cmd: []string{"python3", "/app/main.py"}}

	_, g := pyGraph(t, img, modgraph.Options{Roots: []string{"yaml"}})
	if !g.Reachable(sp + "/yaml/__init__.py") {
		t.Errorf("--roots yaml did not resolve: %v", g.Roots())
	}
}

func TestIsInterpreter(t *testing.T) {
	for _, s := range []string{"python", "python3", "python3.12", "pypy3", "pypy"} {
		if !isInterpreter(s) {
			t.Errorf("%q should be an interpreter", s)
		}
	}
	for _, s := range []string{"pythonic-tool", "sh", "node", "python-config"} {
		if isInterpreter(s) {
			t.Errorf("%q should not be an interpreter", s)
		}
	}
}

func TestIsModuleExcludesPycacheTwins(t *testing.T) {
	p := &python{}
	for _, f := range []string{"/a/b.py", "/a/_x.cpython-312.so", "/a/legacy.pyc"} {
		if !p.IsModule(f) {
			t.Errorf("%q should be a module", f)
		}
	}
	for _, f := range []string{"/a/__pycache__/b.cpython-312.pyc", "/a/README.md", "/a/x.pyi"} {
		if p.IsModule(f) {
			t.Errorf("%q should not be a module", f)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
