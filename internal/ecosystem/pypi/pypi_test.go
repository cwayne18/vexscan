package pypi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// pyImage writes a tree of files and wraps it as an image.
func pyImage(t *testing.T, files map[string]string) *target.Image {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &target.Image{Ref: "test", FS: target.NewDirFS(root)}
}

// record renders a RECORD body from site-packages-relative paths.
func record(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		b.WriteString(p + ",sha256=x,1\n")
	}
	return b.String()
}

// statuses runs the whole plugin over one advisory and reports the finding per
// distribution.
func statuses(t *testing.T, img *target.Image, subjects []ecosystem.Subject) map[string]ecosystem.Finding {
	t.Helper()
	return statusesWith(t, img, subjects, Options{})
}

func statusesWith(t *testing.T, img *target.Image, subjects []ecosystem.Subject, opts Options) map[string]ecosystem.Finding {
	t.Helper()
	ctx := context.Background()
	p := New(opts)

	ok, err := p.DetectImage(ctx, img)
	if err != nil {
		t.Fatalf("DetectImage: %v", err)
	}
	if !ok {
		t.Fatal("DetectImage said the plugin does not apply")
	}
	components, err := p.InventoryImage(ctx, img, subjects)
	if err != nil {
		t.Fatalf("InventoryImage: %v", err)
	}

	adv := &osv.Advisory{ID: "CVE-2024-0001", Summary: "a hole"}
	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		items = append(items, ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{"CVE-2024-0001": adv},
			Requested:  []string{"CVE-2024-0001"},
			Targeted:   len(subjects) > 0 && !subjects[0].MatchesAll(),
		})
	}

	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatalf("AnalyzeImage: %v", err)
	}
	out := map[string]ecosystem.Finding{}
	for _, f := range findings {
		out[f.Module] = f
	}
	return out
}

const sp = "/usr/lib/python3.12/site-packages"

// The rows of the status table this plugin implements today, in one image.
func TestStatusTable(t *testing.T) {
	img := pyImage(t, map[string]string{
		// Installed with code: linked, and the name it is imported by differs
		// from the name OSV keys it on.
		sp + "/PyYAML-6.0.1.dist-info/METADATA":      "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.0.1.dist-info/top_level.txt": "yaml\n",
		sp + "/PyYAML-6.0.1.dist-info/RECORD":        record("yaml/__init__.py", "yaml/loader.py"),
		sp + "/yaml/__init__.py":                     "",
		sp + "/yaml/loader.py":                       "",

		// A stubs-only distribution: the manifest lists .pyi and nothing else,
		// so there is no code to be vulnerable.
		sp + "/types_requests-2.31.0.dist-info/METADATA": "Name: types-requests\nVersion: 2.31.0\n",
		sp + "/types_requests-2.31.0.dist-info/RECORD":   record("requests-stubs/__init__.pyi"),
		sp + "/requests-stubs/__init__.pyi":              "",
	})

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if len(got) != 2 {
		t.Fatalf("inventoried %d distributions, want 2: %v", len(got), got)
	}

	if f := got["pyyaml"]; f.Status != ecosystem.StatusLinked {
		t.Errorf("pyyaml = %s/%s, want linked", f.Status, f.Method)
	} else if f.PURL != "pkg:pypi/pyyaml@6.0.1" {
		t.Errorf("pyyaml purl = %q", f.PURL)
	}

	f := got["types-requests"]
	if f.Status != ecosystem.StatusNotPresent || f.Method != MethodNoCode {
		t.Errorf("types-requests = %s/%s, want not_present/%s", f.Status, f.Method, MethodNoCode)
	}
	if f.Justification != "vulnerable_code_not_present" {
		t.Errorf("types-requests justification = %q", f.Justification)
	}
}

func TestNamedDistributionThatIsNotInstalled(t *testing.T) {
	img := pyImage(t, map[string]string{
		sp + "/pip-24.0.dist-info/METADATA": "Name: pip\nVersion: 24.0\n",
		sp + "/pip-24.0.dist-info/RECORD":   record("pip/__init__.py"),
		sp + "/pip/__init__.py":             "",
	})

	got := statuses(t, img, []ecosystem.Subject{{Ecosystem: "pypi", Name: "Django", Raw: "pypi:Django"}})
	f, ok := got["django"]
	if !ok {
		t.Fatalf("no finding for the named distribution: %v", got)
	}
	if f.Status != ecosystem.StatusNotPresent || f.Justification != "component_not_present" {
		t.Errorf("django = %s/%s, want not_present/component_not_present", f.Status, f.Justification)
	}
	if f.Method != MethodInventory {
		t.Errorf("django method = %q", f.Method)
	}
}

// An unidentifiable dist-info means the inventory is incomplete, and an
// incomplete inventory cannot support "this distribution is not installed".
func TestUnreadableMetadataBlocksAnAbsenceClaim(t *testing.T) {
	img := pyImage(t, map[string]string{
		sp + "/pip-24.0.dist-info/METADATA": "Name: pip\nVersion: 24.0\n",
		sp + "/pip-24.0.dist-info/RECORD":   record("pip/__init__.py"),
		sp + "/pip/__init__.py":             "",
		// No name to be had: no METADATA, and the directory name carries none.
		sp + "/.dist-info/WHEEL": "Wheel-Version: 1.0\n",
	})

	got := statuses(t, img, []ecosystem.Subject{{Ecosystem: "pypi", Name: "Django", Raw: "pypi:Django"}})
	f := got["django"]
	if f.Status != ecosystem.StatusUndetermined {
		t.Fatalf("django = %s, want undetermined (the unnamed dist could be it)", f.Status)
	}
	if f.Reason != "unreadable_dist_metadata" {
		t.Errorf("reason = %q", f.Reason)
	}
	if len(f.Evidence) == 0 || !f.Evidence[0].Blocking {
		t.Errorf("the blocking evidence is missing: %+v", f.Evidence)
	}
}

// A distribution with no RECORD has no manifest to prove a negative with, so
// finding no code must not be reported as "ships no code".
func TestReconstructedFileListCannotSayNoCode(t *testing.T) {
	img := pyImage(t, map[string]string{
		// METADATA but no RECORD and no top_level.txt: the import name is
		// guessed, and nothing on disk matches the guess.
		sp + "/mystery-1.0.dist-info/METADATA": "Name: mystery\nVersion: 1.0\n",
	})

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	f := got["mystery"]
	if f.Status != ecosystem.StatusLinked {
		t.Fatalf("mystery = %s/%s, want linked: an unreadable manifest is not evidence of absence", f.Status, f.Method)
	}
	if len(f.Evidence) == 0 || !f.Evidence[0].Blocking {
		t.Errorf("the blocking evidence is missing: %+v", f.Evidence)
	}
}

// The same distribution installed twice is one component with two locations,
// not two identical findings.
func TestOneDistributionInstalledTwice(t *testing.T) {
	const dp = "/usr/lib/python3/dist-packages"
	img := pyImage(t, map[string]string{
		sp + "/six-1.16.0.dist-info/METADATA": "Name: six\nVersion: 1.16.0\n",
		sp + "/six-1.16.0.dist-info/RECORD":   record("six.py"),
		sp + "/six.py":                        "",
		dp + "/six-1.16.0.dist-info/METADATA": "Name: six\nVersion: 1.16.0\n",
		dp + "/six-1.16.0.dist-info/RECORD":   record("six.py"),
		dp + "/six.py":                        "",
	})

	p := New(Options{})
	components, err := p.InventoryImage(context.Background(), img, []ecosystem.Subject{{Raw: "all"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1: %+v", len(components), components)
	}
	if got := len(components[0].Locations); got != 2 {
		t.Errorf("locations = %v, want both site-packages directories", components[0].Locations)
	}
}

func TestMatchesNameAcceptsEverySpellingOfOneName(t *testing.T) {
	img := pyImage(t, map[string]string{
		sp + "/ruamel.yaml-0.18.5.dist-info/METADATA":      "Name: ruamel.yaml\nVersion: 0.18.5\n",
		sp + "/ruamel.yaml-0.18.5.dist-info/top_level.txt": "ruamel\n",
		sp + "/ruamel.yaml-0.18.5.dist-info/RECORD":        record("ruamel/yaml/__init__.py"),
		sp + "/ruamel/yaml/__init__.py":                    "",
	})

	// The normalized name, the name as METADATA spells it, a purl, and the
	// name the code is imported by all reach the same distribution.
	for _, s := range []ecosystem.Subject{
		{Ecosystem: "pypi", Name: "ruamel-yaml", Raw: "a"},
		{Ecosystem: "pypi", Name: "ruamel.yaml", Raw: "b"},
		{PURL: "pkg:pypi/ruamel-yaml@0.18.5", Raw: "c"},
		{Ecosystem: "pypi", Name: "ruamel", Raw: "d"},
	} {
		got := statuses(t, img, []ecosystem.Subject{s})
		if f, ok := got["ruamel-yaml"]; !ok || f.Status != ecosystem.StatusLinked {
			t.Errorf("subject %+v found %v", s, got)
		}
	}
}

func TestDetectSkipsAnImageWithNoPython(t *testing.T) {
	img := pyImage(t, map[string]string{"/etc/os-release": "ID=debian\n"})
	ok, err := New(Options{}).DetectImage(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("the plugin claimed to apply to an image with no site-packages")
	}
}

// appTree is an image whose entrypoint imports one installed distribution and
// not the other. It is the shape every reachability row of the status table is
// decided on.
func appTree(main string, extra map[string]string) map[string]string {
	files := map[string]string{
		"/usr/lib/python3.12/os.py":                     "",
		"/app/main.py":                                  main,
		sp + "/PyYAML-6.0.1.dist-info/METADATA":         "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.0.1.dist-info/top_level.txt":    "yaml\n",
		sp + "/PyYAML-6.0.1.dist-info/RECORD":           record("yaml/__init__.py", "yaml/loader.py"),
		sp + "/yaml/__init__.py":                        "from .loader import Loader\n",
		sp + "/yaml/loader.py":                          "",
		sp + "/requests-2.31.0.dist-info/METADATA":      "Name: requests\nVersion: 2.31.0\n",
		sp + "/requests-2.31.0.dist-info/top_level.txt": "requests\n",
		sp + "/requests-2.31.0.dist-info/RECORD":        record("requests/__init__.py"),
		sp + "/requests/__init__.py":                    "",
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

// evidence renders a finding's evidence for an assertion message, and reports
// whether any of it is blocking.
func evidence(f ecosystem.Finding) (string, bool) {
	var b strings.Builder
	blocking := false
	for _, e := range f.Evidence {
		fmt.Fprintf(&b, "\n  [%s blocking=%v] %s", e.Origin, e.Blocking, e.Detail)
		blocking = blocking || e.Blocking
	}
	return b.String(), blocking
}

// The two rows the graph adds: reached is still linked, and unreached with
// nothing blocking is the only not_in_execute_path this ecosystem can reach.
func TestImportGraphDecidesReachability(t *testing.T) {
	img := pyImage(t, appTree("import yaml\n", nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})

	f := got["requests"]
	if f.Status != ecosystem.StatusNotInPath || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("requests = %s/%s, want not_in_execute_path/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("requests justification = %q", f.Justification)
	}
	if _, blocking := evidence(f); blocking {
		det, _ := evidence(f)
		t.Errorf("a concluded finding must carry no blocking evidence:%s", det)
	}

	f = got["pyyaml"]
	if f.Status != ecosystem.StatusLinked || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("pyyaml = %s/%s, want linked/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	// Reaching a distribution is only useful if the finding says what reached
	// it, so the reader can check the claim.
	det, _ := evidence(f)
	if !strings.Contains(det, "/app/main.py") {
		t.Errorf("nothing in the evidence names what imports pyyaml:%s", det)
	}
}

// A computed import in the application's own code is unscoped: it could load
// anything, so nothing installed can be declared unreached.
func TestABlockingTaintStopsTheUnreachedConclusion(t *testing.T) {
	files := appTree("import yaml\nimport importlib\nmod = importlib.import_module(chosen)\n", map[string]string{
		"/usr/lib/python3.12/importlib/__init__.py": "",
	})
	img := pyImage(t, files)
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["requests"]
	if f.Status != ecosystem.StatusLinked || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("requests = %s/%s, want linked/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	det, blocking := evidence(f)
	if !blocking {
		t.Errorf("the taint that withheld the conclusion is not in the evidence:%s", det)
	}
	// Both halves are recorded: nothing reached it, and why that is not the
	// answer.
	if !strings.Contains(det, "nothing reachable from") {
		t.Errorf("the unreached half of the finding is missing:%s", det)
	}

	// --dynamic-import-policy=assume-none is the user taking that risk on.
	f = statusesWith(t, img, []ecosystem.Subject{{Raw: "all"}}, Options{DynamicPolicy: modgraph.DynamicAssumeNone})["requests"]
	if f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("with assume-none requests = %s, want not_in_execute_path:%s", f.Status, det)
	}
}

// lazyTree installs a distribution that imports by computed name, declaring
// requires as its Requires-Dist. The requirement chain fetcher -> deeper is
// what the closure has to walk.
func lazyTree(requires string, extra map[string]string) map[string]string {
	dist := func(name, version, req string) map[string]string {
		meta := fmt.Sprintf("Name: %s\nVersion: %s\n", name, version)
		if req != "" {
			meta += req
		}
		return map[string]string{
			sp + "/" + name + "-" + version + ".dist-info/METADATA":      meta,
			sp + "/" + name + "-" + version + ".dist-info/top_level.txt": name + "\n",
			sp + "/" + name + "-" + version + ".dist-info/RECORD":        record(name + "/__init__.py"),
		}
	}
	files := appTree("import lazyapp\n", map[string]string{
		"/usr/lib/python3.12/importlib/__init__.py": "",
		sp + "/lazyapp/__init__.py":                 "import importlib\nmod = importlib.import_module(chosen)\n",
		sp + "/fetcher/__init__.py":                 "",
		sp + "/deeper/__init__.py":                  "",
	})
	for _, m := range []map[string]string{
		dist("lazyapp", "1.0", requires),
		dist("fetcher", "2.0", "Requires-Dist: deeper\n"),
		dist("deeper", "3.0", ""),
	} {
		for k, v := range m {
			files[k] = v
		}
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

// A computed import inside an installed distribution has to block conclusions
// about that distribution's *requirements*, not merely about itself.
//
// Scoping the taint to the distribution containing the computed import made it
// inert: that distribution is reached by definition, since its file had to be
// read for the taint to be found, so the taint could never withhold a
// conclusion from anything. The npm plugin had the same defect and node:22-slim
// showed what it costs -- tar reported not_in_execute_path behind exactly the
// require that loads it.
func TestADynamicImportBlocksTheDistributionsItCouldReach(t *testing.T) {
	img := pyImage(t, lazyTree("Requires-Dist: fetcher (>=2.0)\n", nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	for _, name := range []string{"fetcher", "deeper"} {
		f := got[name]
		det, blocking := evidence(f)
		if f.Status != ecosystem.StatusLinked {
			t.Errorf("%s = %s, want linked: lazyapp could import it at runtime:%s", name, f.Status, det)
		}
		if !blocking {
			t.Errorf("%s was withheld by no evidence, so nothing recorded why:%s", name, det)
		}
	}
	// Neither is required by lazyapp, so the taint has to leave both of them
	// concludable. A scope that swallowed these would be the global taint this
	// fix exists to avoid.
	for _, name := range []string{"requests", "pyyaml"} {
		if f := got[name]; f.Status != ecosystem.StatusNotInPath {
			det, _ := evidence(f)
			t.Errorf("%s = %s, want not_in_execute_path: lazyapp does not require it:%s", name, f.Status, det)
		}
	}
}

// The two ways a requirement can be missing are not the same fact.
//
// An unconditional Requires-Dist naming something that is not installed means
// the environment is not what the metadata describes, and nothing about it
// bounds anything. A marker-gated one is the marker working: an unselected
// extra is supposed to be absent, and treating that as unknown would push
// almost every Python image into a global taint.
func TestAMissingRequirementIsOnlyUnknownWhenItIsUnconditional(t *testing.T) {
	run := func(t *testing.T, requires string) ecosystem.Finding {
		t.Helper()
		img := pyImage(t, lazyTree(requires, nil))
		img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}
		return statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["requests"]
	}

	f := run(t, "Requires-Dist: absent-from-this-image\n")
	det, blocking := evidence(f)
	if f.Status != ecosystem.StatusLinked || !blocking {
		t.Errorf("requests = %s (blocking=%v), want linked: the closure could not be walked:%s", f.Status, blocking, det)
	}

	f = run(t, "Requires-Dist: pytest; extra == \"test\"\n")
	if f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("requests = %s, want not_in_execute_path: an unselected extra is expected to be absent:%s", f.Status, det)
	}
}

// Silence about a file list that was guessed is not evidence: the modules the
// graph checked may not be the ones the distribution installs.
func TestReconstructedFileListCannotSayUnreached(t *testing.T) {
	files := appTree("import yaml\n", map[string]string{
		// METADATA and top_level.txt but no RECORD: the file list is
		// reconstructed by walking the import name's directory.
		sp + "/mystery-1.0.dist-info/METADATA":      "Name: mystery\nVersion: 1.0\n",
		sp + "/mystery-1.0.dist-info/top_level.txt": "mystery\n",
		sp + "/mystery/__init__.py":                 "",
	})
	img := pyImage(t, files)
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})

	f := got["mystery"]
	if f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Fatalf("mystery = %s/%s, want linked: an inferred file list cannot prove a negative:%s", f.Status, f.Method, det)
	}
	det, blocking := evidence(f)
	if !blocking {
		t.Errorf("the missing manifest is not recorded as blocking:%s", det)
	}
	// The distribution beside it, with a manifest and the same reachability,
	// still concludes: the block is about provenance, not about the image.
	if r := got["requests"]; r.Status != ecosystem.StatusNotInPath {
		t.Errorf("requests = %s, want not_in_execute_path", r.Status)
	}
}

// --roots is how an image whose real command comes from outside its config
// still gets a closure rather than a global escalation.
func TestExtraRootsFeedTheImportGraph(t *testing.T) {
	img := pyImage(t, appTree("import yaml\n", nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"/bin/sh", "-c", "exec python3 /app/main.py"}}

	// Without help, a foreign entrypoint escalates every installed module to a
	// root, so nothing is unreached and nothing concludes.
	if f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["requests"]; f.Status != ecosystem.StatusLinked {
		t.Errorf("requests = %s, want linked behind the foreign-entrypoint taint", f.Status)
	}

	f := statusesWith(t, img, []ecosystem.Subject{{Raw: "all"}}, Options{Roots: []string{"/app/main.py"}})["requests"]
	if f.Status != ecosystem.StatusNotInPath || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("with --roots requests = %s/%s, want not_in_execute_path/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	// The conclusion rests on the user's assertion, so the finding has to name
	// what it was rooted at.
	det, _ := evidence(f)
	if !strings.Contains(det, "/app/main.py") {
		t.Errorf("the evidence does not name the root the conclusion rests on:%s", det)
	}
}

func TestCodeFilesCountsConsoleScripts(t *testing.T) {
	// A console script is generated Python with no extension. A distribution
	// that installs one ships executable code even if nothing else it owns
	// looks like a module.
	got := codeFiles([]string{"/usr/bin/pygmentize", "/usr/share/doc/README"})
	if len(got) != 1 || got[0] != "/usr/bin/pygmentize" {
		t.Errorf("codeFiles = %v", got)
	}
}
