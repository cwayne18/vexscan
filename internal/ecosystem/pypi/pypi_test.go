package pypi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
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
	ctx := context.Background()
	p := New(Options{})

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

func TestCodeFilesCountsConsoleScripts(t *testing.T) {
	// A console script is generated Python with no extension. A distribution
	// that installs one ships executable code even if nothing else it owns
	// looks like a module.
	got := codeFiles([]string{"/usr/bin/pygmentize", "/usr/share/doc/README"})
	if len(got) != 1 || got[0] != "/usr/bin/pygmentize" {
		t.Errorf("codeFiles = %v", got)
	}
}
