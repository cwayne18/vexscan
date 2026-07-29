package pypi

import (
	"context"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/target"
)

// mined runs the plugin over one advisory whose prose the model has already
// been asked about, and returns the finding for one distribution.
func mined(t *testing.T, img *target.Image, opts Options, details string, hints *llm.Hints, dist string) ecosystem.Finding {
	t.Helper()
	ctx := context.Background()
	opts.Mine = true
	p := New(opts)

	components, err := p.InventoryImage(ctx, img, []ecosystem.Subject{{Raw: "all"}})
	if err != nil {
		t.Fatalf("InventoryImage: %v", err)
	}
	adv := &osv.Advisory{ID: "CVE-2024-0001", Summary: "a hole", Details: details}

	items := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		items = append(items, ecosystem.WorkItem{
			Component:  c,
			Advisories: map[string]*osv.Advisory{adv.ID: adv},
			Hints:      map[string]*llm.Hints{adv.ID: hints},
		})
	}
	findings, err := p.AnalyzeImage(ctx, img, items)
	if err != nil {
		t.Fatalf("AnalyzeImage: %v", err)
	}
	for _, f := range findings {
		if f.Module == dist {
			return f
		}
	}
	t.Fatalf("no finding for %s: %+v", dist, findings)
	return ecosystem.Finding{}
}

// pyyamlTree is PyYAML installed with its optional C accelerator either
// present or absent -- the case the mined-module layer exists for.
func pyyamlTree(withCyaml bool) map[string]string {
	files := map[string]string{
		"/usr/lib/python3.12/os.py":                  "",
		"/app/main.py":                               "import yaml\n",
		sp + "/PyYAML-6.0.1.dist-info/METADATA":      "Name: PyYAML\nVersion: 6.0.1\n",
		sp + "/PyYAML-6.0.1.dist-info/top_level.txt": "yaml\n",
		sp + "/PyYAML-6.0.1.dist-info/RECORD":        record("yaml/__init__.py", "yaml/loader.py"),
		sp + "/yaml/__init__.py":                     "from .loader import Loader\n",
		sp + "/yaml/loader.py":                       "",
	}
	if withCyaml {
		files[sp+"/PyYAML-6.0.1.dist-info/RECORD"] = record("yaml/__init__.py", "yaml/loader.py", "yaml/cyaml.py")
		files[sp+"/yaml/cyaml.py"] = ""
	}
	return files
}

const cyamlAdvisory = "The vulnerability is in the yaml.cyaml loader, which wraps libyaml."

// The row the whole layer is for: the advisory's module is not among the files
// this build installed.
func TestMinedModuleAbsentFromTheDistribution(t *testing.T) {
	img := pyImage(t, pyyamlTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	f := mined(t, img, Options{}, cyamlAdvisory, &llm.Hints{Modules: []string{"yaml.cyaml"}}, "pyyaml")
	if f.Status != ecosystem.StatusNotPresent || f.Method != MethodModuleAbsent {
		det, _ := evidence(f)
		t.Fatalf("pyyaml = %s/%s, want not_present/%s:%s", f.Status, f.Method, MethodModuleAbsent, det)
	}
	if f.Justification != "vulnerable_code_not_present" {
		t.Errorf("justification = %q", f.Justification)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, "yaml.cyaml") {
		t.Errorf("the evidence does not name the module it looked for:%s", det)
	}
}

// A file list that was reconstructed rather than read cannot support the same
// conclusion: the module may be somewhere the walk did not look.
func TestMinedModuleAbsenceNeedsAManifest(t *testing.T) {
	files := pyyamlTree(false)
	delete(files, sp+"/PyYAML-6.0.1.dist-info/RECORD")
	img := pyImage(t, files)
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	f := mined(t, img, Options{}, cyamlAdvisory, &llm.Hints{Modules: []string{"yaml.cyaml"}}, "pyyaml")
	if f.Status == ecosystem.StatusNotPresent {
		det, _ := evidence(f)
		t.Errorf("pyyaml = %s/%s, want no conclusion from an inferred file list:%s", f.Status, f.Method, det)
	}
}

// The module is installed, the distribution is imported, and nothing imports
// the module. That is a real observation and a weak one, so it decides nothing
// without --trust-import-absence.
func TestMinedModuleInstalledButNeverImported(t *testing.T) {
	img := pyImage(t, pyyamlTree(true))
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	f := mined(t, img, Options{}, cyamlAdvisory, &llm.Hints{Modules: []string{"yaml.cyaml"}}, "pyyaml")
	if f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Fatalf("pyyaml = %s/%s, want linked without --trust-import-absence:%s", f.Status, f.Method, det)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, MethodImportAbsent) {
		t.Errorf("the unimported module was not recorded:%s", det)
	}

	f = mined(t, img, Options{TrustImportAbsence: true}, cyamlAdvisory, &llm.Hints{Modules: []string{"yaml.cyaml"}}, "pyyaml")
	if f.Status != ecosystem.StatusNotInPath || f.Method != MethodImportAbsent {
		det, _ := evidence(f)
		t.Errorf("with --trust-import-absence pyyaml = %s/%s, want not_in_execute_path/%s:%s",
			f.Status, f.Method, MethodImportAbsent, det)
	}
}

// The three gates, each on its own. None of them may change a status, and each
// has to say why it refused.
func TestMinedModuleValidationGates(t *testing.T) {
	img := pyImage(t, pyyamlTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	cases := []struct {
		name    string
		details string
		hints   *llm.Hints
		want    string
	}{{
		name:    "not in the advisory text",
		details: "Something is wrong with the loader.",
		hints:   &llm.Hints{Modules: []string{"yaml.cyaml"}},
		want:    "invented rather than extracted",
	}, {
		name:    "belongs to another project",
		details: "Both django.http and yaml are mentioned here.",
		hints:   &llm.Hints{Modules: []string{"django.http"}},
		want:    "top-level name this distribution installs",
	}, {
		// yaml.load is a function, and a model that lists the leaf as a symbol
		// too has told us so.
		name:    "an attribute wearing a module's clothes",
		details: "Calling yaml.load with untrusted input is unsafe; use safe_load.",
		hints:   &llm.Hints{Modules: []string{"yaml.load"}, Symbols: []string{"load"}},
		want:    "attribute rather than a module",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mined(t, img, Options{}, tc.details, tc.hints, "pyyaml")
			if f.Status == ecosystem.StatusNotPresent {
				det, _ := evidence(f)
				t.Fatalf("a rejected hint decided the finding: %s/%s:%s", f.Status, f.Method, det)
			}
			det, _ := evidence(f)
			if !strings.Contains(det, tc.want) {
				t.Errorf("the evidence does not say why the hint was rejected (want %q):%s", tc.want, det)
			}
		})
	}
}

// Without --mine-advisories there are no hints, and the finding must read
// exactly as it did before this layer existed.
func TestNoHintsChangesNothing(t *testing.T) {
	img := pyImage(t, pyyamlTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"python3", "/app/main.py"}}

	f := mined(t, img, Options{}, cyamlAdvisory, nil, "pyyaml")
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("pyyaml = %s/%s, want linked", f.Status, f.Method)
	}
	for _, e := range f.Evidence {
		if e.Origin == MethodMined {
			t.Errorf("a run with no hints recorded a mining observation: %+v", e)
		}
	}
}

func TestModuleFilesMatchesEveryShapeOfModule(t *testing.T) {
	files := []string{
		sp + "/yaml/__init__.py",
		sp + "/yaml/loader.py",
		sp + "/_yaml.cpython-312-x86_64-linux-gnu.so",
		sp + "/yamlx/loader.py",
	}
	for _, tc := range []struct {
		dotted string
		want   string
	}{
		{"yaml", sp + "/yaml/__init__.py"},
		{"yaml.loader", sp + "/yaml/loader.py"},
		{"_yaml", sp + "/_yaml.cpython-312-x86_64-linux-gnu.so"},
	} {
		got := moduleFiles(tc.dotted, files)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("moduleFiles(%q) = %v, want [%s]", tc.dotted, got, tc.want)
		}
	}
	// A prefix of a directory name is not a package boundary.
	if got := moduleFiles("yam", files); len(got) != 0 {
		t.Errorf("moduleFiles(\"yam\") = %v, want nothing", got)
	}
}
