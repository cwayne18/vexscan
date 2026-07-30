package npm

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
// been asked about, and returns the finding for one package.
func mined(t *testing.T, img *target.Image, opts Options, details string, hints *llm.Hints, name string) ecosystem.Finding {
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
		if f.Module == name {
			return f
		}
	}
	t.Fatalf("no finding for %s: %+v", name, findings)
	return ecosystem.Finding{}
}

// lodashTree is lodash installed with the vulnerable subpath either shipped or
// not -- the case the mined-subpath layer exists for. The application requires
// the package, so the ordinary closure has nothing to say and only the subpath
// question is left.
func lodashTree(withTemplate bool) map[string]string {
	files := map[string]string{
		"/app/index.js":             "require('lodash')\n",
		nm + "/lodash/package.json": pkgJSON("lodash", "4.17.20", "index.js"),
		nm + "/lodash/index.js":     "require('./isEqual.js')\n",
		nm + "/lodash/isEqual.js":   "module.exports = 1\n",
		nm + "/idle/package.json":   pkgJSON("idle", "1.0.0", "index.js"),
		nm + "/idle/index.js":       "",
	}
	if withTemplate {
		files[nm+"/lodash/template.js"] = "module.exports = 2\n"
	}
	return files
}

const templateAdvisory = "A prototype pollution issue in lodash/template allows an attacker to inject properties."

// The row the whole layer is for: the advisory's subpath is not among the files
// this build installed.
func TestMinedSubpathAbsentFromThePackage(t *testing.T) {
	img := nodeImage(t, lodashTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := mined(t, img, Options{}, templateAdvisory, &llm.Hints{Modules: []string{"lodash/template"}}, "lodash")
	if f.Status != ecosystem.StatusNotPresent || f.Method != MethodModuleAbsent {
		det, _ := evidence(f)
		t.Fatalf("lodash = %s/%s, want not_present/%s:%s", f.Status, f.Method, MethodModuleAbsent, det)
	}
	if f.Justification != "vulnerable_code_not_present" {
		t.Errorf("justification = %q", f.Justification)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, "lodash/template") {
		t.Errorf("the evidence does not name the subpath it looked for:%s", det)
	}
}

// The subpath is installed, the package is required, and nothing requires the
// subpath. That is a real observation and a weak one, so it decides nothing
// without --trust-import-absence.
func TestMinedSubpathInstalledButNeverRequired(t *testing.T) {
	img := nodeImage(t, lodashTree(true))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := mined(t, img, Options{}, templateAdvisory, &llm.Hints{Modules: []string{"lodash/template"}}, "lodash")
	if f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Fatalf("lodash = %s/%s, want linked without --trust-import-absence:%s", f.Status, f.Method, det)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, MethodImportAbsent) {
		t.Errorf("the unrequired subpath was not recorded:%s", det)
	}

	f = mined(t, img, Options{TrustImportAbsence: true}, templateAdvisory,
		&llm.Hints{Modules: []string{"lodash/template"}}, "lodash")
	if f.Status != ecosystem.StatusNotInPath || f.Method != MethodImportAbsent {
		det, _ := evidence(f)
		t.Errorf("with --trust-import-absence lodash = %s/%s, want not_in_execute_path/%s:%s",
			f.Status, f.Method, MethodImportAbsent, det)
	}
}

// A blocking taint stops the absence conclusion the same way it stops the
// closure's: whatever the scan could not follow may be loading the very file
// the advisory names.
func TestMinedSubpathAbsenceDefersToATaint(t *testing.T) {
	files := lodashTree(false)
	files["/app/index.js"] = "require('lodash')\nconst m = require(chosen)\n"
	img := nodeImage(t, files)
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := mined(t, img, Options{}, templateAdvisory, &llm.Hints{Modules: []string{"lodash/template"}}, "lodash")
	if f.Status == ecosystem.StatusNotPresent {
		det, _ := evidence(f)
		t.Errorf("lodash = %s/%s, want no conclusion while a computed require is live:%s", f.Status, f.Method, det)
	}
	if _, blocking := evidence(f); !blocking {
		det, _ := evidence(f)
		t.Errorf("the taint that withheld the conclusion is not in the evidence:%s", det)
	}
}

// The three gates, each on its own. None of them may change a status, and each
// has to say why it refused.
func TestMinedSubpathValidationGates(t *testing.T) {
	img := nodeImage(t, lodashTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	cases := []struct {
		name    string
		details string
		hints   *llm.Hints
		want    string
	}{{
		name:    "not in the advisory text",
		details: "Something is wrong with the template renderer.",
		hints:   &llm.Hints{Modules: []string{"lodash/template"}},
		want:    "invented rather than extracted",
	}, {
		name:    "belongs to another package",
		details: "Both @babel/traverse/lib/path and lodash are mentioned here.",
		hints:   &llm.Hints{Modules: []string{"@babel/traverse/lib/path"}},
		want:    "rather than lodash",
	}, {
		// A bare package name is installed by definition, so there is no
		// absence for it to report.
		name:    "the package name itself",
		details: "The lodash package is affected.",
		hints:   &llm.Hints{Modules: []string{"lodash"}},
		want:    "installed by definition",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mined(t, img, Options{}, tc.details, tc.hints, "lodash")
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

// A dotted name is a property access, not a module. It cannot resolve to a
// file, so the gate that would otherwise report its absence must not fire.
func TestADottedNameIsNotASubpath(t *testing.T) {
	img := nodeImage(t, lodashTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := mined(t, img, Options{},
		"Calling lodash.template with untrusted input is unsafe.",
		&llm.Hints{Modules: []string{"lodash.template"}}, "lodash")
	if f.Status == ecosystem.StatusNotPresent {
		det, _ := evidence(f)
		t.Errorf("lodash = %s/%s: a property access is not a missing file:%s", f.Status, f.Method, det)
	}
}

// The resolver, not string matching, is what turns a subpath into files -- so
// an "exports" map that redirects the advisory's subpath elsewhere still finds
// the code.
func TestMinedSubpathFollowsTheExportsMap(t *testing.T) {
	img := nodeImage(t, map[string]string{
		"/app/index.js": "require('modern')\n",
		nm + "/modern/package.json": `{"name":"modern","version":"2.0.0",` +
			`"exports":{".":"./dist/main.js","./feature":"./dist/feature.js"}}`,
		nm + "/modern/dist/main.js":    "",
		nm + "/modern/dist/feature.js": "module.exports = 1\n",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := mined(t, img, Options{},
		"The flaw is in modern/feature.",
		&llm.Hints{Modules: []string{"modern/feature"}}, "modern")
	if f.Status == ecosystem.StatusNotPresent {
		det, _ := evidence(f)
		t.Fatalf("modern = %s/%s: exports redirects that subpath to a file that exists:%s", f.Status, f.Method, det)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, "shipped by modern") {
		t.Errorf("the evidence does not record that the subpath was found:%s", det)
	}
}

// Without --mine-advisories there are no hints, and the finding must read
// exactly as it did before this layer existed.
func TestNoHintsChangesNothing(t *testing.T) {
	img := nodeImage(t, lodashTree(false))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := mined(t, img, Options{}, templateAdvisory, nil, "lodash")
	if f.Status != ecosystem.StatusLinked {
		t.Errorf("lodash = %s/%s, want linked", f.Status, f.Method)
	}
	for _, e := range f.Evidence {
		if e.Origin == MethodMined {
			t.Errorf("a run with no hints recorded a mining observation: %+v", e)
		}
	}
}
