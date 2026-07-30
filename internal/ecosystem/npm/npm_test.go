package npm

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

// nodeImage writes a tree of files and wraps it as an image.
func nodeImage(t *testing.T, files map[string]string) *target.Image {
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

// pkgJSON renders a minimal manifest.
func pkgJSON(name, version, main string) string {
	if main == "" {
		return fmt.Sprintf(`{"name":%q,"version":%q}`, name, version)
	}
	return fmt.Sprintf(`{"name":%q,"version":%q,"main":%q}`, name, version, main)
}

// statuses runs the whole plugin over one advisory and reports the finding per
// package.
func statuses(t *testing.T, img *target.Image, subjects []ecosystem.Subject) map[string]ecosystem.Finding {
	t.Helper()
	return statusesWith(t, img, subjects, Options{})
}

func statusesWith(t *testing.T, img *target.Image, subjects []ecosystem.Subject, opts Options) map[string]ecosystem.Finding {
	t.Helper()
	out := map[string]ecosystem.Finding{}
	for _, f := range findingsFor(t, img, subjects, opts) {
		out[f.Module] = f
	}
	return out
}

// findingsFor is statuses without the keying, for the cases where one name
// covers several findings.
func findingsFor(t *testing.T, img *target.Image, subjects []ecosystem.Subject, opts Options) []ecosystem.Finding {
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
	return findings
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

const nm = "/app/node_modules"

// The inventory rows of the status table, in one image.
func TestStatusTable(t *testing.T) {
	img := nodeImage(t, map[string]string{
		// Installed with code: linked.
		nm + "/debug/package.json": pkgJSON("debug", "4.3.4", "./src/index.js"),
		nm + "/debug/src/index.js": "module.exports = 1\n",

		// A types-only package ships .d.ts and nothing Node can load.
		nm + "/@types/node/package.json": pkgJSON("@types/node", "20.11.0", ""),
		nm + "/@types/node/index.d.ts":   "declare module 'fs';\n",
	})

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if len(got) != 2 {
		t.Fatalf("inventoried %d packages, want 2: %v", len(got), got)
	}

	if f := got["debug"]; f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Errorf("debug = %s/%s, want linked:%s", f.Status, f.Method, det)
	} else if f.PURL != "pkg:npm/debug@4.3.4" {
		t.Errorf("debug purl = %q", f.PURL)
	}

	f := got["@types/node"]
	if f.Status != ecosystem.StatusNotPresent || f.Method != MethodNoCode {
		det, _ := evidence(f)
		t.Errorf("@types/node = %s/%s, want not_present/%s:%s", f.Status, f.Method, MethodNoCode, det)
	}
	if f.Justification != "vulnerable_code_not_present" {
		t.Errorf("@types/node justification = %q", f.Justification)
	}
	if f.PURL != "pkg:npm/@types/node@20.11.0" {
		t.Errorf("@types/node purl = %q", f.PURL)
	}
}

func TestNamedPackageThatIsNotInstalled(t *testing.T) {
	img := nodeImage(t, map[string]string{
		nm + "/debug/package.json": pkgJSON("debug", "4.3.4", "index.js"),
		nm + "/debug/index.js":     "",
	})

	got := statuses(t, img, []ecosystem.Subject{{Ecosystem: "npm", Name: "lodash", Raw: "npm:lodash"}})
	f, ok := got["lodash"]
	if !ok {
		t.Fatalf("no finding for the named package: %v", got)
	}
	if f.Status != ecosystem.StatusNotPresent || f.Justification != "component_not_present" {
		t.Errorf("lodash = %s/%s, want not_present/component_not_present", f.Status, f.Justification)
	}
	if f.Method != MethodInventory {
		t.Errorf("lodash method = %q", f.Method)
	}
}

// A package.json that will not parse means the inventory is incomplete, and an
// incomplete inventory cannot support "this package is not installed".
func TestUnreadableManifestBlocksAnAbsenceClaim(t *testing.T) {
	img := nodeImage(t, map[string]string{
		nm + "/debug/package.json":   pkgJSON("debug", "4.3.4", "index.js"),
		nm + "/debug/index.js":       "",
		nm + "/mystery/package.json": "{ this is not json",
	})

	got := statuses(t, img, []ecosystem.Subject{{Ecosystem: "npm", Name: "lodash", Raw: "npm:lodash"}})
	f := got["lodash"]
	if f.Status != ecosystem.StatusUndetermined {
		det, _ := evidence(f)
		t.Fatalf("lodash = %s, want undetermined (the unparsed manifest could be it):%s", f.Status, det)
	}
	if f.Reason != "unreadable_package_manifest" {
		t.Errorf("reason = %q", f.Reason)
	}
	if _, blocking := evidence(f); !blocking {
		t.Errorf("the blocking evidence is missing: %+v", f.Evidence)
	}
}

// npm expresses a version conflict by nesting, so two nesting levels holding
// different versions are two components, and the resolver has to give each
// importer the copy it would actually load.
func TestNestedNodeModulesAreDistinctVersions(t *testing.T) {
	img := nodeImage(t, map[string]string{
		"/app/index.js":                             "require('a')\nrequire('ms')\n",
		nm + "/a/package.json":                      pkgJSON("a", "1.0.0", "index.js"),
		nm + "/a/index.js":                          "require('ms')\n",
		nm + "/a/node_modules/ms/package.json":      pkgJSON("ms", "1.0.0", "index.js"),
		nm + "/a/node_modules/ms/index.js":          "module.exports = 1\n",
		nm + "/ms/package.json":                     pkgJSON("ms", "2.1.3", "index.js"),
		nm + "/ms/index.js":                         "module.exports = 2\n",
		nm + "/unused/package.json":                 pkgJSON("unused", "1.0.0", "index.js"),
		nm + "/unused/index.js":                     "module.exports = 3\n",
		nm + "/unused/node_modules/ms/package.json": pkgJSON("ms", "0.7.0", "index.js"),
		nm + "/unused/node_modules/ms/index.js":     "module.exports = 0\n",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	p := New(Options{})
	components, err := p.InventoryImage(context.Background(), img, []ecosystem.Subject{{Ecosystem: "npm", Name: "ms", Raw: "npm:ms"}})
	if err != nil {
		t.Fatal(err)
	}
	// Three versions of ms are installed, so there are three things to say.
	versions := map[string]bool{}
	for _, c := range components {
		versions[c.Version] = true
	}
	if len(components) != 3 || !versions["1.0.0"] || !versions["2.1.3"] || !versions["0.7.0"] {
		t.Fatalf("got %d components %v, want one per installed version", len(components), versions)
	}

	// And the graph resolves each require to the copy Node would load: the two
	// required versions are reached, the one nested under an unrequired
	// package is not. All three findings carry the name "ms", so they can only
	// be told apart by version.
	byVersion := map[string]ecosystem.Finding{}
	for _, f := range findingsFor(t, img, []ecosystem.Subject{{Ecosystem: "npm", Name: "ms", Raw: "npm:ms"}}, Options{}) {
		byVersion[f.Version] = f
	}
	for _, v := range []string{"1.0.0", "2.1.3"} {
		if f := byVersion[v]; f.Status != ecosystem.StatusLinked {
			det, _ := evidence(f)
			t.Errorf("ms@%s = %s, want linked: it is required:%s", v, f.Status, det)
		}
	}
	if f := byVersion["0.7.0"]; f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("ms@0.7.0 = %s/%s, want not_in_execute_path: nothing requires the package it nests under:%s",
			f.Status, f.Method, det)
	}
}

// appTree is an image whose entrypoint requires one installed package and not
// the other. It is the shape every reachability row is decided on.
func appTree(main string, extra map[string]string) map[string]string {
	files := map[string]string{
		"/app/index.js":               main,
		"/app/package.json":           pkgJSON("app", "1.0.0", "index.js"),
		nm + "/debug/package.json":    pkgJSON("debug", "4.3.4", "./src/index.js"),
		nm + "/debug/src/index.js":    "module.exports = 1\n",
		nm + "/left-pad/package.json": pkgJSON("left-pad", "1.3.0", "index.js"),
		nm + "/left-pad/index.js":     "module.exports = 2\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

// The two rows the graph adds: required is still linked, and unrequired with
// nothing blocking is the only not_in_execute_path this ecosystem can reach.
func TestRequireGraphDecidesReachability(t *testing.T) {
	img := nodeImage(t, appTree("const d = require('debug')\n", nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})

	f := got["left-pad"]
	if f.Status != ecosystem.StatusNotInPath || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("left-pad = %s/%s, want not_in_execute_path/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("left-pad justification = %q", f.Justification)
	}
	if det, blocking := evidence(f); blocking {
		t.Errorf("a concluded finding must carry no blocking evidence:%s", det)
	}

	f = got["debug"]
	if f.Status != ecosystem.StatusLinked || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("debug = %s/%s, want linked/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, "/app/index.js") {
		t.Errorf("nothing in the evidence names what requires debug:%s", det)
	}
}

// ESM reaches the graph through a different syntax and must reach the same
// answer, including the multi-line braced form whose "from" lands on its own
// line.
func TestESMImportsAreFollowed(t *testing.T) {
	img := nodeImage(t, appTree("export {\n  a,\n} from 'debug'\nimport './local.js'\n", map[string]string{
		"/app/local.js": "",
	}))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if f := got["debug"]; f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Errorf("debug = %s, want linked: a re-export is an import:%s", f.Status, det)
	}
	if f := got["left-pad"]; f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("left-pad = %s, want not_in_execute_path:%s", f.Status, det)
	}
}

// A computed require in the application's own code is unscoped: it could load
// anything, so nothing installed can be declared unrequired.
func TestABlockingTaintStopsTheUnreachedConclusion(t *testing.T) {
	img := nodeImage(t, appTree("require('debug')\nconst m = require(chosen)\n", nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["left-pad"]
	if f.Status != ecosystem.StatusLinked || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("left-pad = %s/%s, want linked/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
	det, blocking := evidence(f)
	if !blocking {
		t.Errorf("the taint that withheld the conclusion is not in the evidence:%s", det)
	}
	if !strings.Contains(det, "nothing reachable from") {
		t.Errorf("the unreached half of the finding is missing:%s", det)
	}

	// --dynamic-import-policy=assume-none is the user taking that risk on.
	f = statusesWith(t, img, []ecosystem.Subject{{Raw: "all"}}, Options{DynamicPolicy: modgraph.DynamicAssumeNone})["left-pad"]
	if f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("with assume-none left-pad = %s, want not_in_execute_path:%s", f.Status, det)
	}
}

// A computed require inside an installed package has to block conclusions about
// that package's *dependencies*, not merely about itself.
//
// This is the shape that shipped broken. The taint was scoped to the package
// containing the computed require, which made it inert: that package is reached
// by definition -- its file was read in order to find the taint -- so the taint
// could never withhold a conclusion from anything. npm's own image demonstrated
// the cost, reporting tar as not_in_execute_path behind a `require(cliEntry)`
// that is exactly how npm loads it.
func TestADynamicRequireBlocksThePackagesItCouldReach(t *testing.T) {
	dep := func(name, version, deps string) string {
		return fmt.Sprintf(`{"name":%q,"version":%q,"main":"index.js","dependencies":{%s}}`, name, version, deps)
	}
	img := nodeImage(t, map[string]string{
		"/app/index.js":     "require('loader')\n",
		"/app/package.json": dep("app", "1.0.0", `"loader":"^1.0.0"`),

		// The lazy loader: reached statically, and it computes what it loads.
		nm + "/loader/package.json": dep("loader", "1.0.0", `"tar":"^7.0.0"`),
		nm + "/loader/index.js": "const p = require('node:path').resolve(__dirname, 'cmd.js')\n" +
			"require(p)\n",
		nm + "/loader/cmd.js": "module.exports = 1\n",

		// Declared by the loader, never named in any file the scanner can read.
		nm + "/tar/package.json": dep("tar", "7.5.11", `"minipass":"^7.0.0"`),
		nm + "/tar/index.js":     "module.exports = 2\n",

		// One level further out: reachable through tar, so still in scope.
		nm + "/minipass/package.json": pkgJSON("minipass", "7.1.2", "index.js"),
		nm + "/minipass/index.js":     "module.exports = 3\n",

		// Depended on by nobody. The loader cannot resolve a bare specifier to
		// it, so the taint must leave this one concludable.
		nm + "/left-pad/package.json": pkgJSON("left-pad", "1.3.0", "index.js"),
		nm + "/left-pad/index.js":     "module.exports = 4\n",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	for _, name := range []string{"tar", "minipass"} {
		f := got[name]
		det, blocking := evidence(f)
		if f.Status != ecosystem.StatusLinked {
			t.Errorf("%s = %s, want linked: the loader could require it at runtime:%s", name, f.Status, det)
		}
		if !blocking {
			t.Errorf("%s was withheld by no evidence, so nothing recorded why:%s", name, det)
		}
	}
	if f := got["left-pad"]; f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("left-pad = %s, want not_in_execute_path: nothing installed depends on it:%s", f.Status, det)
	}
}

// A dependency closure that cannot be walked is not a small closure. A manifest
// naming something that is not installed where the resolver can see it means
// the tree is not fully modelled here, and a taint scoped to only what the walk
// did find would clear exactly the packages it failed to see.
func TestAnUnwalkableClosureTaintsGlobally(t *testing.T) {
	img := nodeImage(t, map[string]string{
		"/app/index.js":     "require('loader')\n",
		"/app/package.json": pkgJSON("app", "1.0.0", "index.js"),

		nm + "/loader/package.json": `{"name":"loader","version":"1.0.0","main":"index.js",` +
			`"dependencies":{"installed-nowhere":"^1.0.0"}}`,
		nm + "/loader/index.js": "require(process.env.PLUGIN)\n",

		nm + "/left-pad/package.json": pkgJSON("left-pad", "1.3.0", "index.js"),
		nm + "/left-pad/index.js":     "module.exports = 1\n",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["left-pad"]
	det, blocking := evidence(f)
	if f.Status != ecosystem.StatusLinked || !blocking {
		t.Errorf("left-pad = %s (blocking=%v), want linked behind a global taint:%s", f.Status, blocking, det)
	}
}

// A require() inside a comment or a template literal is not a require.
//
// A require() inside an ordinary string literal is deliberately not tested
// here, because the scanner does read it as one. It has to: the interior of a
// quoted string is exactly where a real specifier lives, so blanking it would
// blank every require in the file. That false positive only ever enlarges the
// reachable set, which is the safe direction.
func TestTheScannerIgnoresNonCode(t *testing.T) {
	main := "" +
		"// require('left-pad')\n" +
		"/* require('left-pad')\n   require('left-pad') */\n" +
		"const t = `require(${'left-pad'})`\n" +
		"require('debug')\n"
	img := nodeImage(t, appTree(main, nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if f := got["left-pad"]; f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("left-pad = %s, want not_in_execute_path: none of those is a require:%s", f.Status, det)
	}
	if f := got["debug"]; f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Errorf("debug = %s, want linked:%s", f.Status, det)
	}
}

// A regex literal may hold an apostrophe -- /don't/ is legal JavaScript. If the
// scanner took that for the start of a string it would blank the rest of the
// file and lose every require below it, which is the one direction that turns
// a missed import into a false clean.
func TestARegexApostropheDoesNotSwallowTheFile(t *testing.T) {
	main := "" +
		"const re = /don't match/\n" +
		"const cls = /[/'\"]/\n" +
		"require('debug')\n"
	img := nodeImage(t, appTree(main, nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if f := got["debug"]; f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Errorf("debug = %s, want linked: the require after the regex was lost:%s", f.Status, det)
	}
	if f := got["left-pad"]; f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("left-pad = %s, want not_in_execute_path:%s", f.Status, det)
	}
}

// The "exports" map redirects a subpath, and the resolver has to follow it
// rather than probe for a file that is not there.
func TestExportsMapResolvesASubpath(t *testing.T) {
	img := nodeImage(t, map[string]string{
		"/app/index.js": "require('modern/feature')\n",
		nm + "/modern/package.json": `{"name":"modern","version":"2.0.0",` +
			`"exports":{".":"./dist/main.js","./feature":{"require":"./dist/feature.js"}}}`,
		nm + "/modern/dist/main.js":    "",
		nm + "/modern/dist/feature.js": "module.exports = 1\n",
		// Never named, so it stays unreached and proves the graph is not just
		// rooting everything.
		nm + "/modern/dist/other.js": "",
		nm + "/idle/package.json":    pkgJSON("idle", "1.0.0", "index.js"),
		nm + "/idle/index.js":        "",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/app/index.js"}}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	f := got["modern"]
	if f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Fatalf("modern = %s, want linked: exports redirects the subpath to a real file:%s", f.Status, det)
	}
	det, _ := evidence(f)
	if !strings.Contains(det, "feature.js") {
		t.Errorf("the evidence does not name the file exports redirected to:%s", det)
	}
	if got["idle"].Status != ecosystem.StatusNotInPath {
		t.Errorf("idle = %s, want not_in_execute_path", got["idle"].Status)
	}
}

// A bundled entrypoint ships no node_modules of its own. The inventory can
// still find an unrelated tree, and the taint has to say out loud that what
// actually runs was never inspected.
func TestBundledEntrypointTaints(t *testing.T) {
	img := nodeImage(t, map[string]string{
		// The thing that runs: one file, no node_modules beside it.
		"/dist/bundle.js": "console.log(1)\n",
		// An unrelated installed tree elsewhere in the image.
		nm + "/left-pad/package.json": pkgJSON("left-pad", "1.3.0", "index.js"),
		nm + "/left-pad/index.js":     "",
	})
	img.Config = target.ImageConfig{Entrypoint: []string{"node", "/dist/bundle.js"}}

	f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["left-pad"]
	if f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Fatalf("left-pad = %s, want linked behind the bundled-entrypoint taint:%s", f.Status, det)
	}
	det, blocking := evidence(f)
	if !blocking {
		t.Fatalf("a bundled entrypoint must block the unreached conclusion:%s", det)
	}
	if !strings.Contains(det, "bundle") && !strings.Contains(det, "node_modules") {
		t.Errorf("the evidence does not explain what a bundle costs the scan:%s", det)
	}
}

// --roots is how an image whose real command comes from outside its config
// still gets a closure rather than a global escalation.
func TestExtraRootsFeedTheRequireGraph(t *testing.T) {
	img := nodeImage(t, appTree("require('debug')\n", nil))
	img.Config = target.ImageConfig{Entrypoint: []string{"/bin/sh", "-c", "exec node /app/index.js"}}

	// Without help, a foreign entrypoint escalates every installed package to a
	// root, so nothing is unrequired and nothing concludes.
	if f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["left-pad"]; f.Status != ecosystem.StatusLinked {
		t.Errorf("left-pad = %s, want linked behind the foreign-entrypoint taint", f.Status)
	}

	f := statusesWith(t, img, []ecosystem.Subject{{Raw: "all"}}, Options{Roots: []string{"/app/index.js"}})["left-pad"]
	if f.Status != ecosystem.StatusNotInPath || f.Method != MethodGraph {
		det, _ := evidence(f)
		t.Fatalf("with --roots left-pad = %s/%s, want not_in_execute_path/%s:%s", f.Status, f.Method, MethodGraph, det)
	}
}

// An image whose config names no command at all cannot have a closure, and the
// escalation that follows must not read as a clean scan.
func TestNoEntrypointEscalates(t *testing.T) {
	img := nodeImage(t, appTree("require('debug')\n", nil))

	f := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})["left-pad"]
	if f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Errorf("left-pad = %s, want linked: with no entrypoint nothing is unrequired:%s", f.Status, det)
	}
}

// npm start is the ordinary way a Node image is launched, and the script it
// names is where the real entry file is written down.
func TestPackageManagerStartFindsTheScript(t *testing.T) {
	files := appTree("require('debug')\n", map[string]string{
		"/app/package.json": `{"name":"app","version":"1.0.0","scripts":{"start":"node index.js"}}`,
	})
	img := nodeImage(t, files)
	img.Config = target.ImageConfig{
		Entrypoint: []string{"npm", "start"},
		WorkingDir: "/app",
	}

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if f := got["debug"]; f.Status != ecosystem.StatusLinked {
		det, _ := evidence(f)
		t.Errorf("debug = %s, want linked:%s", f.Status, det)
	}
	f := got["left-pad"]
	if f.Status != ecosystem.StatusNotInPath {
		det, _ := evidence(f)
		t.Errorf("left-pad = %s, want not_in_execute_path: npm start named the entry file:%s", f.Status, det)
	}
}

func TestDetectSkipsAnImageWithNoNodeModules(t *testing.T) {
	img := nodeImage(t, map[string]string{"/etc/os-release": "ID=debian\n"})
	ok, err := New(Options{}).DetectImage(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("the plugin claimed to apply to an image with no node_modules")
	}
}

func TestMatchesNameAcceptsAScopedPackageByItsBareName(t *testing.T) {
	img := nodeImage(t, map[string]string{
		nm + "/@babel/traverse/package.json": pkgJSON("@babel/traverse", "7.23.2", "lib/index.js"),
		nm + "/@babel/traverse/lib/index.js": "",
	})

	for _, s := range []ecosystem.Subject{
		{Ecosystem: "npm", Name: "@babel/traverse", Raw: "a"},
		{Ecosystem: "npm", Name: "traverse", Raw: "b"},
		{PURL: "pkg:npm/@babel/traverse@7.23.2", Raw: "c"},
		{PURL: "pkg:npm/%40babel/traverse@7.23.2", Raw: "d"},
	} {
		got := statuses(t, img, []ecosystem.Subject{s})
		if f, ok := got["@babel/traverse"]; !ok || f.Status != ecosystem.StatusLinked {
			t.Errorf("subject %+v found %v", s, got)
		}
	}
}

// A package installed at two nesting levels at the same version is one thing to
// say about the image, not two byte-identical findings.
func TestOnePackageInstalledTwiceAtOneVersion(t *testing.T) {
	img := nodeImage(t, map[string]string{
		nm + "/ms/package.json":                pkgJSON("ms", "2.1.3", "index.js"),
		nm + "/ms/index.js":                    "",
		nm + "/a/package.json":                 pkgJSON("a", "1.0.0", "index.js"),
		nm + "/a/index.js":                     "",
		nm + "/a/node_modules/ms/package.json": pkgJSON("ms", "2.1.3", "index.js"),
		nm + "/a/node_modules/ms/index.js":     "",
	})

	p := New(Options{})
	components, err := p.InventoryImage(context.Background(), img, []ecosystem.Subject{{Ecosystem: "npm", Name: "ms", Raw: "npm:ms"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1: %+v", len(components), components)
	}
	if len(components[0].Locations) != 2 {
		t.Errorf("locations = %v, want both nesting levels", components[0].Locations)
	}
}

// A nested node_modules belongs to the package that nests it, so its files must
// not be counted as the outer package's.
func TestNestedFilesBelongToTheNestedPackage(t *testing.T) {
	img := nodeImage(t, map[string]string{
		// The outer package ships only types; the copy of ms nested inside it
		// ships real code. If the walk credited that code to @types/thing, the
		// no-code row would be lost.
		nm + "/@types/thing/package.json":                 pkgJSON("@types/thing", "1.0.0", ""),
		nm + "/@types/thing/index.d.ts":                   "",
		nm + "/@types/thing/node_modules/ms/package.json": pkgJSON("ms", "2.1.3", "index.js"),
		nm + "/@types/thing/node_modules/ms/index.js":     "module.exports = 1\n",
	})

	got := statuses(t, img, []ecosystem.Subject{{Raw: "all"}})
	if f := got["@types/thing"]; f.Status != ecosystem.StatusNotPresent || f.Method != MethodNoCode {
		det, _ := evidence(f)
		t.Errorf("@types/thing = %s/%s, want not_present/%s:%s", f.Status, f.Method, MethodNoCode, det)
	}
	if f := got["ms"]; f.Status == ecosystem.StatusNotPresent {
		t.Errorf("ms = %s, want a package that ships code", f.Status)
	}
}

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in   string
		name string
		typ  string
		ok   bool
	}{
		{"pkg:npm/debug@4.3.4", "debug", "npm", true},
		{"pkg:npm/@babel/traverse@7.23.2", "@babel/traverse", "npm", true},
		{"pkg:npm/%40babel/traverse@7.23.2", "@babel/traverse", "npm", true},
		{"pkg:npm/@babel/traverse", "@babel/traverse", "npm", true},
		{"pkg:pypi/pyyaml@6.0.1", "pyyaml", "pypi", true},
		{"debug", "", "", false},
	}
	for _, c := range cases {
		name, typ, ok := parsePURL(c.in)
		if name != c.name || typ != c.typ || ok != c.ok {
			t.Errorf("parsePURL(%q) = %q,%q,%v want %q,%q,%v", c.in, name, typ, ok, c.name, c.typ, c.ok)
		}
	}
}
