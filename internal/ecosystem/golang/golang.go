// Package golang is the Go ecosystem plugin. It implements both capability
// interfaces, because Go is the one ecosystem vexscan can analyze from either
// end: a shipped binary (pclntab presence + govulncheck binary mode) or a
// source checkout (govulncheck call-graph reachability).
//
// The two paths differ in more than technique. In image mode the plugin
// produces an inventory and the orchestrator resolves advisories from OSV. In
// source mode govulncheck *is* the advisory source — it reports the module
// version alongside the verdict — so there is nothing for an inventory phase to
// contribute.
package golang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/source"
	"github.com/cwayne18/vexscan/internal/target"
	"github.com/cwayne18/vexscan/internal/vex"
)

// Plugin analyzes Go modules.
type Plugin struct {
	// VersionOverride replaces the module version read from a binary's build
	// info. It exists for binaries built with a replace directive or a vendored
	// tree, where build info reports a version OSV cannot match.
	VersionOverride string

	// GoVersion optionally pins the toolchain used for source-mode analysis
	// ("1.24.0"). It matters for stdlib findings, which are toolchain-specific.
	GoVersion string

	// Image is the reference of the image being scanned, in image mode ("" for
	// rootfs or source mode). Its tag is the last resort for a main module
	// whose build info reports "(devel)": `go build` from a checkout stamps no
	// comparable version, and when the binary's own linker flags do not carry
	// one either, the tag is all that is left. See mainModuleVersion for the
	// order the recoveries are tried in and the safeguards on each.
	Image string

	// Modules is an inventory handed in from outside rather than read out of
	// binaries -- today, the Go components of the bill of materials --sbom
	// named.
	//
	// It is a type of this package's own rather than the langdb.Package the
	// other language plugins take, because Go's inventory is not an installed
	// tree: this plugin reads build info out of executables, and a module path
	// and a version is the whole of what survives into a purl. See
	// ecosystem.SBOMFinding for why nothing it produces can be concluded on.
	Modules []Module

	// Logf receives progress messages. Never nil after New.
	Logf func(format string, args ...any)
}

// Module is one Go module an outside inventory named.
type Module struct {
	Path    string
	Version string
}

// Options configure a Plugin.
type Options struct {
	VersionOverride string
	GoVersion       string
	Image           string
	Modules         []Module
	Logf            func(format string, args ...any)
}

// New returns a configured Go plugin.
func New(opts Options) *Plugin {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Plugin{
		VersionOverride: opts.VersionOverride,
		GoVersion:       opts.GoVersion,
		Image:           opts.Image,
		Modules:         opts.Modules,
		Logf:            logf,
	}
}

// ID implements ecosystem.Plugin.
func (p *Plugin) ID() string { return "golang" }

// Ecosystems implements ecosystem.Plugin.
func (p *Plugin) Ecosystems() []string { return []string{"Go"} }

// StdlibModule is the name OSV and govulncheck use for the standard library.
const StdlibModule = binscan.StdlibModule

// NormalizeModule maps the "std" spelling users type onto the "stdlib" spelling
// OSV and govulncheck use.
func NormalizeModule(module string) string {
	if module == "std" {
		return StdlibModule
	}
	return module
}

// binary is one Go binary that links a component's module.
type binary struct {
	path string // absolute path in the extracted tree
	rel  string // path as it appears inside the image
	// main is the binary's own module path, out of its build info. It is the
	// artifact a VEX hub keys statements about this binary's dependencies
	// under, which the image itself is not: an image ships many binaries and a
	// hub speaks about each one separately.
	main string
}

// mainModulePath is a binary's own module path, or "" for one built outside a
// module.
func mainModulePath(bin binscan.Binary) string {
	if bin.Info == nil {
		return ""
	}
	return bin.Info.Main.Path
}

// mainModuleRawVersion is the version build info stamped on a binary's own main
// module, before any recovery -- "" for a binary with no build info, and quite
// possibly "(devel)", which is what mainModuleVersion is for.
func mainModuleRawVersion(bin binscan.Binary) string {
	if bin.Info == nil {
		return ""
	}
	return bin.Info.Main.Version
}

// buildSettings is a binary's recorded build settings, or nil when it carries
// no build info at all.
func buildSettings(bin binscan.Binary) []debug.BuildSetting {
	if bin.Info == nil {
		return nil
	}
	return bin.Info.Settings
}

// state is the plugin-private payload carried in Component.Extra from the
// inventory phase to the analysis phase, so the tree is walked and each
// binary's build info parsed exactly once per run.
type state struct {
	binaries []binary

	// meta marks a component that came from an inventory handed in rather than
	// read out of a binary. There is no binary to open, so no symbol table to
	// test and no govulncheck to run: the two things this plugin decides with.
	meta bool

	// inferred, when set, records that this component's Version was recovered
	// rather than read from buildinfo.Main.Version. The analysis phase attaches
	// it as evidence to every finding so a reader can never mistake a recovered
	// version for one the build info stated outright.
	inferred inference

	// uncomparable, when set, records that this component's Version is one OSV
	// cannot range-match and no recovery could replace -- and holds the account
	// of that. The analysis phase demotes the component's affected verdicts to
	// undetermined, because a presence test that found the code proves nothing
	// on its own when nothing can say whether the code found is already the
	// fixed code. See uncomparableVersion.
	//
	// Never set together with inferred: a version that was recovered is
	// comparable by construction, and one that was not is what this records.
	uncomparable string
}

// inference is a main-module version that build info did not supply, and the
// account of where it came from instead.
//
// Both fields or neither: origin is the empty string exactly when nothing was
// inferred. It doubles as the Evidence.Origin the finding carries, because the
// two recoveries are not equally strong and a reader has to be able to tell
// them apart -- a version read out of the binary's own linker flags is a fact
// about the artifact, and one taken from the image tag is a well-guarded guess
// about it.
type inference struct {
	origin string
	detail string
}

// mainModuleVersion resolves the version to report for a binary's own main
// module, and an account of where that version came from when build info did
// not supply it.
//
// Go stamps no comparable version on a main module built from a checkout: build
// info reports "(devel)" (see isDevelVersion), which OSV cannot range-match, so
// it returns advisories already fixed in the running version and every one of
// them lands as a false positive against the module's own always-present code.
//
// There are two recoveries and they are tried strongest first:
//
//  1. The binary's own linker flags. A project that versions itself with
//     `-ldflags -X .../version.Version=v1.36.2+k3s1` recorded that string in
//     build info even though it never reached Main.Version, so this is not an
//     inference at all -- it is the number the build used, read back out of the
//     artifact. See moduleVersionFromLDFlags for the test that keeps a stamp
//     naming some *dependency's* version from being read as this module's.
//  2. The image tag, which is a guess about the artifact rather than a fact
//     from it, and so is fenced by tagAuthority -- the thing that stops a Go
//     binary inside python:3.12.1 being reported as version 3.12.1 of itself.
//
// Both are governed by the single rule this tool never bends: it must not
// silently under-report. A version that reads too high ranges past a real
// advisory and marks a vulnerable binary clean, so every gate below fails
// closed. When neither recovery is allowed, the original version is returned
// unchanged and the scan goes on querying OSV with "(devel)" and over-reporting
// -- the safe direction, rather than guessing a version that could hide a real
// vulnerability.
func (p *Plugin) mainModuleVersion(modulePath, rawVersion string, settings []debug.BuildSetting) (version string, from inference) {
	if !isDevelVersion(rawVersion) {
		return rawVersion, inference{}
	}
	reported := rawVersion
	if reported == "" {
		reported = "(empty)"
	}

	if stamped, key := moduleVersionFromLDFlags(modulePath, settings); stamped != "" {
		// Naming the key, not just the version, is what makes this auditable:
		// it shows the reader whose version variable was read, which is the
		// entire question moduleVersionFromLDFlags had to answer.
		return stamped, inference{
			origin: "ldflags-version",
			detail: fmt.Sprintf("version not in build info (reported %s); read from the binary's own -ldflags stamp %s=%s",
				reported, key, stamped),
		}
	}

	if p.Image == "" {
		return rawVersion, inference{}
	}
	inferred, tag, why := moduleVersionFromImageTag(modulePath, p.Image)
	if why == "" {
		return rawVersion, inference{}
	}
	// Lead with the fact that this version is not from the artifact, and end
	// with why the tag was believed. An inference a reader cannot audit is not
	// much better than a silent one: naming the tag says where the number came
	// from, and naming the authority says why it was allowed to.
	return inferred, inference{
		origin: "image-tag-version",
		detail: fmt.Sprintf("version not in build info (reported %s); inferred from image tag %q -- %s", reported, tag, why),
	}
}

// depVersion resolves the version to report for one of a binary's *dependency*
// modules, given the resolved version of the binary's own main module.
//
// The comment mainModuleVersion grew up next to says dependencies carry real
// versions. Nearly all of them do, and the ones that do not are the reason this
// exists: a module the main module vendors out of its own tree through a
// directory replace is stamped "(devel)" exactly like a main module built from
// a checkout, with none of the recoveries pointed at it. See stagingversion.go
// for what that costs on a Kubernetes image.
//
// Exactly one of the two accounts comes back set, and they are opposites.
// `from` means a comparable version was recovered and says where it came from.
// `uncomparable` means none could be, and says what that leaves unanswered --
// which the caller must not treat as a version, only as a key to look the
// module up under, since dropping the component entirely would turn a module
// nothing could decide into a module with nothing against it.
func (p *Plugin) depVersion(mainPath, mainVersion, depPath, depVersion string) (version string, from inference, uncomparable string) {
	if !isDevelVersion(depVersion) {
		return depVersion, inference{}, ""
	}
	if v, from := stagingModuleVersion(mainPath, mainVersion, depPath, depVersion); v != "" {
		return v, from, ""
	}
	return depVersion, inference{}, uncomparableDetail(depPath, depVersion)
}

// DetectImage implements ecosystem.ImageAnalyzer.
//
// Go always applies: a Go binary can appear in any image, including one built
// FROM scratch with no package manager and no recognizable distro. The real
// test is whether the inventory walk finds one, and finding none is a
// legitimate "no Go code here" rather than a detection failure.
func (p *Plugin) DetectImage(context.Context, *target.Image) (bool, error) { return true, nil }

// InventoryImage implements ecosystem.ImageAnalyzer.
//
// It returns one component per (module, version) with the binaries linking it
// as Locations. That grouping is what lets the analysis phase keep the
// historical per-binary output shape — one finding per (binary, advisory) —
// without the orchestrator knowing anything about binaries.
func (p *Plugin) InventoryImage(ctx context.Context, img *target.Image, subjects []ecosystem.Subject) ([]ecosystem.Component, error) {
	modules, all := p.wantedModules(subjects)

	// A handed-in inventory replaces the walk rather than adding to it. There
	// are no binaries in the empty tree --sbom stands up, and walking it would
	// only produce a second, empty answer to a question the document already
	// answered.
	if len(p.Modules) > 0 {
		return p.supplied(modules, all), nil
	}

	root := img.FS.Root()
	p.Logf("Scanning for Go binaries...")
	bins := binscan.FindGoBinaries(img.FS)
	p.Logf("Found %d Go binaries.", len(bins))

	if all {
		// Every module every binary links, read straight out of build info.
		// An image with no Go code in it produces nothing, which is the honest
		// answer rather than a silence: there was no Go code to examine.
		return p.groupAll(root, bins), nil
	}
	if len(modules) == 0 {
		return nil, nil // nothing was aimed at this plugin
	}
	return p.group(root, bins, modules), nil
}

// supplied inventories the modules an outside inventory named.
//
// It has no counterpart of groupAll and group both, because there is nothing
// to interrogate: the document lists the modules outright, so the two questions
// those functions answer differently -- which modules does this binary link,
// and does this binary link that module -- are the same filter here.
func (p *Plugin) supplied(modules []string, all bool) []ecosystem.Component {
	if !all && len(modules) == 0 {
		return nil // nothing was aimed at this plugin
	}
	want := make(map[string]bool, len(modules))
	for _, m := range modules {
		want[m] = true
	}

	out := make([]ecosystem.Component, 0, len(p.Modules))
	seen := map[string]bool{}
	for _, m := range p.Modules {
		if m.Path == "" || (!all && !want[m.Path]) {
			continue
		}
		// One component per module@version, the same key grouper uses: a
		// document that lists the same module twice is one thing to say.
		key := m.Path + "@" + m.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ecosystem.Component{
			Ecosystem: "Go",
			Name:      m.Path,
			Version:   m.Version,
			PURL:      purl(m.Path, m.Version),
			Extra:     &state{meta: true},
		})
	}
	p.Logf("Found %d Go modules to check (Go).", len(out))
	return out
}

// groupAll inventories every module linked into every binary.
//
// It exists separately from group because the two ask opposite questions.
// group has a short list of module names and interrogates each binary about
// them; groupAll has the binaries and reads their dependency lists, which is
// the only way round that stays linear when an image carries a hundred
// binaries with a few hundred dependencies apiece.
//
// The version override is deliberately ignored here: --version answers "what
// version is this one module really", which means nothing applied to every
// module in the image at once.
func (p *Plugin) groupAll(root string, bins []binscan.Binary) []ecosystem.Component {
	g := newGrouper()
	for _, bin := range bins {
		if bin.Info == nil {
			continue
		}
		rel := target.Rel(root, bin.Path)
		main := mainModulePath(bin)
		// The standard library is a module OSV publishes advisories against,
		// and it is linked into every Go binary by definition, so an
		// enumeration that left it out would miss the CVEs most likely to
		// apply to all of them at once.
		g.add(StdlibModule, binscan.NormalizeGoVersion(bin.Info.GoVersion), rel, bin.Path, main)

		// The main module is resolved first because its version is what the
		// dependency loop below measures a vendored staging module against.
		var mainVer string
		if m := bin.Info.Main; m.Path != "" {
			// The main module's build-info version can be "(devel)" for a
			// binary built from a checkout, which OSV cannot match; recover a
			// comparable version from the binary's linker flags or the image
			// tag when it is safe to, and keep the provenance so the recovery
			// is visible.
			ver, from := p.mainModuleVersion(m.Path, m.Version, bin.Info.Settings)
			if ver != "" {
				g.add(m.Path, ver, rel, bin.Path, main)
				g.markInferred(m.Path, ver, from)
			}
			mainVer = ver
		}
		for _, dep := range bin.Info.Deps {
			m := dep
			if dep.Replace != nil {
				m = dep.Replace
			}
			if m.Path == "" || m.Version == "" {
				continue
			}
			// Nearly every dependency states a real version and comes through
			// depVersion untouched. The exception is a module the main module
			// vendors out of its own tree, which is stamped "(devel)".
			ver, from, why := p.depVersion(main, mainVer, m.Path, m.Version)
			g.add(m.Path, ver, rel, bin.Path, main)
			g.markInferred(m.Path, ver, from)
			g.markUncomparable(m.Path, ver, why)
		}
	}
	return g.components()
}

// group folds the discovered binaries into one component per (module, version).
func (p *Plugin) group(root string, bins []binscan.Binary, modules []string) []ecosystem.Component {
	g := newGrouper()
	for _, bin := range bins {
		rel := target.Rel(root, bin.Path)
		main := mainModulePath(bin)
		for _, module := range modules {
			version := p.VersionOverride
			var from inference
			var why string
			if version == "" {
				version = bin.ModuleVersion(module)
				// The requested module can be this binary's own main module or
				// one it vendors from its own tree, both of which have the
				// "(devel)" defect groupAll works around; give a targeted scan
				// the same recoveries rather than leaving it stuck with a
				// version OSV cannot match.
				switch {
				case main == module:
					version, from = p.mainModuleVersion(module, version, buildSettings(bin))
				case version != "":
					mainVer, _ := p.mainModuleVersion(main, mainModuleRawVersion(bin), buildSettings(bin))
					version, from, why = p.depVersion(main, mainVer, module, version)
				}
			}
			if version == "" {
				continue // module not linked into this binary
			}
			g.add(module, version, rel, bin.Path, main)
			g.markInferred(module, version, from)
			g.markUncomparable(module, version, why)
		}
	}
	return g.components()
}

// grouper collects (module, version, binary) triples into components.
//
// One component per module@version, so two binaries linking the same version
// share a single OSV lookup, and the binaries that link it ride along as
// Locations. That grouping is what lets the analysis phase emit one finding
// per (binary, advisory) without the orchestrator knowing binaries exist.
type grouper struct {
	byKey map[string]*ecosystem.Component
	order []string
}

func newGrouper() *grouper {
	return &grouper{byKey: map[string]*ecosystem.Component{}}
}

func (g *grouper) add(module, version, rel, path, main string) {
	key := module + "@" + version
	c, ok := g.byKey[key]
	if !ok {
		c = &ecosystem.Component{
			Ecosystem: "Go",
			Name:      module,
			Version:   version,
			PURL:      purl(module, version),
			Extra:     &state{},
		}
		g.byKey[key] = c
		g.order = append(g.order, key)
	}
	// A binary reached twice for the same module -- a replace directive
	// pointing at a path already listed -- must not be scanned twice.
	st := c.Extra.(*state)
	if len(st.binaries) > 0 && st.binaries[len(st.binaries)-1].path == path {
		return
	}
	c.Locations = append(c.Locations, rel)
	st.binaries = append(st.binaries, binary{path: path, rel: rel, main: main})
}

func (g *grouper) components() []ecosystem.Component {
	out := make([]ecosystem.Component, 0, len(g.order))
	for _, key := range g.order {
		out = append(out, *g.byKey[key])
	}
	return out
}

// markInferred records on an already-added component that its version was
// recovered rather than read from build info. The account travels into the
// analysis phase through Component.Extra so every finding for the component can
// carry the provenance as evidence.
//
// A zero inference is a no-op rather than an erasure: two binaries can share a
// module@version with only one of them having had to recover it, and the
// component is the same either way.
func (g *grouper) markInferred(module, version string, from inference) {
	if from.origin == "" {
		return
	}
	if c, ok := g.byKey[module+"@"+version]; ok {
		c.Extra.(*state).inferred = from
	}
}

// markUncomparable records on an already-added component that its version is
// one OSV cannot range-match and nothing could recover. The empty account is a
// no-op for the same reason the zero inference is: the component is keyed by
// module@version, so every binary that reached it reached it with the same
// version and either all of them could not compare it or none of them could.
func (g *grouper) markUncomparable(module, version, why string) {
	if why == "" {
		return
	}
	if c, ok := g.byKey[module+"@"+version]; ok {
		c.Extra.(*state).uncomparable = why
	}
}

// wantedModules resolves subjects to the module paths to look for, and reports
// separately whether one of them asked for everything.
//
// The two ways this comes back with no modules are different and have to stay
// different. No subject aimed here at all -- `--package deb:openssl` -- means Go
// was never asked, and the honest answer is an empty inventory. A subject that
// *was* aimed here and names everything -- `--all` -- means enumerate, which is
// a much larger scan over a completely different source of module names.
// Collapsing the two would either run that scan when nobody asked for it or
// return silence when somebody did.
func (p *Plugin) wantedModules(subjects []ecosystem.Subject) (modules []string, all bool) {
	seen := map[string]bool{}
	for _, s := range subjects {
		if s.Ecosystem != "" && !ecosystem.MatchEcosystem(p, s.Ecosystem) {
			continue
		}
		name := s.Name
		if name == "" && s.PURL != "" {
			name, _ = parsePURL(s.PURL)
		}
		if name == "" {
			all = true
			continue
		}
		name = NormalizeModule(name)
		if !seen[name] {
			seen[name] = true
			modules = append(modules, name)
		}
	}
	return modules, all
}

// AnalyzeImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) AnalyzeImage(ctx context.Context, img *target.Image, items []ecosystem.WorkItem) ([]ecosystem.Finding, error) {
	// Detected once: LookPath is cheap but the result is the same for every
	// binary, and a linked finding records it so a missing govulncheck reads as
	// a skipped reachability test rather than one that ruled nothing out.
	govulnAvailable := binscan.GovulncheckAvailable()
	var out []ecosystem.Finding
	for _, item := range items {
		st, ok := item.Component.Extra.(*state)
		if !ok {
			return nil, fmt.Errorf("golang: component %s was not produced by this plugin", item.Component.Key())
		}
		requests := item.Requests()

		// No binary to open. Every test below reads one, and the loop over an
		// empty list would report nothing at all for a module the document
		// plainly names -- which reads as a module with no advisories against
		// it rather than one nothing was able to examine.
		if st.meta {
			for _, req := range requests {
				f := ecosystem.Finding{
					Module:  item.Component.Name,
					Version: item.Component.Version,
					PURL:    item.Component.PURL,
					CVE:     req.ID,
				}
				if req.Advisory == nil {
					f.Status = ecosystem.StatusUndetermined
					f.Reason = "no_osv_package_mapping"
					out = append(out, f)
					continue
				}
				out = append(out, ecosystem.SBOMFinding(f, item.Component.Name))
			}
			continue
		}

		for _, bin := range st.binaries {
			syms, err := binscan.LoadSymbols(bin.path)
			if err != nil {
				p.Logf("  ! cannot read %s: %v", bin.rel, err)
				continue
			}
			stripped := binscan.IsStripped(bin.path)

			// govulncheck is a subprocess per binary, so it is computed lazily:
			// only a linked, package-granularity, non-stripped candidate can
			// change its status.
			var gvIDs map[string]struct{}
			gvDone := false
			govuln := func() map[string]struct{} {
				if !gvDone {
					gvIDs = binscan.GovulncheckNotAffected(ctx, bin.path)
					gvDone = true
				}
				return gvIDs
			}

			ec := evalCtx{
				binaryRel:       bin.rel,
				module:          item.Component.Name,
				version:         item.Component.Version,
				purl:            item.Component.PURL,
				product:         vex.GoProduct(bin.main),
				stripped:        stripped,
				syms:            syms,
				govuln:          govuln,
				govulnAvailable: govulnAvailable,
				logf:            p.Logf,
			}
			for _, req := range requests {
				f := evaluate(ctx, ec, req.ID, req.Advisory)
				if st.inferred.origin != "" {
					// The version this finding was decided against was
					// recovered, not read from buildinfo.Main.Version.
					// Recording it as evidence keeps the recovery honest: a
					// reader sees where the number came from rather than
					// trusting a version build info never stated.
					f.Evidence = append(f.Evidence, ecosystem.Evidence{
						Origin: st.inferred.origin,
						Detail: st.inferred.detail,
					})
				}
				if st.uncomparable != "" {
					f = uncomparableVersion(f, st.uncomparable)
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// DetectSource implements ecosystem.SourceAnalyzer: a tree is a Go project if
// it has a go.mod.
func (p *Plugin) DetectSource(_ context.Context, src *target.Source) (bool, error) {
	fi, err := os.Stat(filepath.Join(src.Dir, "go.mod"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return !fi.IsDir(), nil
}

// AnalyzeSource implements ecosystem.SourceAnalyzer.
func (p *Plugin) AnalyzeSource(ctx context.Context, src *target.Source, subjects []ecosystem.Subject, requested []string) ([]ecosystem.Finding, error) {
	modules, all := p.wantedModules(subjects)
	if len(modules) == 0 && !all {
		return nil, nil // nothing was aimed at this plugin
	}

	stmts, err := source.Scan(ctx, src, p.GoVersion, p.Logf)
	if err != nil {
		return nil, err
	}
	if all {
		// govulncheck source mode enumerates for free: it reports every
		// vulnerable module in the graph, so --all is just a matter of taking
		// the modules from its output instead of from the command line.
		modules = flaggedModules(stmts)
	}

	// In source mode the artifact is the checkout's own module, which is what a
	// hub would have filed statements about this dependency graph under.
	product := vex.GoProduct(moduleOf(src.Dir))

	var out []ecosystem.Finding
	for _, module := range modules {
		fs := findingsForModule(module, stmts, requested, !all)
		for i := range fs {
			fs[i].Product = product
		}
		out = append(out, fs...)
	}
	return out, nil
}

// moduleOf reads the module path out of a checkout's go.mod.
//
// Hand-parsed rather than pulled in with golang.org/x/mod: the module
// directive is the first non-comment line of every go.mod, and a dependency
// for one line of parsing is a worse trade than the fifteen lines below.
// Failure is silent and returns "" -- a missing module path only means no hub
// lookup, and DetectSource has already established the file exists.
func moduleOf(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		rest, ok := strings.CutPrefix(line, "module")
		if !ok || (rest != "" && !strings.ContainsAny(rest[:1], " \t")) {
			continue
		}
		// A module path may be quoted, though gofmt never writes it that way.
		return strings.Trim(strings.TrimSpace(rest), `"`)
	}
	return ""
}

// flaggedModules is every module govulncheck had something to say about,
// sorted so a repeated scan reports in the same order.
func flaggedModules(stmts []source.Statement) []string {
	seen := map[string]bool{}
	var out []string
	for _, st := range stmts {
		if st.Module != "" && !seen[st.Module] {
			seen[st.Module] = true
			out = append(out, st.Module)
		}
	}
	sort.Strings(out)
	return out
}

// findingsForModule turns govulncheck's statements for one module into
// findings.
//
// targeted says whether the user named this module. It only matters for a
// requested id the module has no statement for: when the module was named, the
// user is owed an answer about it and gets one, and when the module came out of
// an enumeration, saying "CVE-2023-39325 is not present in each of your 400
// dependencies" is noise. An id that lands nowhere at all is reported by the
// orchestrator, which is the only thing that can see that it landed nowhere.
func findingsForModule(module string, stmts []source.Statement, requested []string, targeted bool) []ecosystem.Finding {
	byID := map[string]source.Statement{}
	moduleSeen := false
	var moduleVersion string
	for _, st := range stmts {
		if st.Module != module {
			continue
		}
		moduleSeen = true
		if moduleVersion == "" {
			moduleVersion = st.Version
		}
		for _, id := range st.IDs() {
			byID[id] = st
		}
	}

	var out []ecosystem.Finding
	if len(requested) > 0 {
		for _, id := range requested {
			st, ok := byID[id]
			if !ok && !targeted {
				continue
			}
			out = append(out, sourceFinding(module, moduleVersion, moduleSeen, id, st, ok))
		}
		return out
	}

	// Report every distinct advisory govulncheck found for the module.
	seen := map[string]bool{}
	for _, st := range stmts {
		if st.Module != module || seen[st.GoID] {
			continue
		}
		seen[st.GoID] = true
		out = append(out, sourceFinding(module, moduleVersion, moduleSeen, primaryID(st), st, true))
	}
	return out
}

// sourceFinding classifies one govulncheck statement.
func sourceFinding(module, moduleVersion string, moduleSeen bool, id string, st source.Statement, matched bool) ecosystem.Finding {
	f := ecosystem.Finding{
		Module:  module,
		Version: moduleVersion,
		PURL:    purl(module, moduleVersion),
		CVE:     id,
		Method:  "govulncheck-source",
	}
	if !matched {
		// No govulncheck statement for this id at the scanned version. Whether
		// that means "analyzed and clean" or "never analyzed" turns entirely on
		// whether the module was in the dependency graph at all, and conflating
		// the two would report an unscanned module as unaffected.
		if moduleSeen {
			f.Status = ecosystem.StatusNotPresent
			f.Justification = "vulnerable_code_not_present"
			f.Reason = "not flagged by govulncheck source analysis"
		} else {
			f.Status = ecosystem.StatusUndetermined
			f.Reason = "module_not_in_dependency_graph"
		}
		return f
	}
	f.GoID = st.GoID
	f.Version = st.Version
	f.PURL = purl(module, f.Version)
	switch {
	case st.Status == "affected":
		f.Status = ecosystem.StatusReachable
		f.Reachability = "reachable (govulncheck source mode: the vulnerable symbol is called)"
	case st.Justification == "vulnerable_code_not_in_execute_path":
		f.Status = ecosystem.StatusNotInPath
		f.Justification = st.Justification
	default: // vulnerable_code_not_present or any other not_affected
		f.Status = ecosystem.StatusNotPresent
		if st.Justification != "" {
			f.Justification = st.Justification
		} else {
			f.Justification = "vulnerable_code_not_present"
		}
	}
	return f
}

// primaryID prefers a CVE alias for display, falling back to the GO id.
func primaryID(st source.Statement) string {
	for _, a := range st.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return st.GoID
}

// purl renders a Go module version as a package URL.
func purl(module, version string) string {
	p := "pkg:golang/" + strings.ReplaceAll(module, "/", "%2F")
	if version != "" {
		p += "@" + version
	}
	return p
}

// parsePURL is the inverse of purl, tolerant of an unescaped module path.
func parsePURL(s string) (module, version string) {
	const prefix = "pkg:golang/"
	if !strings.HasPrefix(s, prefix) {
		return "", ""
	}
	body := strings.TrimPrefix(s, prefix)
	if at := strings.LastIndex(body, "@"); at >= 0 {
		version = body[at+1:]
		body = body[:at]
	}
	return strings.ReplaceAll(body, "%2F", "/"), version
}
