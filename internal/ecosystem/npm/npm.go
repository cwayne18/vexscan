// Package npm is the Node package ecosystem plugin.
//
// Its deterministic presence test has the same two halves as the Python
// plugin's, for the same reason: nothing is eliminated at install time, so an
// inventory can only establish that the code is on disk. The first half is the
// node_modules inventory in internal/langdb -- is the package installed, and
// does it ship anything Node can load? The second is the static require/import
// closure rooted at what the image runs (internal/modgraph over the Node
// Language in node.go), which is this ecosystem's DT_NEEDED closure and the
// only lever left for saying an installed package never runs.
//
// Node differs from Python in one way that matters here. Which copy of a
// package a file sees depends on where the file is, because npm expresses a
// version conflict by nesting a second node_modules inside the package that
// needs it. The resolver therefore keys every lookup on the importing
// directory, and the inventory reports each nesting level as its own installed
// instance.
package npm

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/target"
)

// Plugin analyzes the Node packages installed in an image.
type Plugin struct {
	// Roots are extra entry files for the require graph, from --roots. An
	// image whose real command comes from outside its config -- a Kubernetes
	// override, an init system, a shell wrapper -- has no entrypoint this
	// plugin could otherwise find, and without one every installed package is
	// escalated to a root.
	Roots []string

	// DynamicPolicy decides whether a reachable computed require blocks
	// conclusions.
	DynamicPolicy modgraph.DynamicPolicy

	// Mine opts into the mined-subpath layer (--mine-advisories with --llm).
	Mine bool

	// TrustImportAbsence lets an installed but never-required subpath decide a
	// status. Off by default: the vulnerable function is usually reached from
	// inside the same package, where nothing records it.
	TrustImportAbsence bool

	// Logf receives progress messages. Never nil after New.
	Logf func(format string, args ...any)

	mu   sync.Mutex
	prep *prepared
}

// Options configure a Plugin.
type Options struct {
	Roots              []string
	DynamicPolicy      modgraph.DynamicPolicy
	Mine               bool
	TrustImportAbsence bool
	Logf               func(format string, args ...any)
}

// New returns a configured npm plugin.
func New(opts Options) *Plugin {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Plugin{
		Roots:              opts.Roots,
		DynamicPolicy:      opts.DynamicPolicy,
		Mine:               opts.Mine,
		TrustImportAbsence: opts.TrustImportAbsence,
		Logf:               logf,
	}
}

// ID implements ecosystem.Plugin.
func (p *Plugin) ID() string { return "npm" }

// Ecosystems implements ecosystem.Plugin. npm is not versioned by distro the
// way the OS ecosystems are, so there is exactly one string.
func (p *Plugin) Ecosystems() []string { return []string{"npm"} }

// WantsHints implements ecosystem.HintConsumer.
//
// An npm advisory names a version range and nothing about which part of the
// package is vulnerable. What is checkable is the subpath: npm writes a module
// with a slash and a function with a dot, so "lodash/template" is a file this
// package either ships or does not, and either requires or does not. That is
// what the mined subpaths are for, after checkSubpaths has established they
// came from the advisory and from this package.
func (p *Plugin) WantsHints() bool { return p.Mine }

// state is the plugin-private payload on each Component.
type state struct {
	// pkgs are the installed instances this component covers. It is a slice
	// because npm legitimately installs the same name and version at more than
	// one nesting level, and reporting those as two components would print two
	// byte-identical findings for one fact.
	pkgs []langdb.Package

	// absent marks a component the user asked about that no node_modules
	// directory contains.
	absent bool

	// unreadable are package.json files that could not be parsed. They only
	// matter to an absent component: something that could not be named cannot
	// be ruled out as the thing being asked about.
	unreadable []string
}

// name is what to call this component in prose.
func (s *state) name() string {
	if len(s.pkgs) == 0 {
		return "this package"
	}
	return s.pkgs[0].Name
}

// importNames are the names this package's code is required by, which is what
// a taint scoped to an import is compared against.
func (s *state) importNames() []string {
	var out []string
	for _, p := range s.pkgs {
		out = append(out, p.ImportNames...)
	}
	return out
}

// dirs are the installed instances' directories, for resolving a subpath.
func (s *state) dirs() []string {
	var out []string
	for _, p := range s.pkgs {
		if p.Dir != "" {
			out = append(out, p.Dir)
		}
	}
	return out
}

// files returns every file the covered instances install.
func (s *state) files() []string {
	var out []string
	for _, p := range s.pkgs {
		out = append(out, p.Files...)
	}
	return out
}

// filesKnown reports whether every covered instance's file list came from the
// package's own directory rather than being reconstructed.
//
// For npm this is true whenever there is a package at all -- the directory is
// the manifest, so there is nothing to reconstruct -- but the check is kept,
// and kept in the same place the Python plugin keeps it, because the rule it
// enforces is about provenance and not about Python: a file list that was
// inferred may never support a negative conclusion.
func (s *state) filesKnown() bool {
	for _, p := range s.pkgs {
		if !p.FilesKnown {
			return false
		}
	}
	return len(s.pkgs) > 0
}

// prepared is the per-image work done once and shared by every component.
type prepared struct {
	img *target.Image
	res langdb.Result

	once     sync.Once
	graph    *modgraph.Graph
	graphErr error
}

// prepare finds and reads every node_modules directory in the image, once.
//
// An image with no node_modules at all is not an error -- most images have no
// Node in them -- and the plugin simply does not apply. A node_modules
// directory that exists and cannot be listed is an error, for the reason
// pkgdb.Read has the same rule: an empty inventory renders as "this image
// contains no vulnerable Node packages".
func (p *Plugin) prepare(img *target.Image) (*prepared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prep != nil && p.prep.img == img {
		return p.prep, nil
	}

	roots, err := langdb.FindRoots(img.FS)
	if err != nil {
		return nil, err
	}

	pr := &prepared{img: img}
	if found := roots[langdb.FormatNPM]; len(found) > 0 {
		r := &langdb.NPM{}
		if pr.res, err = r.Read(img.FS, found); err != nil {
			return nil, err
		}
	}

	p.prep = pr
	return pr, nil
}

// DetectImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) DetectImage(_ context.Context, img *target.Image) (bool, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return false, err
	}
	return len(pr.res.Roots) > 0, nil
}

// InventoryImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) InventoryImage(_ context.Context, img *target.Image, subjects []ecosystem.Subject) ([]ecosystem.Component, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return nil, err
	}

	// Grouped by name and version. Two nesting levels holding the same version
	// of one package are one thing to say about the image; two *different*
	// versions are two, which is why the version is part of the key.
	order := []string{}
	groups := map[string][]langdb.Package{}

	matched := map[string]bool{}
	for _, pkg := range pr.res.Packages {
		s, ok := selects(subjects, pkg)
		if !ok {
			continue
		}
		matched[s] = true
		key := pkg.Name + "@" + pkg.Version
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], pkg)
	}

	out := make([]ecosystem.Component, 0, len(order))
	for _, key := range order {
		out = append(out, component(groups[key]))
	}

	// A package the user named that no node_modules contains is a finding, not
	// a silence -- but only when the subject was aimed at this plugin. A bare
	// name with no ecosystem is how --module names a Go module, and answering
	// component_not_present for every module path on every image would be
	// noise indistinguishable from a real result.
	for _, s := range subjects {
		if s.MatchesAll() || matched[s.Raw] || !aimedHere(p, s) {
			continue
		}
		name := s.Name
		if name == "" {
			name, _, _ = parsePURL(s.PURL)
		}
		if name == "" {
			continue
		}
		p.Logf("  no installed Node package is named %s", name)
		out = append(out, ecosystem.Component{
			Ecosystem: "npm",
			Name:      name,
			Extra:     &state{absent: true, unreadable: pr.res.Unreadable},
		})
	}

	p.Logf("Found %d Node packages to check (npm).", len(out))
	return out, nil
}

// component builds the OSV coordinates for one installed package.
func component(pkgs []langdb.Package) ecosystem.Component {
	names := pkgs[0].OSVNames()

	locations := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		locations = append(locations, p.Dir)
	}
	sort.Strings(locations)

	return ecosystem.Component{
		Ecosystem: "npm",
		Name:      names[0],
		AltNames:  names[1:],
		Version:   pkgs[0].Version,
		PURL:      purl(pkgs[0]),
		Locations: locations,
		Extra:     &state{pkgs: pkgs},
	}
}

// selects reports whether any subject names this package, returning the raw
// subject text that matched so the caller can tell which ones found nothing.
func selects(subjects []ecosystem.Subject, pkg langdb.Package) (string, bool) {
	for _, s := range subjects {
		if s.MatchesAll() {
			return s.Raw, true
		}
		if s.PURL != "" {
			if name, _, ok := parsePURL(s.PURL); ok && matchesName(pkg, name) {
				return s.Raw, true
			}
			continue
		}
		if matchesName(pkg, s.Name) {
			return s.Raw, true
		}
	}
	return "", false
}

// matchesName matches a subject against the package's name.
//
// npm names are case-sensitive and there is no PEP 503 equivalent to
// normalize, so this is very nearly a string compare. The one accommodation is
// a scoped package written without its scope: "debug" must not find
// "@types/debug", but a user who types the bare name of a package that only
// exists scoped has typed something unambiguous, and refusing it would be
// pedantry rather than safety.
func matchesName(pkg langdb.Package, name string) bool {
	if name == "" {
		return false
	}
	if pkg.Name == name {
		return true
	}
	if strings.HasPrefix(pkg.Name, "@") && !strings.HasPrefix(name, "@") {
		_, unscoped, _ := strings.Cut(pkg.Name, "/")
		return unscoped == name
	}
	return false
}

// aimedHere reports whether a subject was addressed to this plugin, either by
// naming it outright or by carrying a purl of the type it owns.
func aimedHere(p *Plugin, s ecosystem.Subject) bool {
	if s.Ecosystem != "" {
		return ecosystem.MatchEcosystem(p, s.Ecosystem)
	}
	if s.PURL != "" {
		_, typ, ok := parsePURL(s.PURL)
		return ok && typ == "npm"
	}
	return false
}

// graph builds the require closure, once.
func (p *Plugin) graph(pr *prepared) (*modgraph.Graph, error) {
	pr.once.Do(func() {
		p.Logf("Building the Node require graph...")
		lang := newNode(pr.img, pr.res, p.Logf)
		pr.graph, pr.graphErr = modgraph.Build(pr.img.FS, lang, modgraph.Options{
			Roots:   p.Roots,
			Dynamic: p.DynamicPolicy,
			Logf:    p.Logf,
		})
	})
	return pr.graph, pr.graphErr
}

// AnalyzeImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) AnalyzeImage(_ context.Context, img *target.Image, items []ecosystem.WorkItem) ([]ecosystem.Finding, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return nil, err
	}

	// The closure costs a walk of every reachable source file, so a run that
	// resolves to nothing but packages the image does not have should not pay
	// for it.
	var g *modgraph.Graph
	for _, item := range items {
		st, ok := item.Component.Extra.(*state)
		if !ok {
			return nil, fmt.Errorf("npm: component %s was not produced by this plugin", item.Component.Key())
		}
		if !st.absent {
			if g, err = p.graph(pr); err != nil {
				return nil, err
			}
			break
		}
	}

	// One resolver for the whole run: the mined layer uses it to turn a
	// subpath into files, and it memoizes.
	nd := newNode(pr.img, pr.res, p.Logf)

	var out []ecosystem.Finding
	for _, item := range items {
		st := item.Component.Extra.(*state)
		ev := evaluator{st: st, g: g, node: nd, trust: p.TrustImportAbsence}
		for _, req := range item.Requests() {
			out = append(out, ev.evaluate(item.Component, req))
		}
	}
	return out, nil
}

// purl renders an installed package as a package URL.
//
// A scope is the purl namespace, and the spec keeps its "@": the canonical
// form percent-encodes it, but every tool in this space -- OSV, Syft, Grype --
// reads and writes the literal spelling, and a purl nobody else parses is
// worse than one that is technically under-encoded.
func purl(pkg langdb.Package) string {
	s := "pkg:npm/" + pkg.Name
	if pkg.Version != "" {
		s += "@" + pkg.Version
	}
	return s
}

// parsePURL pulls the name and type out of a package URL, keeping the
// namespace, since for npm the namespace is half the name.
func parsePURL(s string) (name, typ string, ok bool) {
	if !strings.HasPrefix(s, "pkg:") {
		return "", "", false
	}
	body := strings.TrimPrefix(s, "pkg:")
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	typ, rest, found := strings.Cut(body, "/")
	if !found || rest == "" {
		return "", "", false
	}
	// The version is separated by the last "@" -- which is not the scope's,
	// since a scope's "@" is the first character of the name.
	if at := strings.LastIndex(rest, "@"); at > 0 {
		rest = rest[:at]
	}
	rest = strings.ReplaceAll(rest, "%40", "@")
	return path.Clean(rest), strings.ToLower(typ), true
}
