// Package pypi is the Python distribution ecosystem plugin.
//
// Its deterministic presence test today is the installed-distribution
// inventory in internal/langdb: is the distribution installed at all, and does
// it ship any importable code? That is a weaker test than the Go plugin's
// pclntab or the OS plugin's DT_NEEDED closure, and deliberately so -- Python
// removes nothing at build time, so "the code is on disk" is all an inventory
// can honestly establish. The import graph that turns reachability into a
// second lever lands on top of this, and until it does every installed
// distribution an advisory applies to reports linked.
package pypi

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// Plugin analyzes the Python distributions installed in an image.
type Plugin struct {
	// Logf receives progress messages. Never nil after New.
	Logf func(format string, args ...any)

	mu   sync.Mutex
	prep *prepared
}

// Options configure a Plugin.
type Options struct {
	Logf func(format string, args ...any)
}

// New returns a configured PyPI plugin.
func New(opts Options) *Plugin {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Plugin{Logf: logf}
}

// ID implements ecosystem.Plugin.
func (p *Plugin) ID() string { return "pypi" }

// Ecosystems implements ecosystem.Plugin. PyPI is not versioned by distro the
// way the OS ecosystems are, so there is exactly one string.
func (p *Plugin) Ecosystems() []string { return []string{"PyPI"} }

// state is the plugin-private payload on each Component.
type state struct {
	// pkgs are the installed distributions this component covers. It is a slice
	// because the same name and version legitimately appears in more than one
	// site-packages directory -- Debian's dist-packages and a virtualenv's
	// site-packages both, for instance -- and reporting those as two components
	// would print two byte-identical findings for one fact.
	pkgs []langdb.Package

	// absent marks a component the user asked about that no site-packages
	// directory lists.
	absent bool

	// unreadable are dist-info directories that could not be identified. They
	// only matter to an absent component: something that could not be named
	// cannot be ruled out as the thing being asked about.
	unreadable []string
}

// files returns every file the covered distributions install.
func (s *state) files() []string {
	var out []string
	for _, p := range s.pkgs {
		out = append(out, p.Files...)
	}
	return out
}

// filesKnown reports whether every covered distribution's file list came from
// its own manifest. One reconstructed list is enough to make the union unfit
// to support a "ships no code" conclusion.
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
}

// prepare finds and reads every site-packages directory in the image, once.
//
// An image with no site-packages at all is not an error -- most images have no
// Python in them -- and the plugin simply does not apply. A site-packages
// directory that exists and cannot be listed is an error, for the reason
// pkgdb.Read has the same rule: an empty inventory renders as "this image
// contains no vulnerable Python packages".
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
	if found := roots[langdb.FormatPyPI]; len(found) > 0 {
		r := &langdb.PyPI{}
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

	// Grouped by name and version, because one distribution installed into two
	// site-packages directories is one thing to say about the image.
	type group struct {
		pkgs []langdb.Package
	}
	order := []string{}
	groups := map[string]*group{}

	matched := map[string]bool{}
	for _, pkg := range pr.res.Packages {
		s, ok := selects(subjects, pkg)
		if !ok {
			continue
		}
		matched[s] = true
		key := pkg.Name + "@" + pkg.Version
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
			order = append(order, key)
		}
		g.pkgs = append(g.pkgs, pkg)
	}

	out := make([]ecosystem.Component, 0, len(order))
	for _, key := range order {
		out = append(out, component(groups[key].pkgs))
	}

	// A distribution the user named that no site-packages lists is a finding,
	// not a silence -- but only when the subject was aimed at this plugin. A
	// bare name with no ecosystem is how --module names a Go module, and
	// answering component_not_present for every module path on every image
	// would be noise indistinguishable from a real result.
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
		p.Logf("  no installed Python distribution is named %s", name)
		out = append(out, ecosystem.Component{
			Ecosystem: "PyPI",
			Name:      langdb.NormalizePyPI(name),
			Extra:     &state{absent: true, unreadable: pr.res.Unreadable},
		})
	}

	p.Logf("Found %d Python distributions to check (PyPI).", len(out))
	return out, nil
}

// component builds the OSV coordinates for one installed distribution.
func component(pkgs []langdb.Package) ecosystem.Component {
	names := pkgs[0].OSVNames()

	locations := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		locations = append(locations, p.Dir)
	}
	sort.Strings(locations)

	return ecosystem.Component{
		Ecosystem: "PyPI",
		Name:      names[0],
		AltNames:  names[1:],
		Version:   pkgs[0].Version,
		PURL:      purl(pkgs[0]),
		Locations: locations,
		Extra:     &state{pkgs: pkgs},
	}
}

// selects reports whether any subject names this distribution, returning the
// raw subject text that matched so the caller can tell which ones found
// nothing.
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

// matchesName matches a subject against the distribution's names, normalized.
//
// Normalizing both sides is what makes `--package pypi:PyYAML`,
// `--package pypi:pyyaml` and `--package pypi:py-yaml` all find the same
// distribution: PEP 503 says they are the same name, and PyPI, OSV and pip all
// treat them that way.
func matchesName(pkg langdb.Package, name string) bool {
	if name == "" {
		return false
	}
	want := langdb.NormalizePyPI(name)
	for _, n := range pkg.OSVNames() {
		if langdb.NormalizePyPI(n) == want {
			return true
		}
	}
	// The import name is worth matching too: a user reading a traceback knows
	// the code as "yaml" long before they know it ships as "PyYAML".
	for _, n := range pkg.ImportNames {
		if langdb.NormalizePyPI(n) == want {
			return true
		}
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
		return ok && typ == "pypi"
	}
	return false
}

// AnalyzeImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) AnalyzeImage(_ context.Context, img *target.Image, items []ecosystem.WorkItem) ([]ecosystem.Finding, error) {
	if _, err := p.prepare(img); err != nil {
		return nil, err
	}

	var out []ecosystem.Finding
	for _, item := range items {
		st, ok := item.Component.Extra.(*state)
		if !ok {
			return nil, fmt.Errorf("pypi: component %s was not produced by this plugin", item.Component.Key())
		}
		ev := evaluator{st: st}
		for _, req := range item.Requests() {
			out = append(out, ev.evaluate(item.Component, req))
		}
	}
	return out, nil
}

// purl renders an installed distribution as a package URL. The purl spec keys
// pypi on the PEP 503 normalized name, which is what langdb.Package.Name
// already holds.
func purl(pkg langdb.Package) string {
	s := "pkg:pypi/" + pkg.Name
	if pkg.Version != "" {
		s += "@" + pkg.Version
	}
	return s
}

// parsePURL pulls the name and type out of a package URL, ignoring the
// namespace, version and qualifiers.
func parsePURL(s string) (name, typ string, ok bool) {
	if !strings.HasPrefix(s, "pkg:") {
		return "", "", false
	}
	body := strings.TrimPrefix(s, "pkg:")
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	typ, rest, found := strings.Cut(body, "/")
	if !found {
		return "", "", false
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	return path.Base(rest), strings.ToLower(typ), rest != ""
}
