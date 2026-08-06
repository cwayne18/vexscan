// Package maven is the Java package ecosystem plugin.
//
// Its deterministic presence test is the strongest one here that is not a
// symbol table, and it is the only one that routinely contradicts a version
// scanner. A jar is a zip: listing its central directory names every class the
// artifact ships, without executing anything and without a parser that could be
// fed a hostile input. So "this artifact does not contain the vulnerable class"
// is a fact this plugin reads off the disk.
//
// That case is the reason the ecosystem exists. The mitigation the Apache
// Logging team published for Log4Shell was
//
//	zip -d log4j-core.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
//
// and the artifact is still org.apache.logging.log4j:log4j-core@2.14.1
// afterwards. Every scanner keying on the version reports CVE-2021-44228;
// vulnerable_code_not_present is the correct answer, and a class list is what
// proves it.
//
// What Java does not have here is a reference graph. Nothing in this package
// reads a constant pool, so an artifact that ships the class is reported linked
// -- present and loadable, with no claim about whether anything calls it. The
// other half of the story that is missing is the coordinate: unlike a Python
// distribution or an npm package, a jar frequently carries no statement of its
// own groupId, so langdb reconstructs one and marks whether it had to. A
// reconstructed coordinate is still queried against OSV; it is never allowed to
// support a claim of absence.
package maven

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// Plugin analyzes the Java archives in an image.
type Plugin struct {
	// Mine opts into the mined-class layer (--mine-advisories with --llm).
	Mine bool

	// Packages is an inventory handed in from outside rather than read out of a
	// tree -- today, the Maven components of the bill of materials --sbom named.
	//
	// It is this plugin's counterpart of ospkg.Plugin.Packages, and it is the
	// weaker one. An rpm header lists the files the package would install, so
	// that path can still rule out a package that ships no code; a CycloneDX
	// component lists nothing -- and here that means no archive to open and no
	// entry list to test a class against -- so every finding it produces is
	// undetermined. See ecosystem.SBOMFinding.
	Packages []langdb.Package

	// Logf receives progress messages. Never nil after New.
	Logf func(format string, args ...any)

	mu   sync.Mutex
	prep *prepared
}

// Options configure a Plugin.
type Options struct {
	Mine     bool
	Packages []langdb.Package
	Logf     func(format string, args ...any)
}

// New returns a configured Maven plugin.
func New(opts Options) *Plugin {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Plugin{Mine: opts.Mine, Packages: opts.Packages, Logf: logf}
}

// ID implements ecosystem.Plugin.
func (p *Plugin) ID() string { return "maven" }

// Ecosystems implements ecosystem.Plugin. OSV keys Java on "Maven" regardless
// of which build tool produced the artifact, so there is exactly one string.
func (p *Plugin) Ecosystems() []string { return []string{"Maven"} }

// WantsHints implements ecosystem.HintConsumer.
//
// Maven advisories are the case that most needs mining and gives it the least
// to work with. OSV's Maven records carry no ecosystem_specific function data
// at all -- unlike RustSec, which publishes affected function names -- so a
// class name can only come from the advisory's prose. When it does, it is
// checkable against something exact: a class is a file in the archive, and
// either the entry is there or it is not.
func (p *Plugin) WantsHints() bool { return p.Mine }

// state is the plugin-private payload on each Component.
type state struct {
	// pkgs are the archives this component covers. It is a slice because one
	// artifact is routinely present more than once -- the same jar in a
	// container's lib directory and inside a war it deploys -- and reporting
	// those as two components would print two identical findings for one fact.
	pkgs []langdb.Package

	// absent marks a component the user asked about that no archive declares.
	absent bool

	// unreadable are archives that would not open, and unidentified are
	// archives that opened and declare no coordinates. Both matter only to an
	// absent component, and for the same reason: something that could not be
	// named cannot be ruled out as the thing being asked about.
	unreadable   []string
	unidentified []string
}

// name is what to call this component in prose.
func (s *state) name() string {
	if len(s.pkgs) == 0 {
		return "this artifact"
	}
	return s.pkgs[0].Name
}

// entries returns every archive entry the covered artifacts hold.
func (s *state) entries() []string {
	var out []string
	for _, p := range s.pkgs {
		out = append(out, p.Files...)
	}
	return out
}

// filesKnown reports whether every covered archive's entry list came from a
// central directory that was read in full.
func (s *state) filesKnown() bool {
	for _, p := range s.pkgs {
		if !p.FilesKnown {
			return false
		}
	}
	return len(s.pkgs) > 0
}

// coordsKnown reports whether every covered archive stated its own coordinates
// rather than having them reconstructed from a file name.
//
// It gates every negative conclusion below the component level. Saying "this
// artifact ships no such class" about an artifact this scan only believes the
// jar to be is two guesses stacked, and the second one hides the first.
func (s *state) coordsKnown() bool {
	for _, p := range s.pkgs {
		if !p.CoordsKnown {
			return false
		}
	}
	return len(s.pkgs) > 0
}

// prepared is the per-image work done once and shared by every component.
type prepared struct {
	img *target.Image
	res langdb.Result

	// metadataOnly means the inventory was handed in rather than read out of a
	// tree, so there is no archive to open. Every verdict that needs one is
	// gated on this being false.
	metadataOnly bool
}

// prepare finds and reads every Java archive in the image, once.
//
// An image with no jars in it is not an error -- most images have no Java --
// and the plugin simply does not apply. An archive that exists and will not
// open is not an error either, because images carry truncated downloads and
// files that merely end in .jar; it goes into Unreadable, where it becomes a
// taint on any later claim of absence rather than a silence.
func (p *Plugin) prepare(img *target.Image) (*prepared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prep != nil && p.prep.img == img {
		return p.prep, nil
	}

	// A handed-in inventory replaces the walk rather than adding to it. There
	// is no tree behind --sbom to find archives in, and walking the empty one
	// it stands up would only produce a second, empty answer to a question the
	// document already answered.
	if len(p.Packages) > 0 {
		p.prep = &prepared{
			img:          img,
			metadataOnly: true,
			res:          langdb.Result{Format: langdb.FormatMaven, Packages: p.Packages},
		}
		return p.prep, nil
	}

	roots, err := langdb.FindRoots(img.FS)
	if err != nil {
		return nil, err
	}

	pr := &prepared{img: img}
	if found := roots[langdb.FormatMaven]; len(found) > 0 {
		r := &langdb.Maven{}
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
	return pr.metadataOnly || len(pr.res.Roots) > 0, nil
}

// InventoryImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) InventoryImage(_ context.Context, img *target.Image, subjects []ecosystem.Subject) ([]ecosystem.Component, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return nil, err
	}

	// Grouped by coordinate and version. The same artifact in two places is one
	// thing to say about the image; two versions of it are two, which is why
	// the version is part of the key.
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

	// An artifact the user named that no archive declares is a finding, not a
	// silence -- but only when the subject was aimed at this plugin. A bare
	// name with no ecosystem is how --module names a Go module, and answering
	// component_not_present for every module path on every image would be noise
	// indistinguishable from a real result.
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
		p.Logf("  no archive in this image declares %s", name)
		out = append(out, ecosystem.Component{
			Ecosystem: "Maven",
			Name:      name,
			Extra: &state{
				absent:       true,
				unreadable:   pr.res.Unreadable,
				unidentified: pr.res.Unidentified,
			},
		})
	}

	p.Logf("Found %d Java artifacts to check (maven).", len(out))
	return out, nil
}

// component builds the OSV coordinates for one artifact.
func component(pkgs []langdb.Package) ecosystem.Component {
	names := pkgs[0].OSVNames()

	locations := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		locations = append(locations, p.Dir)
	}
	sort.Strings(locations)

	return ecosystem.Component{
		Ecosystem: "Maven",
		Name:      names[0],
		AltNames:  names[1:],
		Version:   pkgs[0].Version,
		PURL:      langdb.MavenPURL(pkgs[0].Name, pkgs[0].Version),
		Locations: locations,
		Extra:     &state{pkgs: pkgs},
	}
}

// AnalyzeImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) AnalyzeImage(_ context.Context, img *target.Image, items []ecosystem.WorkItem) ([]ecosystem.Finding, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return nil, err
	}

	var out []ecosystem.Finding
	for _, item := range items {
		st, ok := item.Component.Extra.(*state)
		if !ok {
			return nil, fmt.Errorf("maven: component %s was not produced by this plugin", item.Component.Key())
		}
		ev := evaluator{st: st, meta: pr.metadataOnly}
		for _, req := range item.Requests() {
			out = append(out, ev.evaluate(item.Component, req))
		}
	}
	return out, nil
}

// selects reports whether any subject names this artifact, returning the raw
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

// matchesName matches a subject against an artifact's coordinates.
//
// The full groupId:artifactId is the exact spelling, and every alternate
// candidate coordinate counts too -- the whole point of offering several is
// that any of them may be the real one. A bare artifactId also matches, because
// "log4j-core" is what people say out loud and the groupId is what they look up
// afterwards. It is ambiguous in principle: two groups can publish the same
// artifactId. In practice the ambiguity resolves into extra findings rather
// than missing ones, which is the safe direction for a selector.
func matchesName(pkg langdb.Package, name string) bool {
	if name == "" {
		return false
	}
	for _, n := range pkg.OSVNames() {
		if n == name {
			return true
		}
		if _, artifact, ok := strings.Cut(n, ":"); ok && artifact == name {
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
		return ok && typ == "maven"
	}
	return false
}

// parsePURL pulls the coordinate and type out of a package URL.
//
// A Maven purl puts the groupId in the namespace and the artifactId in the
// name, so pkg:maven/org.apache.logging.log4j/log4j-core is the purl spelling
// of the colon-joined coordinate OSV keys on.
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
	if at := strings.LastIndex(rest, "@"); at > 0 {
		rest = rest[:at]
	}
	group, artifact, found := strings.Cut(rest, "/")
	if !found || group == "" || artifact == "" {
		return "", "", false
	}
	return group + ":" + artifact, strings.ToLower(typ), true
}
