// Package ospkg is the OS package ecosystem plugin: dpkg, apk and rpm.
//
// Its deterministic presence test is the DT_NEEDED closure in
// internal/elfgraph -- would the dynamic linker ever load a file this package
// installed? -- backed by the package database, which answers the cheaper
// question of whether the package is installed at all and whether it ships any
// code.
//
// The package name is ospkg rather than os so that files here can still import
// the standard library's os.
package ospkg

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// Plugin analyzes the packages a distribution's package manager installed.
type Plugin struct {
	// Roots are extra entrypoints for the closure, from --roots. An image whose
	// real command comes from outside its config -- a Kubernetes override, an
	// init system -- has no entrypoint this plugin could otherwise find.
	Roots []string

	// DlopenPolicy decides whether a reachable dlopen blocks conclusions.
	DlopenPolicy elfgraph.DlopenPolicy

	// Ecosystem overrides the OSV ecosystem string derived from os-release. It
	// is the escape hatch for the distributions whose ecosystem os-release does
	// not determine -- SUSE files base packages against the module that ships
	// them, which os-release does not record.
	Ecosystem string

	// Packages, when non-empty, is the inventory to use instead of reading a
	// database out of the tree. It is how --rpm scans packages that were never
	// installed anywhere, and it puts the plugin in metadata-only mode: there
	// is no filesystem behind these packages, so no closure can run and no
	// finding can earn a linked verdict.
	Packages []Supplied

	// Mine reports that this plugin wants advisory prose mined for it. It only
	// says what the orchestrator should spend; the validation that decides
	// whether a mined hint may matter lives in checkSymbols regardless.
	Mine bool

	// TrustImportAbsence lets an unimported symbol decide a status.
	//
	// Off by default, and the default is the honest one: the absence of a
	// direct dynamic import does not prove the vulnerable function is never
	// called, because it is usually called from inside the same library that
	// defines it, where no relocation records it. Turning this on asserts that
	// the risk is acceptable; leaving it off records the observation and
	// changes nothing.
	TrustImportAbsence bool

	// ReadELF loads ELF metadata; nil means the real debug/elf reader. It is
	// the same injection point elfgraph.Options exposes, so the status table
	// can be exercised against a filesystem holding no ELF objects at all.
	ReadELF elfgraph.Reader

	// ReadSymbols loads dynamic symbol tables; nil means elfgraph.Symbols.
	ReadSymbols elfgraph.SymbolReader

	// Logf receives progress messages. Never nil after New.
	Logf func(format string, args ...any)

	mu   sync.Mutex
	prep *prepared
}

// Options configure a Plugin.
type Options struct {
	Roots              []string
	DlopenPolicy       elfgraph.DlopenPolicy
	Ecosystem          string
	Packages           []Supplied
	Mine               bool
	TrustImportAbsence bool
	ReadELF            elfgraph.Reader
	ReadSymbols        elfgraph.SymbolReader
	Logf               func(format string, args ...any)
}

// New returns a configured OS plugin.
func New(opts Options) *Plugin {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Plugin{
		Roots:              opts.Roots,
		DlopenPolicy:       opts.DlopenPolicy,
		Ecosystem:          opts.Ecosystem,
		Packages:           opts.Packages,
		Mine:               opts.Mine,
		TrustImportAbsence: opts.TrustImportAbsence,
		ReadELF:            opts.ReadELF,
		ReadSymbols:        opts.ReadSymbols,
		Logf:               logf,
	}
}

// ID implements ecosystem.Plugin.
func (p *Plugin) ID() string { return "os" }

// Ecosystems implements ecosystem.Plugin. The concrete string for a given
// image is derived from its os-release at detect time; these are the families
// --ecosystem can name.
func (p *Plugin) Ecosystems() []string { return osv.Families() }

// WantsHints implements ecosystem.HintConsumer.
//
// Distro OSV records give a fixed version and nothing about what inside the
// package is vulnerable, so for an image the only thing left to check is
// whether the named function was compiled into this build. That is what the
// mined symbols are for -- after checkSymbols has established they came from
// the advisory and from this package's namespace.
func (p *Plugin) WantsHints() bool { return p.Mine }

// state is the plugin-private payload on each Component.
type state struct {
	// pkg is the database row, or the zero value when absent is set.
	pkg pkgdb.Package

	// meta is the rpm header metadata, populated only in metadata-only mode.
	// It is the entire evidence base there: with no filesystem to walk, what
	// the header says about the files this package would install is all the
	// presence test has to work from.
	meta pkgdb.Meta

	// absent marks a component the user asked about that no database lists.
	// It carries no version, so its advisory lookup returns every advisory ever
	// filed against the name -- which is what makes "you asked about openssl and
	// this image has none" a statement about specific CVEs rather than silence.
	absent bool
}

// prepared is the per-image work done once and shared by every component: the
// package databases, the distribution identity, and the ELF closure.
type prepared struct {
	img *target.Image

	ecosystem string
	release   string // narrows a bare-family ecosystem; see osv.Release.ProductRelease
	distro    string // os-release ID, for the purl namespace
	dbs       []pkgdb.Result

	// metadataOnly means the inventory was handed in rather than read out of a
	// tree, so there is no filesystem to test presence against. Every verdict
	// that needs one is gated on this being false.
	metadataOnly bool
	// meta is the header metadata for the supplied packages, keyed by metaKey.
	// Empty unless metadataOnly.
	meta map[string]pkgdb.Meta

	// The closure is the expensive part -- every ELF object in the image gets
	// opened -- and a scan that resolves to no installed package never needs
	// it, so it is built on first use rather than at detect time.
	once     sync.Once
	graph    *elfgraph.Graph
	graphErr error

	// syms is only populated under --mine-advisories.
	syms *symbolCache
}

// symbolCache holds the dynamic symbol tables read during one image's scan.
//
// glibc alone exports a couple of thousand symbols, and the importer scan
// walks every reachable object once per package being checked, so without this
// the same tables would be parsed over and over inside a single run.
type symbolCache struct {
	fsys target.RootFS
	read elfgraph.SymbolReader

	mu    sync.Mutex
	cache map[string]symbolEntry
}

type symbolEntry struct {
	defined, undefined []string
	err                error
}

// prepare reads the package databases and the distribution identity, once per
// image.
//
// A tree with no package database at all is not an error: a scratch image or a
// distroless one legitimately has none, and the plugin simply does not apply.
// A tree that has one and cannot be understood is an error, always, because the
// alternative is an empty inventory that renders as "this image contains no
// vulnerable packages".
func (p *Plugin) prepare(img *target.Image) (*prepared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prep != nil && p.prep.img == img {
		return p.prep, nil
	}

	pr := &prepared{img: img, syms: &symbolCache{
		fsys:  img.FS,
		read:  p.ReadSymbols,
		cache: map[string]symbolEntry{},
	}}
	// A handed-in inventory replaces the tree entirely: nothing below this
	// reads a database, an os-release, or a file, because with --rpm there is
	// nothing to read one out of.
	if len(p.Packages) > 0 {
		if err := p.prepareSupplied(pr); err != nil {
			return nil, err
		}
		p.prep = pr
		return pr, nil
	}

	found := false
	for _, r := range pkgdb.Readers() {
		if _, ok := r.Detect(img.FS); ok {
			found = true
			break
		}
	}
	if !found {
		p.prep = pr
		return pr, nil
	}

	rel, relErr := readRelease(img.FS)
	switch {
	case p.Ecosystem != "":
		pr.ecosystem = p.Ecosystem
	case relErr != nil:
		return nil, fmt.Errorf("this image has an OS package database but no usable /etc/os-release, "+
			"so its advisories cannot be looked up: %w; name it with --osv-ecosystem", relErr)
	default:
		eco, err := rel.Ecosystem()
		if err != nil {
			return nil, err
		}
		pr.ecosystem = eco
	}
	pr.distro = strings.ToLower(rel.ID)
	// Only meaningful when the ecosystem was derived: a user who named the
	// ecosystem outright with --osv-ecosystem has already said which product
	// they mean, and narrowing that further could only subtract from it.
	if p.Ecosystem == "" && relErr == nil {
		pr.release = rel.ProductRelease()
	}

	dbs, err := pkgdb.Read(img.FS)
	if err != nil {
		return nil, err
	}
	pr.dbs = dbs

	p.prep = pr
	return pr, nil
}

// DetectImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) DetectImage(_ context.Context, img *target.Image) (bool, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return false, err
	}
	return len(pr.dbs) > 0, nil
}

// InventoryImage implements ecosystem.ImageAnalyzer.
func (p *Plugin) InventoryImage(_ context.Context, img *target.Image, subjects []ecosystem.Subject) ([]ecosystem.Component, error) {
	pr, err := p.prepare(img)
	if err != nil {
		return nil, err
	}

	var out []ecosystem.Component
	matched := map[string]bool{}
	for _, db := range pr.dbs {
		for _, pkg := range db.Packages {
			s, ok := selects(subjects, pkg)
			if !ok {
				continue
			}
			matched[s] = true
			out = append(out, pr.component(pkg))
		}
	}

	// A package the user named that no database lists is a finding, not a
	// silence -- but only when the subject was aimed at this plugin. A bare
	// name with no ecosystem is how --module names a Go module, and answering
	// "component_not_present" for every Go module path on every image would be
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
		p.Logf("  no installed package is named %s", name)
		out = append(out, ecosystem.Component{
			Ecosystem: pr.ecosystem,
			Name:      name,
			Extra:     &state{absent: true},
		})
	}

	p.Logf("Found %d OS packages to check (%s).", len(out), pr.ecosystem)
	return out, nil
}

// component builds the OSV coordinates for one installed package.
func (pr *prepared) component(pkg pkgdb.Package) ecosystem.Component {
	names := pkg.OSVNames()
	version := osvVersion(pr.ecosystem, pkg)
	return ecosystem.Component{
		Ecosystem: pr.ecosystem,
		Release:   pr.release,
		Name:      names[0],
		AltNames:  names[1:],
		Version:   version,
		PURL:      purl(pr.distro, pkg, version),
		Locations: []string{pkg.DB},
		Extra:     &state{pkg: pkg, meta: pr.meta[metaKey(pkg)]},
	}
}

// osvVersion is the package version as the ecosystem's OSV records spell it.
//
// rpm databases always carry an epoch and Red Hat's OSV records keep it
// ("1:3.0.7-24.el9"), but Azure Linux's do not: its records read "2.38-6" for a
// package the database calls "0:2.38-6", and an epoch-prefixed query against
// them matches nothing at all -- which reads exactly like a clean image.
func osvVersion(eco string, pkg pkgdb.Package) string {
	if pkg.Format != pkgdb.FormatRPM || !strings.HasPrefix(eco, "Azure Linux") {
		return pkg.Version
	}
	return strings.TrimPrefix(pkg.Version, strconv.Itoa(pkg.Epoch)+":")
}

// selects reports whether any subject names this package, returning the raw
// subject text that matched so the caller can tell which ones found nothing.
func selects(subjects []ecosystem.Subject, pkg pkgdb.Package) (string, bool) {
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

// matchesName matches against the installed name and every name OSV might key
// the package on, so `--package openssl` finds the libssl3 that was built from
// it.
func matchesName(pkg pkgdb.Package, name string) bool {
	if name == "" {
		return false
	}
	if pkg.Name == name {
		return true
	}
	for _, n := range pkg.OSVNames() {
		if n == name {
			return true
		}
	}
	return false
}

// aimedHere reports whether a subject was addressed to this plugin, either by
// naming it outright or by carrying a purl of a type it owns.
func aimedHere(p *Plugin, s ecosystem.Subject) bool {
	if s.Ecosystem != "" {
		return ecosystem.MatchEcosystem(p, s.Ecosystem)
	}
	if s.PURL != "" {
		_, typ, ok := parsePURL(s.PURL)
		return ok && (typ == "deb" || typ == "rpm" || typ == "apk")
	}
	return false
}

// graph builds the ELF closure, once.
func (p *Plugin) graph(pr *prepared) (*elfgraph.Graph, error) {
	pr.once.Do(func() {
		p.Logf("Building the shared-library closure...")
		pr.graph, pr.graphErr = elfgraph.Build(pr.img.FS, elfgraph.Options{
			Config:       pr.img.Config,
			Roots:        p.Roots,
			DlopenPolicy: p.DlopenPolicy,
			ReadELF:      p.ReadELF,
			Logf:         p.Logf,
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

	// The closure is only needed for a component that is actually installed;
	// a run that resolves to nothing but absent packages should not pay for it.
	// In metadata-only mode there is nothing to close over at all -- the tree
	// behind these packages is empty because they were never installed -- so
	// building one would spend the time to conclude that nothing is reachable,
	// which is not a conclusion this mode is entitled to draw.
	var g *elfgraph.Graph
	for _, item := range items {
		st, ok := item.Component.Extra.(*state)
		if !ok {
			return nil, fmt.Errorf("os: component %s was not produced by this plugin", item.Component.Key())
		}
		if !st.absent && !pr.metadataOnly {
			if g, err = p.graph(pr); err != nil {
				return nil, err
			}
			break
		}
	}

	var out []ecosystem.Finding
	for _, item := range items {
		st := item.Component.Extra.(*state)
		ev := p.evaluator(pr, g, st)
		for _, req := range item.Requests() {
			out = append(out, ev.evaluate(item.Component, req))
		}
	}
	return out, nil
}

// readRelease parses the image's os-release.
func readRelease(fsys target.RootFS) (osv.Release, error) {
	f, err := fsys.Open("/etc/os-release")
	if err != nil {
		// Debian and Alpine both symlink /etc/os-release to this.
		f, err = fsys.Open("/usr/lib/os-release")
	}
	if err != nil {
		return osv.Release{}, fmt.Errorf("no /etc/os-release: %w", err)
	}
	defer f.Close()
	return osv.ParseOSRelease(f)
}

// purl renders an installed package as a package URL.
func purl(distro string, pkg pkgdb.Package, version string) string {
	typ := string(pkg.Format)
	namespace := distro
	if namespace == "rhel" {
		// The purl spec names Red Hat's namespace "redhat"; os-release says
		// "rhel".
		namespace = "redhat"
	}
	s := "pkg:" + typ + "/"
	if namespace != "" {
		s += namespace + "/"
	}
	s += pkg.Name
	if version != "" {
		s += "@" + version
	}
	if pkg.Arch != "" {
		s += "?arch=" + pkg.Arch
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

// sortedUnique is a small helper for evidence strings, where order must not
// depend on map iteration.
func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
