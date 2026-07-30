// Package lockmode is the repo-mode analyzer shared by the PyPI and npm
// plugins: inventory a checkout's lock files, then decide advisories against
// what they declare.
//
// It is one package rather than two evaluators because, unlike image mode,
// there is nothing ecosystem-specific left to reason about. Image mode has a
// site-packages layout and an import graph per language; a lock file has been
// reduced by internal/lockfile to a list of coordinates and a development flag,
// and every question repo mode can answer is a question about those two things.
// What still differs -- how a name is normalized, how a purl is spelled, what
// the packages are called in prose -- is data, and lives in Config.
//
// The three answers it can give are the whole of repo mode:
//
//	named package absent from the lock files   not_present, component_not_present
//	present but declared development-only      not_in_execute_path
//	otherwise                                  linked
//
// The gap between that and image mode's table is the import graph, and it is
// not an oversight. Resolving a specifier needs an installed dependency tree,
// and materializing one means running the target's build -- arbitrary code from
// the thing being audited. Repo mode declines, and the "linked" row says out
// loud that no graph was resolved rather than letting the silence read as a
// weaker form of the same answer.
package lockmode

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/lockfile"
	"github.com/cwayne18/vexscan/internal/target"
)

// Config is what one ecosystem has to supply.
type Config struct {
	// Owner is the plugin this analyzer serves, used to tell whether a subject
	// was addressed to it.
	Owner ecosystem.Plugin

	// Ecosystem is the OSV ecosystem string ("PyPI", "npm").
	Ecosystem string

	// Format selects the lock file readers.
	Format lockfile.Format

	// Prefix names the methods this analyzer reports: "<prefix>-lockfile" and
	// "<prefix>-dev-only".
	Prefix string

	// PURLType is the package-URL type this ecosystem owns ("pypi", "npm"),
	// used to route a --package given as a purl.
	PURLType string

	// Normalize maps a name to the spelling OSV keys it on. PEP 503 for PyPI;
	// identity for npm, which keys on the name verbatim, scope included.
	Normalize func(string) string

	// PURL renders a package URL for one coordinate.
	PURL func(name, version string) string

	Logf func(string, ...any)
}

// Analyzer implements the three phases of ecosystem.InventorySourceAnalyzer for
// one ecosystem.
type Analyzer struct{ Config }

// MethodLockfile is the method name for a conclusion drawn from the lock file
// contents alone.
func (a Analyzer) MethodLockfile() string { return a.Prefix + "-lockfile" }

// MethodDevOnly is the method name for the development-dependency partition.
func (a Analyzer) MethodDevOnly() string { return a.Prefix + "-dev-only" }

func (a Analyzer) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

// dir is the tree-absolute directory to read lock files from: the subdirectory
// the user pointed at, or the checkout root.
func dir(src *target.Source) string { return path.Join("/", src.Subdir) }

// state is what Inventory carries forward to Analyze about one component.
type state struct {
	// absent means the user named this package and no lock file declares it.
	absent bool

	// files are the lock files consulted, for evidence.
	files []string

	// dev is lockfile.DevOnly's answer: the lock files all declare this
	// package in a development group.
	dev bool

	// pinned reports that the lock files gave a version. An unpinned entry
	// proves presence and nothing more, which changes what may be concluded
	// about an advisory's range.
	pinned bool
}

// Detect reports whether the checkout carries a lock file of this format.
func (a Analyzer) Detect(_ context.Context, src *target.Source) (bool, error) {
	res, err := lockfile.Read(src.FS, dir(src), a.Format)
	if err != nil {
		return false, err
	}
	return len(res) > 0, nil
}

// Inventory turns the checkout's lock files into components.
func (a Analyzer) Inventory(_ context.Context, src *target.Source, subjects []ecosystem.Subject) ([]ecosystem.Component, error) {
	results, err := lockfile.Read(src.FS, dir(src), a.Format)
	if err != nil {
		return nil, err
	}

	// Repo-relative, because a checkout has no meaningful path space of its
	// own: "package-lock.json" is what the reader has in front of them, while
	// the tree-absolute "/package-lock.json" reads like a path on the host.
	rel := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, f := range in {
			out = append(out, strings.TrimPrefix(f, "/"))
		}
		return out
	}
	var read []string
	for _, r := range results {
		read = append(read, strings.TrimPrefix(r.File, "/"))
	}

	matched := map[string]bool{}
	var out []ecosystem.Component
	for _, pkg := range lockfile.Packages(results) {
		raw, ok := a.selects(subjects, pkg.Name)
		if !ok {
			continue
		}
		matched[raw] = true

		// Dev is asked of the raw results rather than read off the flattened
		// package, because the question is about every place the name appears:
		// a package that is a runtime dependency in any lock file ships.
		dev := lockfile.DevOnly(results, pkg.Name)
		declaredIn := rel(lockfile.FilesFor(results, pkg.Name))
		out = append(out, ecosystem.Component{
			Ecosystem: a.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
			PURL:      a.PURL(pkg.Name, pkg.Version),
			Locations: declaredIn,
			Extra: &state{
				files:  declaredIn,
				dev:    dev,
				pinned: pkg.Version != "",
			},
		})
	}

	// A package the user named that no lock file declares is a finding, not a
	// silence -- but only when the subject was aimed at this plugin. A bare
	// name with no ecosystem is how --module names a Go module, and answering
	// component_not_present for every module path would be noise
	// indistinguishable from a real result.
	for _, s := range subjects {
		if s.MatchesAll() || matched[s.Raw] || !a.aimedHere(s) {
			continue
		}
		name := s.Name
		if name == "" {
			name, _, _ = ParsePURL(s.PURL)
		}
		if name == "" {
			continue
		}
		a.logf("  no lock file in this checkout declares %s", name)
		out = append(out, ecosystem.Component{
			Ecosystem: a.Ecosystem,
			Name:      a.Normalize(name),
			// Every file that was read, not the empty set of files declaring
			// it: the claim here is about what all of them failed to say.
			Extra: &state{absent: true, files: read},
		})
	}

	a.logf("Found %d %s packages to check (%s).", len(out), a.Ecosystem, a.Prefix)
	return out, nil
}

// Analyze decides each work item.
func (a Analyzer) Analyze(_ context.Context, _ *target.Source, items []ecosystem.WorkItem) ([]ecosystem.Finding, error) {
	var out []ecosystem.Finding
	for _, item := range items {
		st, ok := item.Component.Extra.(*state)
		if !ok {
			return nil, fmt.Errorf("%s: component %s was not produced by this plugin", a.Prefix, item.Component.Key())
		}
		for _, req := range item.Requests() {
			out = append(out, a.evaluate(item.Component, st, req))
		}
	}
	return out, nil
}

// evaluate decides one advisory against one declared package.
func (a Analyzer) evaluate(c ecosystem.Component, st *state, req ecosystem.Request) ecosystem.Finding {
	f := ecosystem.Finding{
		Module:  c.Name,
		Version: c.Version,
		PURL:    c.PURL,
		CVE:     req.ID,
	}

	// Absence is decided before the advisory is looked at. Whether OSV carries
	// a record for this id makes no difference to the fact that the checkout
	// does not declare the package the id was asked about.
	if st.absent {
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "component_not_present"
		f.Method = a.MethodLockfile()
		f.Evidence = []ecosystem.Evidence{{
			Origin: a.MethodLockfile(),
			Detail: fmt.Sprintf("%s is not declared in %s", c.Name, lockFiles(st.files)),
		}}
		return f
	}

	if req.Advisory == nil {
		f.Status = ecosystem.StatusUndetermined
		f.Reason = "no_osv_package_mapping"
		return f
	}

	if st.dev {
		// A deterministic test, not a heuristic: "dev" in a lock file means
		// reachable only through development dependencies, so the package is
		// absent from a production install by construction -- `npm ci
		// --omit=dev` and `poetry install --only main` will not write it.
		//
		// What it does not mean is that the code never runs. It runs in CI, and
		// it runs on the machine of everyone who checks the repo out, which is
		// why this is not_in_execute_path rather than not_present.
		f.Status = ecosystem.StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = a.MethodDevOnly()
		f.Evidence = []ecosystem.Evidence{{
			Origin: a.MethodDevOnly(),
			Detail: fmt.Sprintf("%s is declared in %s as a development dependency only, so a production install does not contain it",
				c.Name, lockFiles(st.files)),
		}}
		return f
	}

	f.Status = ecosystem.StatusLinked
	f.Method = a.MethodLockfile()
	f.Evidence = []ecosystem.Evidence{{
		Origin: a.MethodLockfile(),
		Detail: fmt.Sprintf("%s%s is declared in %s", c.Name, atVersion(c.Version), lockFiles(st.files)),
	}}

	if !st.pinned {
		// The advisory was matched against the package name alone, because the
		// checkout pins no version to compare its affected range to. That is a
		// weaker claim than the ordinary row above and has to be marked as one:
		// without it, a `flask` with no `==` would report every Flask advisory
		// ever filed as though the range had been checked.
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin:   a.MethodLockfile(),
			Detail:   fmt.Sprintf("no version is pinned for %s in %s, so this advisory's affected range was not checked against one", c.Name, lockFiles(st.files)),
			Blocking: true,
		})
		f.Reachability = "declared as a dependency at an unpinned version; source mode resolves no import graph"
		return f
	}

	f.Reachability = "declared as a dependency; source mode resolves no import graph, so whether the code is imported is not asserted"
	return f
}

// selects reports whether any subject names this package, returning the raw
// subject text that matched so Inventory can tell which ones found nothing.
func (a Analyzer) selects(subjects []ecosystem.Subject, name string) (string, bool) {
	for _, s := range subjects {
		if s.MatchesAll() {
			return s.Raw, true
		}
		want := s.Name
		if s.PURL != "" {
			n, typ, ok := ParsePURL(s.PURL)
			if !ok || typ != a.PURLType {
				continue
			}
			want = n
		}
		if want != "" && a.Normalize(want) == a.Normalize(name) {
			return s.Raw, true
		}
	}
	return "", false
}

// aimedHere reports whether a subject was addressed to this plugin, either by
// naming it outright or by carrying a purl of the type it owns.
func (a Analyzer) aimedHere(s ecosystem.Subject) bool {
	if s.Ecosystem != "" {
		return ecosystem.MatchEcosystem(a.Owner, s.Ecosystem)
	}
	if s.PURL != "" {
		_, typ, ok := ParsePURL(s.PURL)
		return ok && typ == a.PURLType
	}
	return false
}

// lockFiles renders a list of lock files for evidence prose. A repo can carry
// a dozen requirements files, so past two the rest are counted rather than
// listed.
func lockFiles(files []string) string {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	switch len(sorted) {
	case 0:
		return "this checkout"
	case 1:
		return sorted[0]
	case 2:
		return sorted[0] + " and " + sorted[1]
	default:
		return fmt.Sprintf("%s, %s and %d other files", sorted[0], sorted[1], len(sorted)-2)
	}
}

// atVersion renders a version for prose, or nothing when there is none.
func atVersion(v string) string {
	if v == "" {
		return " with no pinned version"
	}
	return " at " + v
}

// ParsePURL pulls the name and type out of a package URL, ignoring the version
// and qualifiers. The namespace is kept, because npm's scope is one: the purl
// for @babel/core is pkg:npm/%40babel/core, and dropping the namespace would
// turn it into a different package.
func ParsePURL(s string) (name, typ string, ok bool) {
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
	// The spec percent-encodes the parts, which for npm means the scope sigil:
	// pkg:npm/%40babel/core. Leaving it encoded would make the name match
	// nothing, and users type the unencoded form anyway.
	if decoded, err := url.PathUnescape(rest); err == nil {
		rest = decoded
	}
	return rest, strings.ToLower(typ), true
}
