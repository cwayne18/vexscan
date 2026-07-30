package lockfile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// NPM reads package-lock.json, in all three of its formats.
type NPM struct{}

func (*NPM) Format() Format { return FormatNPM }

// npmLock is the subset of package-lock.json this needs.
//
// Both trees are declared because a v2 lock file carries both: "packages" for
// npm 7 and later, "dependencies" as a compatibility shim for npm 6. v1 has
// only "dependencies" and v3 only "packages", so reading whichever is present
// covers every version without branching on lockfileVersion -- which is worth
// avoiding, since a v4 that keeps the "packages" shape would still work.
type npmLock struct {
	Packages     map[string]npmEntry `json:"packages"`
	Dependencies map[string]npmDep   `json:"dependencies"`
}

// npmEntry is one entry in the v2/v3 "packages" map, keyed by install path.
type npmEntry struct {
	// Name is set only when the install path does not spell the registry
	// name -- an aliased dependency, `"foo": "npm:bar@1.0"`, installs bar's
	// code at node_modules/foo. OSV keys the advisory on bar.
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`

	// Link marks a symlink into the workspace rather than a registry install.
	// The target is another entry in the same map, which is the one carrying
	// the version, so counting the link too would double it.
	Link bool `json:"link"`

	// Resolved is the tarball URL. Its absence on a non-link, non-root entry
	// means the package did not come from a registry.
	Resolved string `json:"resolved"`
}

// npmDep is one node of the v1 "dependencies" tree.
type npmDep struct {
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]npmDep `json:"dependencies"`
}

func (n *NPM) Read(fsys target.RootFS, dir string) ([]Result, error) {
	var out []Result
	for _, file := range find(fsys, dir, []string{"package-lock.json", "npm-shrinkwrap.json"}) {
		res, err := n.readFile(fsys, file)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (n *NPM) readFile(fsys target.RootFS, file string) (Result, error) {
	data, err := fsys.ReadFile(file)
	if err != nil {
		return Result{}, fmt.Errorf("reading %s: %w", file, err)
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, fmt.Errorf("parsing %s: %w", file, err)
	}

	res := Result{Format: FormatNPM, File: file, DevKnown: true}
	if len(lock.Packages) > 0 {
		res.Packages = packagesFromV2(lock.Packages)
	} else {
		res.Packages = packagesFromV1(lock.Dependencies)
	}
	return res, nil
}

// packagesFromV2 reads the "packages" map of a v2 or v3 lock file.
func packagesFromV2(entries map[string]npmEntry) []Package {
	var out []Package
	for installPath, e := range entries {
		// The root project is keyed by the empty string, and workspace members
		// by their bare directory. Neither is a dependency, and neither is
		// something OSV can be asked about.
		if installPath == "" || !strings.Contains(installPath, "node_modules/") {
			continue
		}
		if e.Link || e.Version == "" {
			continue
		}
		name := e.Name
		if name == "" {
			name = nameFromInstallPath(installPath)
		}
		if name == "" {
			continue
		}
		out = append(out, Package{Name: name, Version: e.Version, Dev: e.Dev})
	}
	return out
}

// nameFromInstallPath recovers a package name from its position in the tree.
//
// Nesting is how npm carries two versions of one package, so the name is what
// follows the *last* node_modules component: in
// "node_modules/tar/node_modules/minipass" the package is minipass. A scope
// keeps its slash, because that is how npm and OSV both spell it.
func nameFromInstallPath(p string) string {
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return ""
	}
	return strings.Trim(p[i+len("node_modules/"):], "/")
}

// packagesFromV1 flattens the nested "dependencies" tree of a v1 lock file.
func packagesFromV1(deps map[string]npmDep) []Package {
	var out []Package
	var walk func(map[string]npmDep, bool)
	walk = func(m map[string]npmDep, parentDev bool) {
		for name, d := range m {
			// v1 marks only the top of a dev subtree, leaving its transitive
			// dependencies unmarked. Inheriting the flag downward is what makes
			// the partition mean the same thing it does in v2, where npm
			// computes the whole reachable set for you.
			dev := d.Dev || parentDev
			if d.Version != "" {
				out = append(out, Package{Name: name, Version: d.Version, Dev: dev})
			}
			walk(d.Dependencies, dev)
		}
	}
	walk(deps, false)
	return out
}
