package langdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// maxNPMDepth bounds how far nested node_modules directories are followed.
//
// npm's own trees rarely exceed a handful of levels since it started hoisting,
// but the structure is only bounded by the dependency graph, and a symlinked
// tree (npm link, pnpm) can be cyclic. A visited set catches the cycles; this
// catches everything else.
const maxNPMDepth = 64

// NPM reads Node packages out of node_modules.
//
// There is no installed-file manifest to read and none is needed: a Node
// package owns its directory outright, minus any nested node_modules, which
// belong to the packages inside them. That nesting is not an accident of layout
// -- it is how npm installs two versions of one package in the same tree -- so
// each nesting level is reported as a separate installed instance, with its own
// Dir. The resolver needs that, because which copy of a package a file sees
// depends on where the file is.
type NPM struct{}

// Format implements Reader.
func (*NPM) Format() Format { return FormatNPM }

// DirNames implements Reader.
func (*NPM) DirNames() []string { return []string{"node_modules"} }

// Read implements Reader.
func (r *NPM) Read(fsys target.RootFS, roots []string) (Result, error) {
	res := Result{Format: FormatNPM, Roots: roots}
	visited := map[string]bool{}
	for _, root := range roots {
		if err := readNodeModules(fsys, root, root, 0, visited, &res); err != nil {
			return Result{}, err
		}
	}
	sortPackages(res.Packages)
	sort.Strings(res.Unreadable)
	return res, nil
}

// readNodeModules parses one node_modules directory and recurses into the
// nested ones inside each package it finds.
//
// db is the top-level node_modules the recursion started from, which is what
// gets reported as the database a package came from; dir is the level being
// read now.
func readNodeModules(fsys target.RootFS, db, dir string, depth int, visited map[string]bool, res *Result) error {
	if depth > maxNPMDepth || visited[dir] {
		return nil
	}
	visited[dir] = true

	entries, err := fsys.ReadDir(dir)
	if err != nil {
		// A top-level node_modules that cannot be listed is a real failure --
		// FindRoots just saw it. A nested one may be a dangling symlink, which
		// is normal in a pruned production image.
		if depth == 0 {
			return fmt.Errorf("listing %s: %w", dir, err)
		}
		return nil
	}

	for _, e := range entries {
		name := e.Name()
		// ".bin" holds symlinks to executables, ".package-lock.json" is
		// bookkeeping, and pnpm's real store lives in ".pnpm" and is reached
		// through the symlinks beside it rather than walked directly.
		if strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasPrefix(name, "@") {
			scope := path.Join(dir, name)
			scoped, err := fsys.ReadDir(scope)
			if err != nil {
				continue
			}
			for _, s := range scoped {
				if strings.HasPrefix(s.Name(), ".") {
					continue
				}
				readNPMPackage(fsys, db, path.Join(scope, s.Name()), name+"/"+s.Name(), depth, visited, res)
			}
			continue
		}
		readNPMPackage(fsys, db, path.Join(dir, name), name, depth, visited, res)
	}
	return nil
}

// readNPMPackage parses one package directory, then descends into its own
// node_modules.
//
// fallback is the name the directory layout implies, used when the manifest
// does not name the package -- which npm permits, and which private and
// vendored packages sometimes do.
func readNPMPackage(fsys target.RootFS, db, dir, fallback string, depth int, visited map[string]bool, res *Result) {
	// Entries are frequently symlinks: pnpm builds the whole tree out of them,
	// and `npm link` produces them one at a time. Resolving to the real path
	// keeps a package from being reported twice under two names, and keeps the
	// file walk -- which never follows symlinks -- pointed at actual files.
	if real, ok := resolveTreePath(fsys, dir); ok {
		dir = real
	}
	if visited[dir] {
		return
	}

	manifest := path.Join(dir, "package.json")
	if fi, err := fsys.Stat(manifest); err != nil || !fi.Mode().IsRegular() {
		// A directory under node_modules with no manifest is not a package.
		// It is still worth descending into: npm's scoped layout and some
		// bundlers leave intermediate directories behind.
		_ = readNodeModules(fsys, db, path.Join(dir, "node_modules"), depth+1, visited, res)
		return
	}

	pkg, ok := parseNPMManifest(fsys, manifest, fallback)
	if !ok {
		res.Unreadable = append(res.Unreadable, manifest)
	} else {
		visited[dir] = true
		pkg.Dir = dir
		pkg.DB = db
		// The directory is the manifest: everything under it belongs to this
		// package except a nested node_modules, which belongs to the packages
		// inside it.
		pkg.Files = walkFiles(fsys, dir, map[string]bool{"node_modules": true})
		pkg.FilesKnown = true
		res.Packages = append(res.Packages, pkg)
	}

	_ = readNodeModules(fsys, db, path.Join(dir, "node_modules"), depth+1, visited, res)
}

// npmManifest is the part of package.json this package needs. Version is
// decoded loosely because a malformed manifest with a usable name is still
// worth reporting -- the name is what an advisory is keyed on.
type npmManifest struct {
	Name    string `json:"name"`
	Version any    `json:"version"`
}

// parseNPMManifest reads name and version out of a package.json.
func parseNPMManifest(fsys target.RootFS, file, fallback string) (Package, bool) {
	b, err := fsys.ReadFile(file)
	if err != nil {
		return Package{}, false
	}
	var m npmManifest
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &m); err != nil {
		return Package{}, false
	}

	name := strings.TrimSpace(m.Name)
	if name == "" {
		name = fallback
	}
	if name == "" {
		return Package{}, false
	}

	version := ""
	if s, ok := m.Version.(string); ok {
		version = strings.TrimSpace(s)
	}

	return Package{
		Format:  FormatNPM,
		Name:    name,
		Version: version,
		// A Node package is imported by the name it declares, scope included.
		// There is no PyYAML-style divergence to guess at, so this is always
		// known.
		ImportNames:      []string{name},
		ImportNamesKnown: true,
	}, true
}

// resolveTreePath follows symlinks to the tree-absolute path a name really
// refers to.
//
// RootFS resolves to host paths because that is what an exec'd subprocess
// needs; stripping the root back off is how a caller gets the inside-the-image
// path that everything else here is keyed by.
func resolveTreePath(fsys target.RootFS, name string) (string, bool) {
	host, err := fsys.HostPath(name)
	if err != nil {
		return "", false
	}
	rel, ok := strings.CutPrefix(host, fsys.Root())
	if !ok {
		return "", false
	}
	rel = path.Clean("/" + strings.TrimPrefix(rel, "/"))
	if rel == name {
		return "", false
	}
	return rel, true
}
