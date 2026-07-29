// Package target models the two things vexscan can analyze — an extracted
// container image and a source checkout — behind a shared vocabulary the
// ecosystem plugins consume.
package target

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// MaxSymlinkHops bounds symlink resolution so a tree containing a link cycle
// cannot hang a caller.
const MaxSymlinkHops = 64

// WalkFunc is called for every entry Walk visits, with a tree-absolute name
// (always starting with "/"). Returning fs.SkipDir or fs.SkipAll behaves as it
// does in filepath.WalkDir.
type WalkFunc func(name string, d fs.DirEntry) error

// RootFS is a read-only view of a filesystem tree that lives in a directory on
// the host but is addressed by the absolute paths it would have from inside.
//
// This is deliberately not an fs.FS. Three consumers need exactly what fs.FS
// refuses to provide: HostPath, because govulncheck is an exec'd subprocess
// that needs a real path; LinkTarget, because shared-library soname resolution
// is mostly symlink chasing and needs the raw link text; and absolute paths,
// because everything inside a container image refers to "/usr/lib", not a
// slash-free relative name.
//
// Every method takes a tree-absolute path. Implementations must confine
// resolution to the tree: a symlink pointing at /etc resolves to /etc inside
// the tree, never to the host's /etc.
type RootFS interface {
	// Root reports the host directory the tree lives in.
	Root() string

	// HostPath maps a tree-absolute path to a host path, following symlinks.
	// The result is guaranteed to be inside Root.
	HostPath(name string) (string, error)

	// Open opens a file for reading, following symlinks.
	Open(name string) (io.ReadCloser, error)

	// ReadFile reads a whole file, following symlinks.
	ReadFile(name string) ([]byte, error)

	// Stat follows symlinks; Lstat reports on the link itself.
	Stat(name string) (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)

	// LinkTarget returns the raw, unresolved text of the symlink at name, or
	// an error when name is not a symlink.
	LinkTarget(name string) (string, error)

	// ReadDir lists a directory in lexical order.
	ReadDir(name string) ([]fs.DirEntry, error)

	// Walk visits name and everything beneath it, without following symlinks
	// (so a link cycle cannot make it loop).
	Walk(name string, fn WalkFunc) error
}

// DirFS is a RootFS backed by a host directory, typically an extracted image.
type DirFS struct {
	root string
}

// NewDirFS returns a RootFS rooted at the host directory root.
func NewDirFS(root string) *DirFS {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	return &DirFS{root: abs}
}

func (d *DirFS) Root() string { return d.root }

func (d *DirFS) HostPath(name string) (string, error) {
	return Resolve(d.root, name)
}

func (d *DirFS) Open(name string) (io.ReadCloser, error) {
	p, err := Resolve(d.root, name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	return f, nil
}

func (d *DirFS) ReadFile(name string) ([]byte, error) {
	p, err := Resolve(d.root, name)
	if err != nil {
		return nil, pathErr("readfile", name, err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, pathErr("readfile", name, err)
	}
	return b, nil
}

func (d *DirFS) Stat(name string) (fs.FileInfo, error) {
	p, err := Resolve(d.root, name)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	// Resolve already followed every symlink component within the tree, so an
	// os.Stat here would only re-follow a dangling link out of it.
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	return fi, nil
}

func (d *DirFS) Lstat(name string) (fs.FileInfo, error) {
	p, err := ResolveParent(d.root, name)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	return fi, nil
}

func (d *DirFS) LinkTarget(name string) (string, error) {
	p, err := ResolveParent(d.root, name)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	t, err := os.Readlink(p)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	return t, nil
}

func (d *DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	p, err := Resolve(d.root, name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	return entries, nil
}

func (d *DirFS) Walk(name string, fn WalkFunc) error {
	host, err := Resolve(d.root, name)
	if err != nil {
		return pathErr("walk", name, err)
	}
	base := path.Clean("/" + name)

	return filepath.WalkDir(host, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			// Extracted images routinely contain entries the current user
			// cannot read. Skipping beats aborting a whole-image scan.
			if de != nil && de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(host, p)
		if rerr != nil {
			return nil
		}
		treeName := base
		if rel != "." {
			treeName = path.Join(base, filepath.ToSlash(rel))
		}
		return fn(treeName, de)
	})
}

func pathErr(op, name string, err error) error {
	return &fs.PathError{Op: op, Path: name, Err: err}
}

// Resolve maps a tree-absolute path to a host path inside root, following
// symlinks that exist in the tree but never escaping it. Absolute link targets
// are re-rooted, exactly as they would resolve from inside a container, and
// ".." is clamped at root rather than allowed to walk out. Resolution is
// lexical (no os.Root) so the module keeps its go 1.23 directive.
func Resolve(root, name string) (string, error) {
	rest := strings.Split(path.Clean("/"+name), "/")
	var resolved []string
	hops := 0

	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]

		switch comp {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}

		candidate := filepath.Join(root, filepath.Join(resolved...), comp)
		fi, err := os.Lstat(candidate)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, comp)
			continue
		}

		hops++
		if hops > MaxSymlinkHops {
			return "", fmt.Errorf("symlink loop resolving %q", name)
		}
		link, err := os.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if path.IsAbs(link) {
			resolved = resolved[:0]
		}
		rest = append(strings.Split(path.Clean(link), "/"), rest...)
	}
	return filepath.Join(root, filepath.Join(resolved...)), nil
}

// ResolveParent resolves everything but the last component of name, leaving a
// final symlink unfollowed. Writers use it so that creating an entry over an
// existing symlink replaces the link instead of writing through it; readers use
// it for lstat and readlink.
func ResolveParent(root, name string) (string, error) {
	clean := path.Clean("/" + name)
	dir, base := path.Split(clean)
	parent, err := Resolve(root, dir)
	if err != nil {
		return "", err
	}
	if base == "" {
		return parent, nil
	}
	return filepath.Join(parent, base), nil
}

// Rel converts a host path under root back to the tree-absolute path it has
// from inside. A path outside root is returned unchanged.
func Rel(root, hostPath string) string {
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return hostPath
	}
	if rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}
