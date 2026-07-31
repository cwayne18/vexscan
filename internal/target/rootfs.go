// Package target models the two things vexscan can analyze — an extracted
// container image and a source checkout — behind a shared vocabulary the
// ecosystem plugins consume.
package target

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// MaxSymlinkHops bounds symlink resolution so a tree containing a link cycle
// cannot hang a caller.
const MaxSymlinkHops = 64

// maxUnreadableSample bounds how many paths of each kind Unreadable names. A
// tree walked by a user who cannot read most of it produces tens of thousands
// of skips, and a report nobody can read is not a report.
const maxUnreadableSample = 10

// WalkFunc is called for every entry Walk visits, with a tree-absolute name
// (always starting with "/"). Returning fs.SkipDir or fs.SkipAll behaves as it
// does in filepath.WalkDir.
type WalkFunc func(name string, d fs.DirEntry) error

// Unreadable accounts for what a tree's walks could not read.
//
// Walk skips what it cannot read rather than aborting, because one
// permission-denied entry must not cost the whole scan. This is what keeps that
// tolerance honest: a subtree that was never looked at is otherwise
// indistinguishable from a subtree with nothing wrong in it, which is the worst
// way this tool can be wrong.
//
// Every gap recorded here is an unknown-size one. A walk lists directories and
// never opens the files in them, so the failure it surfaces is always "this
// directory would not list" -- which hides an unknown number of unnamed
// entries, and leaves nothing downstream able to say even what question went
// unanswered. That is why any entry at all is enough to stop the scan reading
// as an account of the tree, and why an unreadable *file* does not appear here:
// it surfaces at the reader that wanted it, which can name what it lost.
type Unreadable struct {
	// Count is every distinct path skipped, across every walk of the tree.
	Count int `json:"count"`

	// Paths names the first few, in the order they were encountered. It is
	// deliberately not all of them: see maxUnreadableSample.
	Paths []string `json:"paths,omitempty"`
}

// Any reports whether anything was skipped, and so whether the scan is an
// incomplete account of the tree.
func (u Unreadable) Any() bool { return u.Count > 0 }

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

	// Unreadable reports what Walk skipped, accumulated across every walk of
	// this tree and deduplicated by path. It is cumulative rather than
	// per-walk because the question it answers -- was any of this tree
	// invisible to the scan -- is a property of the tree, and several plugins
	// walk the same one.
	Unreadable() Unreadable
}

// DirFS is a RootFS backed by a host directory: an extracted image, or a
// rootfs the user already had on disk.
type DirFS struct {
	root string

	mu      sync.Mutex
	seen    map[string]bool
	skipped Unreadable
}

// NewDirFS returns a RootFS rooted at the host directory root.
func NewDirFS(root string) *DirFS {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	return &DirFS{root: abs, seen: map[string]bool{}}
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

	// treeName maps a host path back to the name it has from inside. The bool
	// is false for a path that is somehow not under the walk root, which the
	// success path skips rather than report under a name that is not its own.
	treeName := func(p string) (string, bool) {
		rel, rerr := filepath.Rel(host, p)
		if rerr != nil {
			return p, false
		}
		if rel == "." {
			return base, true
		}
		return path.Join(base, filepath.ToSlash(rel)), true
	}

	return filepath.WalkDir(host, func(p string, de fs.DirEntry, err error) error {
		who, ok := treeName(p)
		if err != nil {
			// Extracted images routinely contain entries the current user
			// cannot read, and a rootfs owned by root and read by someone else
			// contains far more. Skipping beats aborting the whole scan -- but
			// the skip is recorded, because what was never looked at must not
			// come out reading the same as what was looked at and found clean.
			// An unnameable path is still recorded, under its host spelling: a
			// gap nobody can locate is still a gap.
			d.note(who, err)
			if de != nil && de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !ok {
			return nil
		}
		return fn(who, de)
	})
}

// note records one skipped entry. A path that is simply not there is not
// recorded: callers walk directories that legitimately do not exist, and
// "absent" is an answer rather than a gap in one.
func (d *DirFS) note(name string, err error) {
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	if d.seen[name] {
		return
	}
	d.seen[name] = true

	d.skipped.Count++
	if len(d.skipped.Paths) < maxUnreadableSample {
		d.skipped.Paths = append(d.skipped.Paths, name)
	}
}

func (d *DirFS) Unreadable() Unreadable {
	d.mu.Lock()
	defer d.mu.Unlock()
	// The sample is copied because it is handed out: a caller appending to it
	// must not write into the accumulator behind it.
	return Unreadable{
		Count: d.skipped.Count,
		Paths: append([]string(nil), d.skipped.Paths...),
	}
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
