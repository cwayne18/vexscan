package target

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// tree builds a host directory from a compact description. A "name -> target"
// value makes a symlink, a trailing "/" in the key makes a directory, anything
// else is a regular file with that content.
func tree(t *testing.T, spec map[string]string) string {
	t.Helper()
	root := t.TempDir()

	// Directories first, then files, then links, so link targets can exist.
	keys := make([]string, 0, len(spec))
	for k := range spec {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			if err := os.MkdirAll(filepath.Join(root, k), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, k := range keys {
		v := spec[k]
		if strings.HasSuffix(k, "/") || strings.HasPrefix(v, "-> ") {
			continue
		}
		p := filepath.Join(root, k)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range keys {
		v := spec[k]
		if !strings.HasPrefix(v, "-> ") {
			continue
		}
		p := filepath.Join(root, k)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(strings.TrimPrefix(v, "-> "), p); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// usrMerge is the layout every modern distro ships, which is also the layout
// that makes naive path joining wrong.
func usrMerge(t *testing.T) string {
	t.Helper()
	return tree(t, map[string]string{
		"usr/lib/":              "",
		"usr/lib/libc.so.6":     "ELF-LIBC",
		"usr/lib/libssl.so.3.0": "ELF-SSL",
		"usr/lib/libssl.so.3":   "-> libssl.so.3.0",
		"lib":                   "-> usr/lib",
		"lib64":                 "-> /usr/lib",
		"etc/passwd":            "root:x:0:0",
	})
}

func TestResolve(t *testing.T) {
	root := usrMerge(t)

	tests := []struct {
		name, in, want string
	}{
		{"plain path", "/usr/lib", "usr/lib"},
		{"relative symlink component", "/lib/libc.so.6", "usr/lib/libc.so.6"},
		{"absolute symlink is re-rooted", "/lib64/libc.so.6", "usr/lib/libc.so.6"},
		{"final component symlink is followed", "/usr/lib/libssl.so.3", "usr/lib/libssl.so.3.0"},
		{"dotdot is clamped at root", "/../../etc/passwd", "etc/passwd"},
		{"dotdot within the tree", "/usr/lib/../lib/x", "usr/lib/x"},
		{"dot segments", "/./usr/./lib", "usr/lib"},
		{"missing path still resolves", "/no/such/file", "no/such/file"},
		{"root", "/", ""},
		{"relative input is treated as absolute", "usr/lib", "usr/lib"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(root, tt.in)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tt.in, err)
			}
			want := filepath.Join(root, tt.want)
			if got != want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.in, got, want)
			}
		})
	}
}

// TestResolveCannotEscape is the property the whole package rests on: nothing a
// tree can contain may produce a host path outside the root.
func TestResolveCannotEscape(t *testing.T) {
	outside := t.TempDir()
	root := tree(t, map[string]string{
		"evil":       "-> " + outside,
		"evildir/":   "",
		"evildir/up": "-> ../../../../../../..",
	})

	for _, in := range []string{
		"/evil/passwd",
		"/evildir/up/etc/passwd",
		"/../../../../etc/passwd",
		"/usr/../../../../etc/passwd",
	} {
		got, err := Resolve(root, in)
		if err != nil {
			continue // refusing outright is also containment
		}
		if !strings.HasPrefix(got, root+string(filepath.Separator)) && got != root {
			t.Errorf("Resolve(%q) escaped the root: %q", in, got)
		}
	}
}

func TestResolveDetectsLoop(t *testing.T) {
	root := tree(t, map[string]string{
		"a": "-> b",
		"b": "-> a",
	})
	if _, err := Resolve(root, "/a/file"); err == nil {
		t.Error("expected a symlink loop error")
	}
}

func TestResolveParentLeavesFinalLinkAlone(t *testing.T) {
	root := usrMerge(t)

	got, err := ResolveParent(root, "/lib/libssl.so.3")
	if err != nil {
		t.Fatal(err)
	}
	// The /lib -> usr/lib component is followed, the final link is not.
	if want := filepath.Join(root, "usr/lib/libssl.so.3"); got != want {
		t.Errorf("ResolveParent = %q, want %q", got, want)
	}
}

func TestRel(t *testing.T) {
	tests := []struct{ root, host, want string }{
		{"/tmp/x", "/tmp/x/usr/bin/app", "/usr/bin/app"},
		{"/tmp/x", "/tmp/x", "/"},
		{"/tmp/x", "/elsewhere/app", "/elsewhere/app"},
		// A sibling directory sharing the root's prefix is outside the root;
		// a naive string trim would silently report it as /usr/bin/app.
		{"/tmp/x", "/tmp/xy/usr/bin/app", "/tmp/xy/usr/bin/app"},
	}
	for _, tt := range tests {
		if got := Rel(tt.root, tt.host); got != tt.want {
			t.Errorf("Rel(%q, %q) = %q, want %q", tt.root, tt.host, got, tt.want)
		}
	}
}

func TestDirFSReads(t *testing.T) {
	root := usrMerge(t)
	fsys := NewDirFS(root)

	t.Run("ReadFile follows links", func(t *testing.T) {
		b, err := fsys.ReadFile("/lib/libssl.so.3")
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "ELF-SSL" {
			t.Errorf("got %q", b)
		}
	})

	t.Run("Open follows links", func(t *testing.T) {
		f, err := fsys.Open("/lib64/libc.so.6")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		b, _ := io.ReadAll(f)
		if string(b) != "ELF-LIBC" {
			t.Errorf("got %q", b)
		}
	})

	t.Run("Stat follows, Lstat does not", func(t *testing.T) {
		st, err := fsys.Stat("/usr/lib/libssl.so.3")
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			t.Error("Stat should have followed the link")
		}
		ls, err := fsys.Lstat("/usr/lib/libssl.so.3")
		if err != nil {
			t.Fatal(err)
		}
		if ls.Mode()&os.ModeSymlink == 0 {
			t.Error("Lstat should have reported the link itself")
		}
	})

	t.Run("LinkTarget returns raw text", func(t *testing.T) {
		// Raw, not resolved: soname resolution reads the version out of it.
		got, err := fsys.LinkTarget("/usr/lib/libssl.so.3")
		if err != nil {
			t.Fatal(err)
		}
		if got != "libssl.so.3.0" {
			t.Errorf("LinkTarget = %q, want %q", got, "libssl.so.3.0")
		}
		if _, err := fsys.LinkTarget("/usr/lib/libc.so.6"); err == nil {
			t.Error("LinkTarget on a regular file should fail")
		}
	})

	t.Run("HostPath stays inside the root", func(t *testing.T) {
		p, err := fsys.HostPath("/../../../etc/passwd")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(p, root) {
			t.Errorf("HostPath escaped: %q", p)
		}
	})

	t.Run("ReadDir", func(t *testing.T) {
		entries, err := fsys.ReadDir("/lib")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		want := []string{"libc.so.6", "libssl.so.3", "libssl.so.3.0"}
		if !reflect.DeepEqual(names, want) {
			t.Errorf("ReadDir = %v, want %v", names, want)
		}
	})

	t.Run("errors name the tree path, not the host path", func(t *testing.T) {
		_, err := fsys.ReadFile("/nope")
		var pe *fs.PathError
		if !errors.As(err, &pe) {
			t.Fatalf("want *fs.PathError, got %T", err)
		}
		if pe.Path != "/nope" {
			t.Errorf("PathError.Path = %q, want %q", pe.Path, "/nope")
		}
	})
}

func TestDirFSWalk(t *testing.T) {
	root := usrMerge(t)
	fsys := NewDirFS(root)

	var seen []string
	if err := fsys.Walk("/usr", func(name string, d fs.DirEntry) error {
		seen = append(seen, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	want := []string{"/usr", "/usr/lib", "/usr/lib/libc.so.6", "/usr/lib/libssl.so.3", "/usr/lib/libssl.so.3.0"}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("Walk = %v, want %v", seen, want)
	}
}

// TestDirFSWalkDoesNotFollowLinks pins the property that keeps Walk terminating
// on a tree with a self-referential directory link.
func TestDirFSWalkDoesNotFollowLinks(t *testing.T) {
	root := tree(t, map[string]string{
		"d/":     "",
		"d/file": "x",
		"d/self": "-> ../d",
	})

	var seen []string
	if err := NewDirFS(root).Walk("/", func(name string, d fs.DirEntry) error {
		seen = append(seen, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	want := []string{"/", "/d", "/d/file", "/d/self"}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("Walk = %v, want %v", seen, want)
	}
}

func TestDirFSWalkSkipDir(t *testing.T) {
	root := tree(t, map[string]string{
		"keep/":      "",
		"keep/a":     "a",
		"skip/":      "",
		"skip/b":     "b",
		"skip/deep/": "",
	})

	var seen []string
	err := NewDirFS(root).Walk("/", func(name string, d fs.DirEntry) error {
		seen = append(seen, name)
		if name == "/skip" {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"/", "/keep", "/keep/a", "/skip"}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("Walk = %v, want %v", seen, want)
	}
}

// TestWalkRecordsAnUnlistableDirectory is the property the whole type exists
// for: a subtree the walk could not enter is skipped, and says so.
func TestWalkRecordsAnUnlistableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so there is no gap to record")
	}
	root := tree(t, map[string]string{
		"open/":       "",
		"open/a":      "a",
		"closed/":     "",
		"closed/deep": "secret",
	})
	closed := filepath.Join(root, "closed")
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore the mode so t.TempDir's cleanup can remove the tree.
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })

	fsys := NewDirFS(root)
	var seen []string
	if err := fsys.Walk("/", func(name string, d fs.DirEntry) error {
		seen = append(seen, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The walk still completes and still reports everything it could reach.
	want := []string{"/", "/closed", "/open", "/open/a"}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("Walk = %v, want %v", seen, want)
	}

	u := fsys.Unreadable()
	if u.Count != 1 {
		t.Errorf("Unreadable.Count = %d, want 1", u.Count)
	}
	if !reflect.DeepEqual(u.Paths, []string{"/closed"}) {
		t.Errorf("Paths = %v, want [/closed]", u.Paths)
	}
	// The directory hid an unknown number of unnamed entries, so the scan is
	// no longer an account of the tree and has to say so.
	if !u.Any() {
		t.Error("an unlistable directory must be recorded")
	}
}

// TestAnUnreadableFileIsNotAWalkGap pins the boundary of what this type
// claims. A walk reads directory listings and never opens the files in them,
// so a mode-0000 file costs the walk nothing; the gap surfaces at whichever
// reader actually wanted the file, which can say which file it lost.
func TestAnUnreadableFileIsNotAWalkGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so there is no gap to record")
	}
	root := tree(t, map[string]string{"a": "a", "b": "b"})
	if err := os.Chmod(filepath.Join(root, "b"), 0o000); err != nil {
		t.Fatal(err)
	}

	fsys := NewDirFS(root)
	var seen []string
	if err := fsys.Walk("/", func(name string, d fs.DirEntry) error {
		seen = append(seen, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if want := []string{"/", "/a", "/b"}; !reflect.DeepEqual(seen, want) {
		t.Errorf("Walk = %v, want %v", seen, want)
	}
	if u := fsys.Unreadable(); u.Any() {
		t.Errorf("Unreadable = %+v, want nothing: the walk never opened the file", u)
	}
	// And the reader that does want it still fails, by name.
	if _, err := fsys.ReadFile("/b"); err == nil {
		t.Error("ReadFile on a mode-0000 file should fail")
	}
}

// TestUnreadableIsCumulativeAndDeduplicated pins the contract the orchestrator
// relies on: several plugins walk the same tree, and one bad directory is one
// gap however many of them trip over it.
func TestUnreadableIsCumulativeAndDeduplicated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so there is no gap to record")
	}
	root := tree(t, map[string]string{"x/": "", "y/": ""})
	for _, d := range []string{"x", "y"} {
		p := filepath.Join(root, d)
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
	}

	fsys := NewDirFS(root)
	for i := 0; i < 3; i++ {
		if err := fsys.Walk("/", func(string, fs.DirEntry) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}

	u := fsys.Unreadable()
	if u.Count != 2 {
		t.Errorf("Unreadable.Count = %d after three walks, want 2", u.Count)
	}
}

// TestWalkingSomethingAbsentIsNotAGap keeps "not there" out of the report.
// Callers walk directories that legitimately do not exist -- langdb probes for
// site-packages in images that have no Python -- and recording those as
// unreadable would make every scan look incomplete.
func TestWalkingSomethingAbsentIsNotAGap(t *testing.T) {
	fsys := NewDirFS(tree(t, map[string]string{"a": "a"}))
	if err := fsys.Walk("/no/such/dir", func(string, fs.DirEntry) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if u := fsys.Unreadable(); u.Any() {
		t.Errorf("Unreadable = %+v, want nothing recorded for an absent path", u)
	}
}

func TestUnreadableSampleIsBounded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so there is no gap to record")
	}
	spec := map[string]string{}
	for i := 0; i < maxUnreadableSample+5; i++ {
		spec[fmt.Sprintf("d%02d/", i)] = ""
	}
	root := tree(t, spec)
	for i := 0; i < maxUnreadableSample+5; i++ {
		p := filepath.Join(root, fmt.Sprintf("d%02d", i))
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
	}

	fsys := NewDirFS(root)
	if err := fsys.Walk("/", func(string, fs.DirEntry) error { return nil }); err != nil {
		t.Fatal(err)
	}

	u := fsys.Unreadable()
	// The count is complete even though the sample is not: a reader needs to
	// know how big the hole is, not just see the first few edges of it.
	if u.Count != maxUnreadableSample+5 {
		t.Errorf("Unreadable.Count = %d, want %d", u.Count, maxUnreadableSample+5)
	}
	if len(u.Paths) != maxUnreadableSample {
		t.Errorf("len(Paths) = %d, want %d", len(u.Paths), maxUnreadableSample)
	}
}
