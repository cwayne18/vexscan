package binscan

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

func TestPackagePresent(t *testing.T) {
	blob := []byte("prefixgolang.org/x/net/http2.(*Framer).ReadFrame\x00other golang.org/x/net/idna.ToASCII junk")
	s := &Symbols{blob: blob}

	if !s.PackagePresent("golang.org/x/net/http2") {
		t.Errorf("expected http2 package to be present")
	}
	if !s.PackagePresent("golang.org/x/net/idna") {
		t.Errorf("expected idna package to be present")
	}
	// A sibling that is not linked must not leak from a parent match.
	if s.PackagePresent("golang.org/x/net/websocket") {
		t.Errorf("websocket should not be present")
	}
	// Parent path without a trailing symbol must not match a child's symbol.
	if s.PackagePresent("golang.org/x/net/http2/hpack") {
		t.Errorf("hpack subpackage should not be present")
	}
}

func TestModulePresent(t *testing.T) {
	blob := []byte("... google.golang.org/grpc/internal/transport.newHTTP2Server ...")
	s := &Symbols{blob: blob}

	if !s.ModulePresent("google.golang.org/grpc") {
		t.Errorf("expected grpc module to be present")
	}
	// The [./] guard must keep a prefix from matching an unrelated module.
	if s.ModulePresent("google.golang.org/grpcfoo") {
		t.Errorf("grpcfoo must not match")
	}
	if s.ModulePresent("golang.org/x/net") {
		t.Errorf("x/net must not be present")
	}
}

func TestNormalizeGoVersion(t *testing.T) {
	cases := map[string]string{
		"go1.24.0":                "1.24.0",
		"go1.21.5":                "1.21.5",
		"go1.24.0 X:boringcrypto": "1.24.0",
		"devel go1.26-abc":        "",
		"":                        "",
	}
	for in, want := range cases {
		if got := NormalizeGoVersion(in); got != want {
			t.Errorf("NormalizeGoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModuleVersionStdlib(t *testing.T) {
	b := Binary{Info: &buildinfo.BuildInfo{GoVersion: "go1.24.0"}}
	if got := b.ModuleVersion("stdlib"); got != "1.24.0" {
		t.Errorf("stdlib version = %q, want 1.24.0", got)
	}
	if got := b.ModuleVersion("std"); got != "1.24.0" {
		t.Errorf("std alias version = %q, want 1.24.0", got)
	}
	if got := b.ModuleVersion("golang.org/x/net"); got != "" {
		t.Errorf("non-dep module = %q, want empty", got)
	}
}

// buildGoBinary compiles a trivial program to dst. Discovery cannot be tested
// with a handwritten fixture: buildinfo rejects anything the toolchain did not
// produce, so a real binary is the only thing FindGoBinaries will report.
func buildGoBinary(t *testing.T, dst string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	src := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/probe\n\ngo 1.23\n")
	write("main.go", "package main\n\nfunc main() {}\n")

	cmd := exec.Command("go", "build", "-o", dst, ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable in this environment: %v: %s", err, out)
	}
}

func TestFindGoBinaries(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"usr/bin", "etc", "proc/self"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	buildGoBinary(t, filepath.Join(root, "usr/bin/app"))
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys := target.NewDirFS(root)
	bins := findPaths(t, fsys, root)
	if want := []string{"/usr/bin/app"}; !reflect.DeepEqual(bins, want) {
		t.Fatalf("FindGoBinaries = %v, want %v", bins, want)
	}
	if u := fsys.Unreadable(); u.Any() {
		t.Errorf("Unreadable = %+v, want nothing on a fully readable tree", u)
	}
}

// TestFindGoBinariesSkipsKernelFilesystems matters only outside image mode: an
// extracted image has no /proc, but a tree captured from a running system does,
// and its synthetic entries stat as regular files.
func TestFindGoBinariesSkipsKernelFilesystems(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"usr/bin", "proc/1", "sys/kernel", "dev/shm"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The same real binary in four places. Only the one outside a kernel
	// filesystem may be reported.
	buildGoBinary(t, filepath.Join(root, "usr/bin/app"))
	blob, err := os.ReadFile(filepath.Join(root, "usr/bin/app"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"proc/1/exe", "sys/kernel/app", "dev/shm/app"} {
		if err := os.WriteFile(filepath.Join(root, p), blob, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got := findPaths(t, target.NewDirFS(root), root)
	if want := []string{"/usr/bin/app"}; !reflect.DeepEqual(got, want) {
		t.Errorf("FindGoBinaries = %v, want %v", got, want)
	}
}

// TestFindGoBinariesRecordsWhatItCouldNotEnter is the reason this walk goes
// through RootFS at all. A Go binary nobody looked at is a module the report
// never mentions, which reads exactly like a module with no advisories.
func TestFindGoBinariesRecordsWhatItCouldNotEnter(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so there is no gap to record")
	}
	root := t.TempDir()
	for _, d := range []string{"usr/bin", "opt/vendor"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	buildGoBinary(t, filepath.Join(root, "usr/bin/app"))
	buildGoBinary(t, filepath.Join(root, "opt/vendor/hidden"))

	closed := filepath.Join(root, "opt/vendor")
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })

	fsys := target.NewDirFS(root)
	got := findPaths(t, fsys, root)
	// The readable half is still reported: one bad directory does not cost the
	// whole scan.
	if want := []string{"/usr/bin/app"}; !reflect.DeepEqual(got, want) {
		t.Errorf("FindGoBinaries = %v, want %v", got, want)
	}
	u := fsys.Unreadable()
	if !u.Any() {
		t.Fatal("an unenterable directory holding a Go binary must be recorded")
	}
	if !reflect.DeepEqual(u.Paths, []string{"/opt/vendor"}) {
		t.Errorf("Unreadable.Paths = %v, want [/opt/vendor]", u.Paths)
	}
}

// findPaths runs the scan and returns tree-absolute paths, so a test does not
// have to care where the temp directory landed.
func findPaths(t *testing.T, fsys target.RootFS, root string) []string {
	t.Helper()
	var out []string
	for _, b := range FindGoBinaries(fsys) {
		out = append(out, target.Rel(root, b.Path))
	}
	sort.Strings(out)
	return out
}
