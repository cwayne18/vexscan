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

// TestCGODisabled compiles the two builds that matter to the static-entrypoint
// discharge: a pure-Go one that carries no C library, and a cgo one that might.
// A handwritten fixture will not do -- buildinfo reads settings the toolchain
// stamps, so only a real binary carries a CGO_ENABLED record at all.
func TestCGODisabled(t *testing.T) {
	off := filepath.Join(t.TempDir(), "off")
	buildGoBinaryEnv(t, off, "CGO_ENABLED=0")
	if disabled, ok := CGODisabled(off); !ok || !disabled {
		t.Errorf("CGO_ENABLED=0 build: got (disabled=%v, ok=%v), want (true, true)", disabled, ok)
	}

	on := filepath.Join(t.TempDir(), "on")
	buildGoBinaryEnv(t, on, "CGO_ENABLED=1")
	if disabled, ok := CGODisabled(on); !ok || disabled {
		t.Errorf("CGO_ENABLED=1 build: got (disabled=%v, ok=%v), want (false, true)", disabled, ok)
	}

	// A file that is not a Go binary tells the prober nothing, so it must stay
	// conservative rather than read absence of a setting as CGO being off.
	notGo := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(notGo, []byte("root:x:0:0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if disabled, ok := CGODisabled(notGo); ok || disabled {
		t.Errorf("non-Go file: got (disabled=%v, ok=%v), want (false, false)", disabled, ok)
	}
}

// buildGoBinary compiles a trivial program to dst. Discovery cannot be tested
// with a handwritten fixture: buildinfo rejects anything the toolchain did not
// produce, so a real binary is the only thing FindGoBinaries will report.
func buildGoBinary(t *testing.T, dst string) {
	t.Helper()
	buildGoBinaryEnv(t, dst)
}

// buildGoBinaryEnv is buildGoBinary with extra environment for the toolchain,
// so a test can pin CGO_ENABLED and read back what the build recorded.
func buildGoBinaryEnv(t *testing.T, dst string, env ...string) {
	t.Helper()
	buildGoSource(t, dst, "package main\n\nfunc main() {}\n", env...)
}

// buildGoSource compiles a given main.go to dst, so a test can choose what the
// program does rather than only how it was built.
func buildGoSource(t *testing.T, dst, mainGo string, env ...string) {
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
	write("main.go", mainGo)

	cmd := exec.Command("go", "build", "-o", dst, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable in this environment: %v: %s", err, out)
	}
}

// TestStaticSymbols reads the static symbol table out of a real ELF binary,
// which is the reader the cgo static-entrypoint discharge is built on. The
// fixtures are cross-compiled to Linux, because a native build on a non-Linux
// host is not ELF at all and debug/elf could not open it -- which is itself the
// conservative "unreadable reads as stripped" path, not the symbol read under
// test.
//
// The stripped build is the load-bearing case. -ldflags=-s -w throws the
// symbol table away, and StaticSymbols must report that, because the whole
// discipline turns on it: a vulnerable symbol absent from a table that still
// exists is absent from the binary, but absent from a table that was discarded
// is unknown, and unknown has to stay blocking.
func TestStaticSymbols(t *testing.T) {
	unstripped := filepath.Join(t.TempDir(), "app")
	buildELF(t, unstripped)

	def, stripped, err := StaticSymbols(unstripped)
	if err != nil {
		t.Fatalf("StaticSymbols: %v", err)
	}
	if stripped {
		t.Fatal("an unstripped build reported stripped")
	}
	// main.main is the program's own entry function; a build that kept its
	// symbol table kept that name, and it is the least fragile thing to assert.
	if !contains(def, "main.main") {
		t.Errorf("defined symbols %d do not include main.main", len(def))
	}

	stripped2 := filepath.Join(t.TempDir(), "app-stripped")
	buildELF(t, stripped2, "-ldflags=-s -w")

	def, stripped, err = StaticSymbols(stripped2)
	if err != nil {
		t.Fatalf("StaticSymbols (stripped): %v", err)
	}
	if !stripped {
		t.Errorf("a -s -w build was not reported stripped (%d symbols read)", len(def))
	}
	if len(def) != 0 {
		t.Errorf("a stripped build reported %d defined symbols, want none", len(def))
	}

	// A file that is not an ELF object cannot have anything proven absent from
	// it, so it reads as stripped rather than erroring -- the caller's blocking
	// default is the whole point.
	notELF := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(notELF, []byte("root:x:0:0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stripped, err := StaticSymbols(notELF); err != nil || !stripped {
		t.Errorf("non-ELF file: got (stripped=%v, err=%v), want (true, nil)", stripped, err)
	}
}

// buildELF cross-compiles a trivial program to dst as a Linux ELF, so the
// static symbol reader has a real symbol table to read on any host.
func buildELF(t *testing.T, dst string, flags ...string) {
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

	args := append([]string{"build", "-o", dst}, flags...)
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable in this environment: %v: %s", err, out)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
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
