package ospkg

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/target"
)

// goImage builds main.go into a tree at /app/server and returns a RootFS over
// it, plus the extra program paths the tree holds.
//
// Real builds, because the probe's whole claim is about what the Go linker
// leaves in a binary. A fixture would only assert what the test author believes
// about the linker, which is the belief under test.
func goImage(t *testing.T, mainGo string, alsoPrograms ...string) target.RootFS {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	root := t.TempDir()
	src := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module example.com/server\n\ngo 1.23\n",
		"main.go": mainGo,
	} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dst := filepath.Join(root, "app", "server")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", dst, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build unavailable in this environment: %v: %s", err, out)
	}

	for _, p := range alsoPrograms {
		f := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("\x7fELF stand-in\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return target.NewDirFS(root)
}

const (
	srcPlainServer = `package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

func main() {
	s := &http.Server{Addr: ":8080", TLSConfig: &tls.Config{}}
	fmt.Fprintln(os.Stderr, s.ListenAndServe())
}
`
	srcServerThatExecsSu = `package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	out, _ := exec.Command("/usr/bin/su", "-c", "id").CombinedOutput()
	s := &http.Server{Addr: ":8080", TLSConfig: &tls.Config{}}
	fmt.Fprintln(os.Stderr, string(out), s.ListenAndServe())
}
`
)

// The answer the tool leans on for a distroless-style image: the entrypoint was
// checked, and it starts nothing.
func TestGoExecProbeClearsAServerThatStartsNothing(t *testing.T) {
	fsys := goImage(t, srcPlainServer, "/usr/bin/su")
	pr, ok := goExecProbe(fsys, "/app/server", []string{"/usr/bin/su"})
	if !ok {
		t.Fatal("the probe declined to answer for a pure-Go binary")
	}
	if pr.CanSpawn {
		t.Errorf("a net/http server reported as able to exec: %s", pr.Why)
	}
	if pr.Why == "" {
		t.Error("no reason given, so the discharge would be unauditable and is discarded")
	}
	if len(pr.Targets) != 0 {
		t.Errorf("targets %v offered for a binary that cannot exec", pr.Targets)
	}
}

// The case the probe exists to catch, end to end through the real scanner: one
// exec.Command, and the target is recovered from the binary's own string
// literals.
func TestGoExecProbeFindsTheSpawnAndTheTarget(t *testing.T) {
	fsys := goImage(t, srcServerThatExecsSu, "/usr/bin/su", "/usr/bin/unrelated")
	pr, ok := goExecProbe(fsys, "/app/server", []string{"/usr/bin/su", "/usr/bin/unrelated"})
	if !ok {
		t.Fatal("the probe declined to answer")
	}
	if !pr.CanSpawn {
		t.Fatal("a binary calling exec.Command was cleared")
	}
	if !strings.Contains(pr.Why, "syscall.forkExec") {
		t.Errorf("the reason does not name a chokepoint: %q", pr.Why)
	}
	if len(pr.Targets) != 1 || pr.Targets[0] != "/usr/bin/su" {
		t.Errorf("targets = %v, want just /usr/bin/su: a program the binary never names must not be rooted", pr.Targets)
	}
}

func TestGoExecProbeDeclinesForANonGoEntrypoint(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app", "server"), []byte("\x7fELF not really\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := goExecProbe(target.NewDirFS(root), "/app/server", nil); ok {
		t.Error("the probe answered for a non-Go binary; absence of Go symbols is not absence of exec")
	}
}

func TestGoExecProbeDeclinesForAMissingFile(t *testing.T) {
	if _, ok := goExecProbe(target.NewDirFS(t.TempDir()), "/app/nope", nil); ok {
		t.Error("the probe answered for a file that is not there")
	}
}

func TestMarkerList(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"syscall.Exec"}, "syscall.Exec"},
		{[]string{"os/exec."}, "os/exec"},
		{[]string{"os/exec.", "syscall.forkExec"}, "os/exec and syscall.forkExec"},
		{
			[]string{"os.startProcess", "os/exec.", "syscall.StartProcess", "syscall.forkExec"},
			"os.startProcess, os/exec, syscall.StartProcess and syscall.forkExec",
		},
	} {
		if got := markerList(tc.in); got != tc.want {
			t.Errorf("markerList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A Go binary big enough to name half an image's binaries would produce a list
// nobody reads, and the taint blocks on the strength of the spawn rather than
// on the strength of the list.
func TestMentionedProgramsIsCapped(t *testing.T) {
	fsys := goImage(t, srcServerThatExecsSu)
	host, err := fsys.HostPath("/app/server")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := binscan.ScanSpawn(host)
	if err != nil {
		t.Fatal(err)
	}
	// "/" is in every Go binary many times over, so every one of these
	// "programs" is mentioned and the cap is the only thing bounding the list.
	var programs []string
	for i := 0; i < 100; i++ {
		programs = append(programs, "/")
	}
	if got := len(mentionedPrograms(scan, programs)); got != 32 {
		t.Errorf("mentionedPrograms returned %d entries, want the cap of 32", got)
	}
}
