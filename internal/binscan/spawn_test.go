package binscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The sources below are deliberately different shapes of the same question.
// Every one of them is a real build: the claim this file makes is about what
// the Go linker leaves in a binary, and a handwritten fixture would be a claim
// about what the test author believes the linker leaves in a binary.
const (
	// srcServer is the case the whole probe exists for -- a realistic service
	// with a lot of the standard library in it and no way to start a process.
	// If any of these imports dragged in os/exec, the probe would taint every
	// Go web server in the world and be worth nothing.
	srcServer = `package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"text/template"
)

func main() {
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	u, _ := user.Current()
	_ = tar.NewWriter(gzip.NewWriter(os.Stdout))
	_, _ = sql.Open("nope", "dsn")
	_ = x509.NewCertPool()
	_ = tls.Config{}
	_ = mime.TypeByExtension(".json")
	_, _ = net.LookupHost("example.com")
	_ = regexp.MustCompile("x")
	_ = template.Must(template.New("t").Parse("{{.}}"))
	b, _ := json.Marshal(u)
	fmt.Fprintln(os.Stderr, string(b), http.ListenAndServe(":8080", nil))
}
`

	// srcOSExec is the ordinary way, through os/exec.
	srcOSExec = `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	out, err := exec.Command("/usr/bin/su", "-c", "id").CombinedOutput()
	fmt.Println(string(out), err)
}
`

	// srcSyscallExec replaces the process instead of forking, which never
	// reaches syscall.forkExec and would be missed by a probe that only looked
	// for the fork path.
	srcSyscallExec = `package main

import "syscall"

func main() {
	_ = syscall.Exec("/bin/busybox", []string{"busybox", "sh"}, nil)
}
`

	// srcStartProcess skips os/exec and goes to the os layer directly.
	srcStartProcess = `package main

import (
	"fmt"
	"os"
)

func main() {
	p, err := os.StartProcess("/bin/echo", []string{"echo", "hi"}, &os.ProcAttr{})
	fmt.Println(p, err)
}
`
)

func scan(t *testing.T, name, src string, env ...string) *SpawnScan {
	t.Helper()
	dst := filepath.Join(t.TempDir(), name)
	buildGoSource(t, dst, src, append([]string{"CGO_ENABLED=0"}, env...)...)
	s, err := ScanSpawn(dst)
	if err != nil {
		t.Fatalf("ScanSpawn(%s): %v", name, err)
	}
	return s
}

// The negative claim is the one the tool leans on, so it is tested against the
// largest binary here rather than against an empty main.
func TestAPureGoServerProvablyStartsNothing(t *testing.T) {
	s := scan(t, "server", srcServer)
	if !s.CannotSpawn() {
		t.Errorf("a net/http server reported as able to spawn, markers %v", s.Markers())
	}
	if s.CanSpawn() {
		t.Error("CanSpawn and CannotSpawn disagree")
	}
}

// Stripping is the normal way these binaries ship. The function-name table
// survives -ldflags=-s -w, and if it did not, every stripped binary would read
// as provably unable to exec, which is the one wrong answer this must not give.
func TestStrippingDoesNotHideASpawn(t *testing.T) {
	for _, tc := range []struct{ name, flags string }{
		{"stripped", "-ldflags=-s -w"},
		{"plain", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "app")
			src := t.TempDir()
			for n, b := range map[string]string{
				"go.mod":  "module example.com/probe\n\ngo 1.23\n",
				"main.go": srcOSExec,
			} {
				if err := os.WriteFile(filepath.Join(src, n), []byte(b), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"build"}
			if tc.flags != "" {
				args = append(args, tc.flags)
			}
			args = append(args, "-o", dst, ".")
			goBuild(t, src, args, "CGO_ENABLED=0")

			s, err := ScanSpawn(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !s.CanSpawn() {
				t.Error("a binary that calls exec.Command reported as spawning nothing")
			}
			if s.CannotSpawn() {
				t.Error("CannotSpawn is true for a binary that execs")
			}
		})
	}
}

// Three different routes to a second process, none of which share a
// higher-level symbol. syscall.Exec in particular reaches none of the fork
// machinery, so a probe written around os/exec alone would clear it.
func TestEveryRouteToASecondProcessIsFound(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"os/exec", srcOSExec, "syscall.forkExec"},
		{"syscall.Exec", srcSyscallExec, "syscall.Exec"},
		{"os.StartProcess", srcStartProcess, "syscall.forkExec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := scan(t, "app", tc.src)
			if !s.CanSpawn() {
				t.Fatalf("%s reported as spawning nothing", tc.name)
			}
			if !slices.Contains(s.Markers(), tc.want) {
				t.Errorf("markers %v do not include the chokepoint %s", s.Markers(), tc.want)
			}
		})
	}
}

// The negative claim rests on the binary linking no C, because a cgo build can
// reach execve without any Go symbol recording it. A cgo binary with no Go
// marker must therefore be neither -- not proven able, not proven unable.
func TestACgoBuildIsNeverProvenUnableToSpawn(t *testing.T) {
	if testing.Short() {
		t.Skip("cgo build is slow")
	}
	dst := filepath.Join(t.TempDir(), "app")
	src := t.TempDir()
	for n, b := range map[string]string{
		"go.mod":  "module example.com/probe\n\ngo 1.23\n",
		"main.go": "package main\n\n/*\n#include <unistd.h>\n*/\nimport \"C\"\n\nfunc main() { C.getpid() }\n",
	} {
		if err := os.WriteFile(filepath.Join(src, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goBuild(t, src, []string{"build", "-o", dst, "."}, "CGO_ENABLED=1")

	s, err := ScanSpawn(dst)
	if err != nil {
		t.Fatal(err)
	}
	if s.CannotSpawn() {
		t.Error("a cgo binary was reported as provably unable to start a program; C can exec without leaving a Go symbol")
	}
}

// A C program has no Go markers in it either, and reading that as "provably
// starts nothing" would clear every C entrypoint in every image on the strength
// of it not being written in Go.
func TestANonGoFileEstablishesNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notgo")
	if err := os.WriteFile(p, []byte("\x7fELF not really\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanSpawn(p); err == nil {
		t.Fatal("a non-Go file scanned without error; absence of Go symbols would read as proof")
	}
}

func TestMentionsFindsAnExecTargetAndRejectsWhatIsNotThere(t *testing.T) {
	s := scan(t, "app", srcOSExec)
	if !s.Mentions("/usr/bin/su") {
		t.Error("the literal exec target was not found in the binary")
	}
	if s.Mentions("/usr/bin/definitely-not-in-this-binary") {
		t.Error("a path that is not in the binary was reported as mentioned")
	}
	if s.Mentions("") {
		t.Error("the empty string matched")
	}
}

// The markers are matched against the whole file rather than a parsed pclntab,
// which is only sound if a marker in the table is a marker in the file. Nothing
// to assert about that directly, so assert the property that depends on it: the
// markers reported are a subset of the ones looked for, and reported in a
// stable order a report can print.
func TestMarkersAreTheOnesLookedForAndSorted(t *testing.T) {
	s := scan(t, "app", srcOSExec)
	got := s.Markers()
	if !slices.IsSorted(got) {
		t.Errorf("markers %v are not sorted", got)
	}
	for _, m := range got {
		if !slices.Contains(spawnMarkers, m) {
			t.Errorf("reported marker %q is not one of %v", m, spawnMarkers)
		}
	}
	if len(got) == 0 {
		t.Error("no markers for a binary that execs")
	}
}

func goBuild(t *testing.T, dir string, args []string, env ...string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "cgo") || strings.Contains(err.Error(), "executable file not found") {
			t.Skipf("go build unavailable in this environment: %v: %s", err, out)
		}
		t.Fatalf("go build: %v: %s", err, out)
	}
}
