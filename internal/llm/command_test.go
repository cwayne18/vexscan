package llm

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeCLI writes an executable shell script and returns its path, so the
// command transport can be exercised against a real process rather than a
// stand-in for one. The thing worth testing here is the exec plumbing --
// stdin, stdout, stderr, exit status -- and none of it is exercised by a fake.
func fakeCLI(t *testing.T, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the command transport tests need a POSIX shell")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSplitCommand(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "claude", want: []string{"claude"}},
		{in: "claude -p", want: []string{"claude", "-p"}},
		{in: "  claude   -p  ", want: []string{"claude", "-p"}},
		{in: `claude -p --model "claude sonnet"`, want: []string{"claude", "-p", "--model", "claude sonnet"}},
		{in: `llm -m 'gpt-4o mini'`, want: []string{"llm", "-m", "gpt-4o mini"}},
		{in: `sh -c ""`, want: []string{"sh", "-c", ""}},
		// No expansion of any kind: a dollar sign is a character, because the
		// alternative is a command line that means different things depending
		// on the environment it was read in.
		{in: `echo $HOME`, want: []string{"echo", "$HOME"}},
		{in: `claude "-p`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := splitCommand(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("splitCommand(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestCommandTransportSendsThePromptOnStdin(t *testing.T) {
	captured := filepath.Join(t.TempDir(), "prompt.txt")
	cli := fakeCLI(t, "fake-llm", `cat > `+captured+`
echo '{"exploitable":"unlikely","confidence":"medium","rationale":"not reachable"}'`)

	c := NewClientWithTransport(mustCommand(t, cli))
	v, err := c.Assess(context.Background(), Request{Ecosystem: "os", CVE: "CVE-1", Module: "openssl", Version: "3.0", Binary: "debian:12", Reachable: "loaded"})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if v.Exploitable != "unlikely" {
		t.Errorf("Exploitable = %q, want unlikely", v.Exploitable)
	}

	got, err := os.ReadFile(captured)
	if err != nil {
		t.Fatalf("the command received no stdin: %v", err)
	}
	// Both halves have to arrive. A CLI has no system-message channel, so if
	// the roles did not collapse into one document the model would be asked
	// the question without being told how to answer it.
	for _, want := range []string{"security analyst", "CVE: CVE-1", "Package: openssl 3.0"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the prompt is missing %q:\n%s", want, got)
		}
	}
}

// A CLI that fails says why on stderr, and that text is the only diagnosis the
// user gets -- "exit status 1" alone would send them to strace.
func TestCommandTransportReportsStderr(t *testing.T) {
	cli := fakeCLI(t, "angry-llm", `echo "not authenticated: run 'foo login'" >&2
exit 1`)

	_, err := NewClientWithTransport(mustCommand(t, cli)).Assess(context.Background(), Request{CVE: "CVE-1"})
	if err == nil {
		t.Fatal("a failing command reported success")
	}
	if !strings.Contains(err.Error(), "not authenticated") {
		t.Errorf("the error hides what the command said: %v", err)
	}
}

// A command that prints nothing has not answered. Letting the empty string
// through would reach parseVerdict, which turns unparseable text into a verdict
// of "unknown" -- a real answer a model can give, and the wrong thing to record
// for a model that never ran.
func TestCommandTransportRejectsSilence(t *testing.T) {
	cli := fakeCLI(t, "quiet-llm", `exit 0`)

	_, err := NewClientWithTransport(mustCommand(t, cli)).Assess(context.Background(), Request{CVE: "CVE-1"})
	if err == nil {
		t.Fatal("a command that printed nothing was accepted as a verdict")
	}
	if !strings.Contains(err.Error(), "printed nothing") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestCommandTransportReportsAMissingBinary(t *testing.T) {
	_, err := NewClientWithTransport(mustCommand(t, "vexscan-no-such-llm-cli")).
		Assess(context.Background(), Request{CVE: "CVE-1"})
	if err == nil {
		t.Fatal("a command that does not exist reported success")
	}
	if !strings.Contains(err.Error(), "vexscan-no-such-llm-cli") {
		t.Errorf("the error does not name the command: %v", err)
	}
}

// A failing command is not retried: the failures a CLI has are mostly the
// permanent kind, and the transient ones were already retried inside it. Six
// attempts at a not-logged-in CLI is six times the wait for the same answer.
func TestCommandTransportDoesNotRetry(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "runs")
	cli := fakeCLI(t, "counting-llm", `echo x >> `+counter+`
exit 1`)

	_, _ = NewClientWithTransport(mustCommand(t, cli)).Assess(context.Background(), Request{CVE: "CVE-1"})

	runs, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(string(runs))); n != 1 {
		t.Errorf("the command ran %d times, want 1", n)
	}
}

func mustCommand(t *testing.T, command string) *CommandTransport {
	t.Helper()
	tr, err := NewCommandTransport(command)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}
