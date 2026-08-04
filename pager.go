package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/cwayne18/vexscan/internal/envx"
)

// Paging, and the one place in this tree that looks at a tty.
//
// report.go explains why the report has no colour and no box drawing: a row has
// to survive being grepped, cut, diffed, and pasted into a gist or a CI log. A
// pager does not touch that. It changes no bytes, and it engages only when
// stdout is a character device -- precisely the case where none of those
// consumers exist. Redirect the output, pipe it, or write it with --out, and
// this file does nothing at all.
//
// What it buys is that `vexscan --image debian:12 --all` is 172 lines whose
// first four are the summary. Without a pager those four are gone before the
// command finishes.

// defaultPager is what to run when nothing in the environment says otherwise.
const defaultPager = "less"

// pagerEnvVars are the variables consulted, in order. The VEXSCAN_/GOMODVEX_
// pair follows envx.Prefixes so the rename convention holds; PAGER is the
// system-wide one every other tool honors.
var pagerEnvVars = []string{envx.Prefixes[0] + "PAGER", envx.Prefixes[1] + "PAGER", "PAGER"}

// pagerCommand returns the shell command to page through, or "" for no paging.
//
// The first variable that is *present* wins, even when it is empty, and an
// empty one means do not page. That is deliberately not envx.Get, which treats
// an empty value as unset and falls through to the next name: right for an
// endpoint URL, wrong here. `VEXSCAN_PAGER= vexscan ...` has to mean off rather
// than default, because otherwise there is no way to turn paging off for good
// short of passing --no-pager to every invocation.
func pagerCommand() string {
	for _, name := range pagerEnvVars {
		if v, ok := os.LookupEnv(name); ok {
			return strings.TrimSpace(v)
		}
	}
	return defaultPager
}

// pagerEnv is the environment for the pager process.
//
// A bare `less` with no LESS of its own gets FRX, which is what git does and
// for the same two reasons. F quits immediately when the report already fits on
// one screen, so a six-line result does not trap anyone in a pager. X leaves
// the report on the terminal after quitting, which is the difference between
// having read a report and having watched one disappear.
//
// Only for a bare `less`: someone who wrote out their own flags, or pointed
// this at some other program, has said what they want.
func pagerEnv(command string, environ []string, lessSet bool) []string {
	if command != defaultPager || lessSet {
		return environ
	}
	return append(environ, "LESS=FRX")
}

// page writes s through the pager, and reports whether it managed to.
//
// False means the caller must print s itself. Every failure path returns false
// rather than an error: a missing shell, an unset $PAGER pointing at a program
// that is not installed, a pipe that breaks halfway. None of those are worth
// losing a report over, and a scan that took forty seconds must not end with
// nothing on screen because someone's dotfiles name a pager they uninstalled.
func page(s string) bool {
	command := pagerCommand()
	if command == "" {
		return false
	}

	// sh -c rather than exec of the bare word, so VEXSCAN_PAGER='less -S' and
	// PAGER='bat -p' work the way their author expects.
	cmd := exec.Command("sh", "-c", command)
	_, lessSet := os.LookupEnv("LESS")
	cmd.Env = pagerEnv(command, os.Environ(), lessSet)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}

	// A write error here is almost always the reader quitting early, which is
	// not a failure -- the reader saw what they wanted and pressed q. The
	// report has already been partly written to the terminal either way, so
	// reprinting it would be worse than saying nothing.
	_, writeErr := io.WriteString(stdin, s)
	stdin.Close()
	if err := cmd.Wait(); err != nil && writeErr == nil {
		// The pager took the text and still failed, or -- far more likely --
		// never existed: sh exits 127 for a command it cannot find, and the
		// text vanishes into a pipe nobody read. Falling back can in principle
		// print a report the pager had already displayed, which is a great deal
		// better than the alternative of printing nothing at all.
		fmt.Fprintf(os.Stderr, "warning: pager %q failed: %v\n", command, err)
		return false
	}
	return true
}

// stdoutIsTerminal reports whether stdout is something a human is watching.
//
// Stat rather than a dependency: go-isatty is in go.mod only as an indirect,
// and a character device is the whole test. A pipe, a file, a CI log capture
// and /dev/null are all not one, which is exactly the set that must never be
// paged.
func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
