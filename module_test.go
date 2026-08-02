package main

import (
	"os/exec"
	"strings"
	"testing"
	"unicode"
)

// modulePunct is every punctuation character a file inside a module zip may
// use. The full rule is that a path element may hold Unicode letters, ASCII
// digits, the ASCII space, and these -- nothing else.
const modulePunct = "!#$%&()+,-.=@[]^_{}~"

// TestTrackedFilesCanGoInAModuleZip fails on a committed file that "go install"
// cannot package.
//
// This is not a style rule. A module zip is built from the repository as it
// stands, and one illegal character anywhere in the tree makes
//
//	go install github.com/cwayne18/vexscan@latest
//
// fail for every user on every platform, with an error naming a file none of
// them asked for. The tag that carries the bad file is immutable once
// published, so the only remedy is a new release -- which is why this is
// checked here rather than found by the first person to try installing.
//
// The character set is Windows-driven: a colon, an asterisk or a quote cannot
// be a filename there, so the module format forbids them everywhere rather
// than producing archives that unpack on some machines and not others. That is
// how it caught internal/pkgdb/testdata/debian12, whose fixture is a real dpkg
// database and whose multiarch file lists are genuinely named "libc6:amd64.list".
// See debianFS for how that fixture keeps the real names at test time.
func TestTrackedFilesCanGoInAModuleZip(t *testing.T) {
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files: %v", err)
	}
	for _, path := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if path == "" {
			continue
		}
		for _, elem := range strings.Split(path, "/") {
			if bad, ok := badChar(elem); ok {
				t.Errorf("%s: %q cannot appear in a file inside a module zip; "+
					"store the file under an escaped name and restore it in the test that reads it",
					path, bad)
				break
			}
		}
	}
}

// badChar returns the first character of a path element that a module zip does
// not allow.
func badChar(elem string) (rune, bool) {
	for _, r := range elem {
		switch {
		case unicode.IsLetter(r), '0' <= r && r <= '9', r == ' ':
		case strings.ContainsRune(modulePunct, r):
		default:
			return r, true
		}
	}
	return 0, false
}
