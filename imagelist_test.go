package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/modgraph"
)

// entryRefs is the references out of a parsed list, for the tests that only
// care that the lines were split correctly.
func entryRefs(entries []imageEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ref)
	}
	return out
}

func TestParseImageList(t *testing.T) {
	got, err := parseImageList(`
# the fleet
alpine:3.20

  debian:12   # trailing comment
alpine:3.20
ghcr.io/org/app@sha256:abc123
   # comment-only line
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpine:3.20", "debian:12", "ghcr.io/org/app@sha256:abc123"}
	if !equalStrings(entryRefs(got), want) {
		t.Errorf("parseImageList = %v, want %v", entryRefs(got), want)
	}
}

// A list written on Windows is still a list.
func TestParseImageListHandlesCRLF(t *testing.T) {
	got, err := parseImageList("alpine:3.20\r\ndebian:12\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(entryRefs(got), []string{"alpine:3.20", "debian:12"}) {
		t.Errorf("parseImageList = %q, want no carriage returns", entryRefs(got))
	}
}

func TestReadImageListFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(path, []byte("alpine:3.20\n# skip\ndebian:12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readImageList(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(entryRefs(got), []string{"alpine:3.20", "debian:12"}) {
		t.Errorf("readImageList = %v", entryRefs(got))
	}
}

func TestReadImageListFromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("alpine:3.20\nbusybox:1.36\n"))
	}))
	defer srv.Close()

	got, err := readImageList(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(entryRefs(got), []string{"alpine:3.20", "busybox:1.36"}) {
		t.Errorf("readImageList = %v", entryRefs(got))
	}
}

// A server that answers with anything other than 200 has not published a list,
// and reading its error page as one would scan whatever the words in it parse
// to.
func TestReadImageListRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := readImageList(context.Background(), srv.URL); err == nil {
		t.Error("want an error for a 404, got nil")
	}
}

func TestDedupeKeepsFirstPosition(t *testing.T) {
	got := dedupe([]string{"b", "a", "b", "c", "a"})
	if !equalStrings(got, []string{"b", "a", "c"}) {
		t.Errorf("dedupe = %v, want [b a c]", got)
	}
}

// Per-image assertions. --roots and --exec-policy are process-global, and the
// claims they carry are not: "this entrypoint execs iptables and that is the
// whole list" is true of one image in a fleet of sixty. Since an unresolvable
// --roots path now blocks, a global root aimed at one image withholds every
// conclusion about the rest, so the per-line form is the only way to make the
// assertion at fleet scale at all.
func TestParseImageListAssertions(t *testing.T) {
	got, err := parseImageList(`
alpine:3.20
kube-vip:v0.6.0 roots=/usr/sbin/xtables-nft-multi exec-policy=assume-none
nginx:1.27 roots=/a,/b roots=/c dlopen-policy=assume-none  # two keys, one repeated
app:v1 dynamic-import-policy=assume-none
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("parseImageList returned %d entries: %v", len(got), entryRefs(got))
	}

	// A bare line is still a bare line: nil, not an empty assertion, so the
	// global flags reach it untouched.
	if got[0].ref != "alpine:3.20" || got[0].assert != nil {
		t.Errorf("a line with no assertions produced %+v", got[0])
	}

	a := got[1].assert
	if a == nil {
		t.Fatal("kube-vip line carried no assertions")
	}
	if !equalStrings(a.Roots, []string{"/usr/sbin/xtables-nft-multi"}) {
		t.Errorf("roots = %v", a.Roots)
	}
	if a.ExecPolicy == nil || *a.ExecPolicy != elfgraph.ExecAssumeNone {
		t.Errorf("exec-policy = %v", a.ExecPolicy)
	}
	// Unmentioned keys stay nil so they inherit rather than reset to a default.
	if a.DlopenPolicy != nil || a.DynamicPolicy != nil {
		t.Errorf("an unmentioned policy was set: %+v", a)
	}

	b := got[2].assert
	if !equalStrings(b.Roots, []string{"/a", "/b", "/c"}) {
		t.Errorf("comma-split and repeated roots = %v", b.Roots)
	}
	if b.DlopenPolicy == nil || *b.DlopenPolicy != elfgraph.DlopenAssumeNone {
		t.Errorf("dlopen-policy = %v", b.DlopenPolicy)
	}
	if c := got[3].assert; c.DynamicPolicy == nil || *c.DynamicPolicy != modgraph.DynamicAssumeNone {
		t.Errorf("dynamic-import-policy = %v", got[3].assert)
	}
}

// A typo in an assertion fails the run rather than being skipped. Skipping
// would fail closed -- the assertion would not apply and the scan would
// conclude less -- but it leaves the user believing they asked for something
// they did not, which is how a pipeline carries a typo for a year.
func TestParseImageListRejectsBadAssertions(t *testing.T) {
	for _, line := range []string{
		"alpine:3.20 exec-polcy=assume-none",      // misspelled key
		"alpine:3.20 exec-policy=assume-non",      // misspelled value
		"alpine:3.20 dlopen-policy=ignore",        // value that is not a policy
		"alpine:3.20 dynamic-import-policy=maybe", // same, other graph
		"alpine:3.20 assume-none",                 // not key=value at all
		"alpine:3.20 roots=",                      // names no path
		"alpine:3.20\nalpine:3.20 roots=/bin/sh",  // one image, two statements
	} {
		if _, err := parseImageList(line); err == nil {
			t.Errorf("parseImageList(%q) was accepted", line)
		}
	}
}

// The overlay itself: a nil assertion changes nothing, and a non-nil one
// touches only the fields it names.
func TestScanAssertApply(t *testing.T) {
	base := analyze.Options{
		Roots:      []string{"/global"},
		ExecPolicy: elfgraph.ExecTaint,
	}

	got := base
	(*scanAssert)(nil).apply(&got)
	if !equalStrings(got.Roots, []string{"/global"}) || got.ExecPolicy != elfgraph.ExecTaint {
		t.Errorf("a nil assertion changed the options: %+v", got)
	}

	// Roots replace rather than append. A line that names its own roots is a
	// complete statement about that image; appending would mean a fleet list
	// could never undo a global root, which is the whole point of the form.
	p := elfgraph.ExecAssumeNone
	got = base
	(&scanAssert{Roots: []string{"/app"}, ExecPolicy: &p}).apply(&got)
	if !equalStrings(got.Roots, []string{"/app"}) {
		t.Errorf("per-image roots = %v, want the global one replaced", got.Roots)
	}
	if got.ExecPolicy != elfgraph.ExecAssumeNone {
		t.Errorf("exec policy = %v", got.ExecPolicy)
	}
	if !equalStrings(base.Roots, []string{"/global"}) {
		t.Errorf("apply mutated the caller's options: %v", base.Roots)
	}
}

// Image four must not inherit image three's roots. scanBatch copies the
// options per target for this reason; a shared struct would carry an assertion
// forward into every image after the one that made it.
func TestDedupeEntriesKeepsAssertions(t *testing.T) {
	p := elfgraph.ExecAssumeNone
	a := &scanAssert{Roots: []string{"/app"}, ExecPolicy: &p}
	got := dedupeEntries([]imageEntry{
		{ref: "alpine:3.20"},            // from --image, bare
		{ref: "alpine:3.20", assert: a}, // from the list, with assertions
		{ref: "debian:12"},
	})
	if len(got) != 2 {
		t.Fatalf("dedupeEntries = %v", entryRefs(got))
	}
	if got[0].assert != a {
		t.Error("the bare duplicate won and the assertion was silently dropped")
	}
	if got[1].ref != "debian:12" {
		t.Errorf("order changed: %v", entryRefs(got))
	}
}
