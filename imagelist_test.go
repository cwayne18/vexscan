package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	got, err := parseImageList("fleet.txt", `
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
	got, err := parseImageList("fleet.txt", "alpine:3.20\r\ndebian:12\r\n")
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
	got, err := parseImageList("fleet.txt", `
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
		if _, err := parseImageList("fleet.txt", line); err == nil {
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

// A fleet list whose images repeat the same three shapes should say each shape
// once. The profile supplies the defaults; the line overrides what is different
// about its own image; the name rides along so a conclusion can say which
// profile it rests on.
func TestParseImageListProfiles(t *testing.T) {
	got, err := parseImageList("fleet.txt", `
[profile go-daemon] exec-policy=assume-none
[profile calico]    roots=/usr/bin/calico-node exec-policy=assume-none   # the one with a CNI plugin dir

docker.io/rancher/hardened-calico:v3.32.0 profile=calico
docker.io/rancher/hardened-coredns:v1.11.1 profile=go-daemon roots=/coredns
docker.io/rancher/hardened-etcd:v3.5.13 profile=go-daemon
alpine:3.20
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"docker.io/rancher/hardened-calico:v3.32.0",
		"docker.io/rancher/hardened-coredns:v1.11.1",
		"docker.io/rancher/hardened-etcd:v3.5.13",
		"alpine:3.20",
	}
	if !equalStrings(entryRefs(got), want) {
		t.Fatalf("refs = %v, want %v", entryRefs(got), want)
	}

	calico := got[0].assert
	if calico == nil || !equalStrings(calico.Roots, []string{"/usr/bin/calico-node"}) {
		t.Errorf("calico roots = %+v, want the profile's", calico)
	}
	if calico.Profile != "calico" {
		t.Errorf("calico profile name = %q, want calico", calico.Profile)
	}

	// The line's own roots replace the profile's rather than adding to them: a
	// line that names what it runs is a complete statement about that image.
	coredns := got[1].assert
	if coredns == nil || !equalStrings(coredns.Roots, []string{"/coredns"}) {
		t.Errorf("coredns roots = %+v, want only its own", coredns)
	}
	if coredns.ExecPolicy == nil || *coredns.ExecPolicy != elfgraph.ExecAssumeNone {
		t.Errorf("coredns lost the profile's exec-policy: %+v", coredns)
	}
	if coredns.Profile != "go-daemon" {
		t.Errorf("coredns profile name = %q, want go-daemon", coredns.Profile)
	}

	// A profile that asserts only a policy contributes only that policy. It must
	// not acquire roots from the line above it that happened to name some.
	etcd := got[2].assert
	if etcd == nil || etcd.Roots != nil {
		t.Errorf("etcd roots = %+v, want none from a roots-less profile", etcd)
	}
	if got[3].assert != nil {
		t.Errorf("a bare line picked up an assertion: %+v", got[3].assert)
	}
}

// Every way of being wrong about a profile is an error before anything is
// pulled, for the reason an unknown key already is: failing closed still leaves
// the user believing they asked for something they did not.
func TestParseImageListProfileErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		list string
	}{
		{"used but never defined", "alpine:3.20 profile=nope\n"},
		{"defined twice", "[profile a] exec-policy=assume-none\n[profile a] roots=/x\nalpine:3.20 profile=a\n"},
		{"asserts nothing", "[profile a]\nalpine:3.20 profile=a\n"},
		{"no closing bracket", "[profile a exec-policy=assume-none\n"},
		{"names no profile", "[profile ] exec-policy=assume-none\n"},
		{"unknown key inside", "[profile a] roots=/x bogus=1\nalpine:3.20 profile=a\n"},
		{"bad value inside", "[profile a] exec-policy=maybe\nalpine:3.20 profile=a\n"},
		{"empty profile name on a line", "alpine:3.20 profile=\n"},
		{"a profile naming another profile", "[profile base] exec-policy=assume-none\n" +
			"[profile calico] profile=base roots=/usr/bin/calico-node\n" +
			"alpine:3.20 profile=calico\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseImageList("fleet.txt", tc.list); err == nil {
				t.Error("parseImageList accepted it")
			}
		})
	}
}

// The two ways of misusing profile= are rejected for their own reasons, and the
// reason has to be the one the author can act on.
//
// Nesting is the one that matters. Profiles are collected in one pass and
// expanded in another, so a profile naming another is read, accepted, and
// dropped -- and dropped towards asserting less, which surfaces as a scan that
// quietly withheld conclusions rather than as an error. Checking the message,
// not just that some error came back, is what keeps the empty-name case from
// passing on the "unknown profile" path it used to take.
func TestParseImageListProfileMisuseSaysWhich(t *testing.T) {
	for _, tc := range []struct {
		name, list, want string
	}{
		{
			"nested", "[profile base] exec-policy=assume-none\n[profile b] profile=base roots=/x\n",
			"cannot name another profile",
		},
		{
			"empty name", "[profile a] roots=/x\nalpine:3.20 profile=\n",
			"profile= names no profile",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseImageList("fleet.txt", tc.list)
			if err == nil {
				t.Fatal("parseImageList accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A profile defined after the images that use it is the natural layout for a
// list that grew one odd image at a time, and there is no reason to reject it.
func TestParseImageListProfileDefinedLater(t *testing.T) {
	got, err := parseImageList("fleet.txt", "alpine:3.20 profile=late\n[profile late] roots=/bin/busybox\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].assert == nil || !equalStrings(got[0].assert.Roots, []string{"/bin/busybox"}) {
		t.Errorf("parseImageList = %+v", got)
	}
}

// dlopen-assume-none= is the fleet form of the narrow dlopen assertion. It is a
// list, so it follows the roots= rule rather than the policy one: the first
// occurrence on a line clears whatever the profile supplied, and later ones
// append. A line that knows which loaders its image has is making a complete
// statement about them, and a fleet list that could only ever add to a
// profile's list could never correct one.
func TestParseImageListNamedDlopenCallers(t *testing.T) {
	got, err := parseImageList("fleet.txt", `
[profile hardened] dlopen-assume-none=/usr/bin/bash exec-policy=assume-none
calico:v3.32 profile=hardened dlopen-assume-none=libnss_systemd.so.2,libselinux.so.1 dlopen-assume-none=/usr/bin/bash
coredns:v1.11 profile=hardened
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parseImageList returned %d entries: %v", len(got), entryRefs(got))
	}

	want := []string{"libnss_systemd.so.2", "libselinux.so.1", "/usr/bin/bash"}
	if a := got[0].assert; !equalStrings(a.DlopenAssumeNoneFor, want) {
		t.Errorf("dlopen-assume-none = %v, want the profile's list replaced then appended to: %v",
			a.DlopenAssumeNoneFor, want)
	}
	// The line that said nothing keeps the profile's list, so the clear above
	// is the line's own doing rather than the profile having been emptied.
	if a := got[1].assert; !equalStrings(a.DlopenAssumeNoneFor, []string{"/usr/bin/bash"}) {
		t.Errorf("a line that named no callers = %v, want the profile's list", a.DlopenAssumeNoneFor)
	}

	// And it reaches the options, replacing rather than extending a global
	// --dlopen-assume-none, for the same reason roots does.
	opts := analyze.Options{DlopenAssumeNoneFor: []string{"/global"}}
	got[0].assert.apply(&opts)
	if !equalStrings(opts.DlopenAssumeNoneFor, want) {
		t.Errorf("after apply = %v, want %v", opts.DlopenAssumeNoneFor, want)
	}
}

// A key with no value is a half-written assertion, and the flag it stands for
// refuses one too. Accepting it would leave the user believing they waved off a
// caller they never named.
func TestParseImageListRejectsEmptyDlopenCaller(t *testing.T) {
	for _, line := range []string{
		"alpine:3.20 dlopen-assume-none=",
		"alpine:3.20 dlopen-assume-none=,",
		"[profile a] dlopen-assume-none=\nalpine:3.20 profile=a\n",
	} {
		if _, err := parseImageList("fleet.txt", line); err == nil {
			t.Errorf("parseImageList(%q) was accepted", line)
		}
	}
}

// A profile that names only callers is a real profile. Before this key existed
// the emptiness check listed every field; missing one here would reject a
// profile that asserts something, which is the opposite of what that check is
// for.
func TestParseImageListProfileOfOnlyDlopenCallers(t *testing.T) {
	got, err := parseImageList("fleet.txt", "[profile p] dlopen-assume-none=/usr/bin/bash\nalpine:3.20 profile=p\n")
	if err != nil {
		t.Fatal(err)
	}
	if a := got[0].assert; a == nil || !equalStrings(a.DlopenAssumeNoneFor, []string{"/usr/bin/bash"}) {
		t.Errorf("profile of only named callers produced %+v", got[0].assert)
	}
}

// entrypoint= and cmd=, the hand-written form of what a Kubernetes manifest
// carries. Kubernetes is not the only thing that replaces an entrypoint --
// docker run --entrypoint, a compose service, a Nomad task and a systemd unit
// all do, and none of them ship a manifest this program can read.

// TestEntrypointKeyReplacesRatherThanRoots is the guard that makes the key
// worth having at all. Written to Roots it would add a starting point and leave
// the shell the image declares rooted beside it, which is the situation the
// override exists to escape, and a report produced that way looks exactly like
// one produced correctly.
func TestEntrypointKeyReplacesRatherThanRoots(t *testing.T) {
	got, err := parseImageList("fleet.txt", "hardened-calico:v3.32.0 entrypoint=/usr/bin/calico-node cmd=-felix\n")
	if err != nil {
		t.Fatal(err)
	}
	a := got[0].assert
	if a == nil {
		t.Fatal("the line carried no assertion")
	}
	if !equalStrings(a.Entrypoint, []string{"/usr/bin/calico-node"}) {
		t.Errorf("Entrypoint = %v", a.Entrypoint)
	}
	if !equalStrings(a.Cmd, []string{"-felix"}) {
		t.Errorf("Cmd = %v", a.Cmd)
	}
	if len(a.Roots) != 0 {
		t.Errorf("the entrypoint was written to Roots, which adds to the config entrypoint rather than replacing it: %v", a.Roots)
	}

	// And it has to survive apply, which is where the override either reaches
	// the scan or is dropped on the floor.
	var opts analyze.Options
	a.apply(&opts)
	if !equalStrings(opts.Entrypoint, []string{"/usr/bin/calico-node"}) || !equalStrings(opts.Cmd, []string{"-felix"}) {
		t.Errorf("the override did not reach the scan: %v %v", opts.Entrypoint, opts.Cmd)
	}
}

// TestEntrypointKeyRecordsTheListAsItsSource. apply drops an override with no
// source, so a missing source is a silently narrower scan; and the source is
// the only part of the clause a reviewer can go and check.
func TestEntrypointKeyRecordsTheListAsItsSource(t *testing.T) {
	got, err := parseImageList("fleet.txt", "alpine:3.20 entrypoint=/bin/app\n")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].assert.EntrypointFrom != "fleet.txt" {
		t.Errorf("EntrypointFrom = %q, want the list that made the claim", got[0].assert.EntrypointFrom)
	}
}

// TestCmdKeyAloneLeavesTheEntrypointAlone. Replacing the arguments is not
// replacing the program: an image whose config entrypoint is a wrapper still
// runs that wrapper. Setting Entrypoint here would unroot it and conclude about
// a process that never starts.
func TestCmdKeyAloneLeavesTheEntrypointAlone(t *testing.T) {
	got, err := parseImageList("fleet.txt", "alpine:3.20 cmd=--serve\n")
	if err != nil {
		t.Fatal(err)
	}
	a := got[0].assert
	if a.Entrypoint != nil {
		t.Errorf("cmd= alone invented an entrypoint override: %v", a.Entrypoint)
	}
	if !equalStrings(a.Cmd, []string{"--serve"}) {
		t.Errorf("Cmd = %v", a.Cmd)
	}
	if a.EntrypointFrom != "fleet.txt" {
		t.Errorf("EntrypointFrom = %q; without it apply drops the override", a.EntrypointFrom)
	}
}

// TestEmptyCmdKeyIsNotAnAbsentOne keeps nil and empty apart at the list, where
// `cmd=` says the image's arguments are dropped and saying nothing says they
// still run. Collapsing them keeps running a command the user said was gone.
func TestEmptyCmdKeyIsNotAnAbsentOne(t *testing.T) {
	got, err := parseImageList("fleet.txt", "alpine:3.20 cmd= exec-policy=assume-none\nbusybox:1.36 exec-policy=assume-none\n")
	if err != nil {
		t.Fatal(err)
	}
	cleared, silent := got[0].assert, got[1].assert
	if cleared.Cmd == nil {
		t.Error("cmd= was read as though it had not been said, so the image's own arguments still run")
	}
	if len(cleared.Cmd) != 0 {
		t.Errorf("cmd= produced %v, want an empty command line", cleared.Cmd)
	}
	if silent.Cmd != nil {
		t.Errorf("a line that said nothing about cmd produced %#v", silent.Cmd)
	}
	if silent.EntrypointFrom != "" {
		t.Errorf("a line that made no override recorded a source: %q", silent.EntrypointFrom)
	}
}

// TestEntrypointKeyDoesNotSplitOnCommas. roots= splits on commas because a path
// cannot contain one; an argument can, and cutting it in two changes what runs.
func TestEntrypointKeyDoesNotSplitOnCommas(t *testing.T) {
	got, err := parseImageList("fleet.txt", "alpine:3.20 entrypoint=/bin/app cmd=--listen=1.2.3.4,5.6.7.8\n")
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got[0].assert.Cmd, []string{"--listen=1.2.3.4,5.6.7.8"}) {
		t.Errorf("Cmd = %v, want one argument", got[0].assert.Cmd)
	}
}

// TestRepeatedEntrypointKeysAreOneArgvInOrder. A command line is ordered, and
// the order decides which token a wrapper forwards to.
func TestRepeatedEntrypointKeysAreOneArgvInOrder(t *testing.T) {
	got, err := parseImageList("fleet.txt", "alpine:3.20 entrypoint=/usr/bin/tini entrypoint=-- entrypoint=/usr/bin/server\n")
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got[0].assert.Entrypoint, []string{"/usr/bin/tini", "--", "/usr/bin/server"}) {
		t.Errorf("Entrypoint = %v", got[0].assert.Entrypoint)
	}
}

// TestEmptyEntrypointKeyIsRefused. "Started with no program at all" is not a
// runnable claim, and read as an override it would unroot the image's own
// entrypoint and root nothing in its place.
func TestEmptyEntrypointKeyIsRefused(t *testing.T) {
	if _, err := parseImageList("fleet.txt", "alpine:3.20 entrypoint=\n"); err == nil {
		t.Fatal("entrypoint= with no program was accepted")
	}
}

// TestLineEntrypointReplacesTheProfilesRatherThanExtending, the same rule
// roots= follows: a line that states its own command line is a complete
// statement about that image, and appending to a profile's would produce an
// argv nobody wrote.
func TestLineEntrypointReplacesTheProfilesRatherThanExtending(t *testing.T) {
	got, err := parseImageList("fleet.txt", `
[profile wrapped] entrypoint=/usr/bin/tini entrypoint=-- exec-policy=assume-none
a:1 profile=wrapped
b:1 profile=wrapped entrypoint=/usr/bin/server
`)
	if err != nil {
		t.Fatal(err)
	}
	// The profile's own argv reaches the image that asked for it.
	if !equalStrings(got[0].assert.Entrypoint, []string{"/usr/bin/tini", "--"}) {
		t.Errorf("profile entrypoint = %v", got[0].assert.Entrypoint)
	}
	if got[0].assert.EntrypointFrom != "fleet.txt" {
		t.Errorf("a profile's entrypoint recorded no source: %q", got[0].assert.EntrypointFrom)
	}
	// And the line's replaces it rather than appending to it.
	if !equalStrings(got[1].assert.Entrypoint, []string{"/usr/bin/server"}) {
		t.Errorf("line entrypoint = %v, want the line's own alone", got[1].assert.Entrypoint)
	}
}

// TestListSourceNamesStandardInput. The documented way to scan a cluster pipes
// a manifest in, and "the image runs /usr/bin/calico-node per -" names nothing
// a reviewer can check.
func TestListSourceNamesStandardInput(t *testing.T) {
	if got := listSource("-"); got != "standard input" {
		t.Errorf("listSource(\"-\") = %q", got)
	}
	if got := listSource("deploy.yaml"); got != "deploy.yaml" {
		t.Errorf("listSource(\"deploy.yaml\") = %q", got)
	}
}
