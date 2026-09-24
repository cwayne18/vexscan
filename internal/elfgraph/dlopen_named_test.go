package elfgraph

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// The per-caller form of the dlopen assertion: --dlopen-assume-none names one
// loader instead of waving off every loader in the image. These tests pin the
// two things that make it worth having over the blanket policy -- it discharges
// exactly the caller named and nothing else, and a name that matched nothing
// says so rather than passing for an assertion that worked.

// dlopenTree is two loaders and a program that needs both, which is the shape
// that shows a named assertion discharging one and leaving the other.
func dlopenTree(t *testing.T) (target.RootFS, fakeELF) {
	t.Helper()
	one := lib()
	one.Dlopen = true
	one.Soname = "libone.so.1"
	two := lib()
	two.Dlopen = true
	two.Soname = "libtwo.so.2"
	return tree(t, map[string]string{
			"/usr/bin/app":         "",
			"/usr/lib/libone.so.1": "",
			"/usr/lib/libtwo.so.2": "",
		}), fakeELF{
			"/usr/bin/app":         exe("libone.so.1", "libtwo.so.2"),
			"/usr/lib/libone.so.1": one,
			"/usr/lib/libtwo.so.2": two,
		}
}

func dlopenTaints(g *Graph) map[string]Taint {
	out := map[string]Taint{}
	for _, t := range g.Taints() {
		if t.Kind == TaintDlopen {
			out[t.Path] = t
		}
	}
	return out
}

func buildNamed(t *testing.T, names ...string) *Graph {
	t.Helper()
	fsys, objs := dlopenTree(t)
	return build(t, fsys, objs, Options{
		Config:              target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		DlopenAssumeNoneFor: names,
	})
}

// TestNamedDlopenAssertionDischargesOnlyThatCaller is the whole point of the
// narrow flag: the blanket policy clears both loaders, this clears one.
func TestNamedDlopenAssertionDischargesOnlyThatCaller(t *testing.T) {
	g := buildNamed(t, "/usr/lib/libone.so.1")

	ts := dlopenTaints(g)
	one, ok := ts["/usr/lib/libone.so.1"]
	if !ok {
		t.Fatal("the named caller lost its dlopen taint entirely; the record is what makes the assertion auditable")
	}
	if one.Blocking {
		t.Errorf("the named caller still blocks: %+v", one)
	}
	if !one.Discharged {
		t.Errorf("the named caller was demoted without being marked discharged: %+v", one)
	}
	if !strings.Contains(one.Detail, "--dlopen-assume-none names /usr/lib/libone.so.1") {
		t.Errorf("detail does not say which assertion answered it: %q", one.Detail)
	}

	two, ok := ts["/usr/lib/libtwo.so.2"]
	if !ok {
		t.Fatal("the unnamed caller has no dlopen taint at all")
	}
	if !two.Blocking || two.Discharged {
		t.Errorf("naming one caller discharged the other: %+v", two)
	}
	if len(g.BlockingTaints()) == 0 {
		t.Error("BlockingTaints is empty, so the unnamed caller stopped gating conclusions")
	}
}

// TestNamedDlopenAssertionMatchesSoname: a user reads a soname out of a report
// and pastes it back in, which has to name the same caller its path does.
func TestNamedDlopenAssertionMatchesSoname(t *testing.T) {
	g := buildNamed(t, "libone.so.1")
	if tt := dlopenTaints(g)["/usr/lib/libone.so.1"]; tt.Blocking || !tt.Discharged {
		t.Errorf("a SONAME did not answer the caller that carries it: %+v", tt)
	}
	if len(g.InertAssertions()) != 0 {
		t.Errorf("a SONAME that matched was reported inert: %v", g.InertAssertions())
	}
}

// TestNamedDlopenAssertionIgnoresBasename: a multiarch image carries
// /usr/lib/libdual.so.9 and /usr/lib32/libdual.so.9, and they are different
// objects. An assertion written as the bare filename names both, so it would
// discharge the one the user never opened on the strength of having looked at
// the other -- which is the whole thing this flag exists not to do. Neither is
// discharged, and the name is reported as having done nothing so the user
// writes the path they meant.
func TestNamedDlopenAssertionIgnoresBasename(t *testing.T) {
	dual := func() *Info {
		i := lib()
		i.Dlopen = true
		return i
	}
	fsys := tree(t, map[string]string{
		"/usr/lib/libdual.so.9":   "",
		"/usr/lib32/libdual.so.9": "",
	})
	objs := fakeELF{"/usr/lib/libdual.so.9": dual(), "/usr/lib32/libdual.so.9": dual()}

	g := build(t, fsys, objs, Options{
		Roots:               []string{"/usr/lib/libdual.so.9", "/usr/lib32/libdual.so.9"},
		DlopenAssumeNoneFor: []string{"libdual.so.9"},
	})

	ts := dlopenTaints(g)
	if len(ts) != 2 {
		t.Fatalf("dlopen taints = %v, want one per copy", ts)
	}
	for p, tt := range ts {
		if !tt.Blocking || tt.Discharged {
			t.Errorf("a bare filename discharged %s: %+v", p, tt)
		}
	}
	if got := g.InertAssertions(); len(got) != 1 || got[0] != "libdual.so.9" {
		t.Errorf("InertAssertions = %v, want the bare filename reported as having matched nothing", got)
	}
}

// TestInertDlopenAssertionIsReported is the guard that keeps a typo from being
// invisible. The assertion removes no taint, so nothing in the verdicts changes
// and nothing in the report would mention it unless this says so.
func TestInertDlopenAssertionIsReported(t *testing.T) {
	g := buildNamed(t, "/usr/lib/libthree.so.3")

	got := g.InertAssertions()
	if len(got) != 1 || got[0] != "/usr/lib/libthree.so.3" {
		t.Fatalf("InertAssertions = %v, want the name that matched nothing", got)
	}
	tt := hasTaint(g, TaintInertAssertion)
	if tt == nil {
		t.Fatal("no inert-assertion taint recorded")
	}
	if tt.Blocking || tt.Discharged {
		t.Errorf("an inert assertion blocked or claimed a discharge: %+v", *tt)
	}
	if !strings.Contains(tt.Detail, "not a reachable object in this image") {
		t.Errorf("detail does not say the name is absent: %q", tt.Detail)
	}
}

// TestInertDlopenAssertionSeparatesAbsentFromSilent: "you spelled it wrong" and
// "that object is here and does not dlopen" send the user to different places,
// so the two are not worth collapsing into one sentence.
func TestInertDlopenAssertionSeparatesAbsentFromSilent(t *testing.T) {
	quiet := lib()
	quiet.Soname = "libquiet.so.4"
	fsys := tree(t, map[string]string{"/usr/bin/app": "", "/usr/lib/libquiet.so.4": ""})
	objs := fakeELF{
		"/usr/bin/app":           exe("libquiet.so.4"),
		"/usr/lib/libquiet.so.4": quiet,
	}

	g := build(t, fsys, objs, Options{
		Config:              target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		DlopenAssumeNoneFor: []string{"/usr/lib/libquiet.so.4"},
	})
	tt := hasTaint(g, TaintInertAssertion)
	if tt == nil {
		t.Fatal("an object that exists but calls no dlopen was not reported inert")
	}
	if !strings.Contains(tt.Detail, "is in this image but calls no dlopen") {
		t.Errorf("detail reads as a missing file rather than a silent one: %q", tt.Detail)
	}
}

// TestMatchedDlopenAssertionIsNotInert: the assertion that did its job must not
// also be reported as having done nothing.
func TestMatchedDlopenAssertionIsNotInert(t *testing.T) {
	g := buildNamed(t, "/usr/lib/libone.so.1")
	if got := g.InertAssertions(); len(got) != 0 {
		t.Errorf("InertAssertions = %v after the name discharged a caller", got)
	}
	if hasTaint(g, TaintInertAssertion) != nil {
		t.Error("a matched assertion raised an inert-assertion taint")
	}
}

// TestBlanketDlopenPolicyRefusesNamedCallers: the two flags say different-sized
// things, and setting both means the user believes one of them does something
// it does not. Erroring beats guessing which one they meant.
func TestBlanketDlopenPolicyRefusesNamedCallers(t *testing.T) {
	fsys, objs := dlopenTree(t)
	_, err := Build(fsys, Options{
		Config:              target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		ReadELF:             objs.read,
		DlopenPolicy:        DlopenAssumeNone,
		DlopenAssumeNoneFor: []string{"/usr/lib/libone.so.1"},
	})
	if err == nil {
		t.Fatal("setting both the blanket policy and a named caller was accepted")
	}
	if !strings.Contains(err.Error(), "/usr/lib/libone.so.1") {
		t.Errorf("the error does not name the flag value to remove: %v", err)
	}
}

func TestMatchDlopenAssertion(t *testing.T) {
	names := []string{"/usr/lib/libone.so.1", "libtwo.so.2"}
	tests := []struct {
		name   string
		path   string
		soname string
		want   string
	}{
		{"by path", "/usr/lib/libone.so.1", "libone.so.1", "/usr/lib/libone.so.1"},
		{"by soname", "/usr/lib/libtwo.so.2", "libtwo.so.2", "libtwo.so.2"},
		{"a path that is only a suffix of the name", "lib/libone.so.1", "", ""},
		{"a soname on the wrong object", "/opt/libone.so.1", "libother.so", ""},
		{"an object with no soname and another path", "/usr/lib32/libtwo.so.2", "", ""},
		{"nothing named", "/usr/lib/libthree.so.3", "libthree.so.3", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDlopenAssertion(names, tt.path, tt.soname); got != tt.want {
				t.Errorf("matchDlopenAssertion(%q, %q) = %q, want %q", tt.path, tt.soname, got, tt.want)
			}
		})
	}
}

// TestBoundedLoaderKeepsItsOwnReasonOverANamedAssertion: where the graph worked
// the answer out for itself and the user also named the caller, the graph's
// finding is what gets reported.
//
// Both discharge, so no status turns on which one is printed -- and that is
// exactly why it is worth pinning. The detail is the whole audit trail: one
// sentence says the analysis proved everything libcrypto can load is already in
// the closure, the other says a human promised it. A reader deciding whether to
// trust a clean row is weighing which of those they were told, and a report
// that downgrades a proof to an assertion is wrong about its own strength in
// the direction that makes a reviewer discount evidence they should not.
func TestBoundedLoaderKeepsItsOwnReasonOverANamedAssertion(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app": "",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3":         "",
		"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so": "",
	}
	objs := fakeELF{
		"/usr/bin/app": exe("libcrypto.so.3"),
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3":         libcryptoCaller(),
		"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{
		Config:              target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		DlopenAssumeNoneFor: []string{"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"},
	})

	tt := dlopenTaintFor(g, "/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
	if tt == nil {
		t.Fatal("libcrypto raised no dlopen taint at all")
	}
	if !tt.Discharged {
		t.Fatalf("the caller was not discharged at all: %+v", *tt)
	}
	if strings.Contains(tt.Detail, "--dlopen-assume-none") {
		t.Errorf("a proof was reported as the user's say-so: %q", tt.Detail)
	}
	if !strings.Contains(tt.Detail, "OpenSSL") {
		t.Errorf("detail does not give the graph's own reason: %q", tt.Detail)
	}
	// Not inert either: the name did find its caller, and sending the user
	// hunting for a typo that is not there is its own wrong answer.
	if got := g.InertAssertions(); len(got) != 0 {
		t.Errorf("InertAssertions = %v for a name whose caller the graph answered first", got)
	}
}
