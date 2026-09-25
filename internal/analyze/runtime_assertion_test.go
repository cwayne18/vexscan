package analyze

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/modgraph"
)

// The default policies are the scan withholding on its own judgement, which is
// not something the user asserted. Only a run that actually made a claim should
// record one -- otherwise every report carries a condition line and the line
// stops meaning anything.
func TestRuntimeAssertionOnlyWhenSomethingWasAsserted(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want bool
	}{
		{"nothing at all", Options{}, false},
		{"explicit defaults", Options{
			DlopenPolicy:  elfgraph.DlopenTaint,
			ExecPolicy:    elfgraph.ExecTaint,
			DynamicPolicy: modgraph.DynamicTaint,
		}, false},
		{"roots alone", Options{Roots: []string{"/usr/bin/app"}}, true},
		{"exec assume-none alone", Options{ExecPolicy: elfgraph.ExecAssumeNone}, true},
		{"dlopen assume-none alone", Options{DlopenPolicy: elfgraph.DlopenAssumeNone}, true},
		{"dynamic assume-none alone", Options{DynamicPolicy: modgraph.DynamicAssumeNone}, true},
		// A profile name is a label on an assertion, not an assertion. On its own
		// it says nothing the scan acted on and must not produce a condition.
		{"profile name alone", Options{Profile: "go-daemon"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.opts.runtimeAssertion()
			if (got != nil) != tc.want {
				t.Errorf("runtimeAssertion() = %+v, want non-nil == %v", got, tc.want)
			}
		})
	}
}

// The sentence is what a reviewer reads six months later, in a VEX document,
// with none of this run's context. It has to name the profile and spell out each
// half of what was assumed.
func TestRuntimeAssertionSentence(t *testing.T) {
	a := (&Options{
		Roots:         []string{"/usr/bin/calico-node", "/usr/bin/calico-ipam"},
		Profile:       "calico",
		ExecPolicy:    elfgraph.ExecAssumeNone,
		DlopenPolicy:  elfgraph.DlopenAssumeNone,
		DynamicPolicy: modgraph.DynamicAssumeNone,
	}).runtimeAssertion()
	if a == nil {
		t.Fatal("runtimeAssertion() = nil")
	}
	s := a.Sentence()
	for _, want := range []string{
		`"calico"`,
		"/usr/bin/calico-node, /usr/bin/calico-ipam",
		"run nothing else",
		"runtime library loading",
		"computed imports",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("sentence does not mention %q: %q", want, s)
		}
	}
}

// A nil assertion is the common case and must not need guarding at every call
// site.
func TestNilRuntimeAssertionSentenceIsEmpty(t *testing.T) {
	var a *RuntimeAssertion
	if s := a.Sentence(); s != "" {
		t.Errorf("Sentence() = %q, want empty", s)
	}
}

// TestNamedDlopenAssertionSentenceIsNotTheBlanketOne: the two flags make claims
// of very different sizes, and a report that rendered them alike would let the
// broad one borrow the narrow one's credibility.
func TestNamedDlopenAssertionSentenceIsNotTheBlanketOne(t *testing.T) {
	named := (&Options{
		DlopenAssumeNoneFor: []string{"/usr/bin/bash", "libselinux.so.1"},
	}).runtimeAssertion()
	if named == nil {
		t.Fatal("naming callers asserted nothing")
	}
	s := named.Sentence()
	if !strings.Contains(s, "/usr/bin/bash, libselinux.so.1 are asserted to dlopen nothing that matters") {
		t.Errorf("sentence does not name the callers that were waved off: %q", s)
	}
	if strings.Contains(s, "runtime library loading") {
		t.Errorf("the narrow assertion reads as the blanket policy: %q", s)
	}

	blanket := (&Options{DlopenPolicy: elfgraph.DlopenAssumeNone}).runtimeAssertion()
	if b := blanket.Sentence(); strings.Contains(b, "/usr/bin/bash") || b == s {
		t.Errorf("the blanket sentence is indistinguishable from the named one: %q", b)
	}
}

// TestInertDlopenAssertionIsSaidInTheSentence is the guard against a silent
// typo. An unmatched name removes no taint, so no verdict moves and nothing
// else in the report would mention it: the user is left staring at rows still
// blocked by a dlopen they believe they answered.
func TestInertDlopenAssertionIsSaidInTheSentence(t *testing.T) {
	a := &RuntimeAssertion{
		Roots:               []string{"/usr/bin/app"},
		DlopenAssumeNoneFor: []string{"/usr/bin/bash", "/usr/bin/bsah"},
		DlopenInert:         []string{"/usr/bin/bsah"},
	}
	s := a.Sentence()
	if !strings.Contains(s, "/usr/bin/bsah was named by --dlopen-assume-none and matches no dlopen caller here") {
		t.Errorf("sentence does not report the name that did nothing: %q", s)
	}
	if !strings.Contains(s, "/usr/bin/bash is asserted to dlopen nothing that matters") {
		t.Errorf("sentence dropped the name that did work, or lost its agreement: %q", s)
	}
	// The inert name must not also appear in the asserted clause. Listing it in
	// both reports the user's intent as though it were the run's premise.
	if strings.Contains(s, "/usr/bin/bash, /usr/bin/bsah are asserted") {
		t.Errorf("an inert name is listed as something the scan assumed: %q", s)
	}
}

// TestWhollyInertDlopenAssertionStillProducesASentence: when every name missed,
// the asserted clause is empty, and the run must not fall back to reading like
// one that asserted nothing at all.
func TestWhollyInertDlopenAssertionStillProducesASentence(t *testing.T) {
	a := &RuntimeAssertion{
		DlopenAssumeNoneFor: []string{"/usr/bin/bsah", "/usr/bin/cpoi"},
		DlopenInert:         []string{"/usr/bin/bsah", "/usr/bin/cpoi"},
	}
	s := a.Sentence()
	if s == "" {
		t.Fatal("a run whose every assertion missed reports no condition at all")
	}
	if strings.Contains(s, "asserted to dlopen nothing that matters") {
		t.Errorf("names that matched nothing are reported as assumptions the scan made: %q", s)
	}
	if !strings.Contains(s, "/usr/bin/bsah, /usr/bin/cpoi were named") ||
		!strings.Contains(s, "match no dlopen caller here") {
		t.Errorf("sentence does not agree with two inert names: %q", s)
	}
}

// TestRuntimeAssertionPartitionKeepsTheUsersOrder: these are the strings the
// user typed, and reordering them makes the reader hunt for the one they are
// checking against a list they wrote themselves.
func TestRuntimeAssertionPartitionKeepsTheUsersOrder(t *testing.T) {
	in, held := partition([]string{"c", "a", "b", "d"}, []string{"b", "c"})
	if strings.Join(in, ",") != "a,d" {
		t.Errorf("kept = %v, want a,d in the order given", in)
	}
	if strings.Join(held, ",") != "c,b" {
		t.Errorf("held = %v, want c,b in the order given", held)
	}
}

// fakeInert is a plugin that built a closure and has an answer about it.
type fakeInert struct{ inert []string }

func (fakeInert) ID() string                  { return "os" }
func (fakeInert) Ecosystems() []string        { return []string{"Debian"} }
func (f fakeInert) InertAssertions() []string { return f.inert }

// quietPlugin is a plugin with no closure and nothing to say -- a language
// plugin, or an OS plugin on an image with no OS packages.
type quietPlugin struct{}

func (quietPlugin) ID() string           { return "golang" }
func (quietPlugin) Ecosystems() []string { return []string{"Go"} }

// TestRecordInertAssertionsAsksThePluginThatLooked: the answer has to come from
// the closure, and a plugin set with no closure in it must leave the field
// empty rather than have the absence read as "every name matched".
func TestRecordInertAssertionsAsksThePluginThatLooked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		plugins []ecosystem.Plugin
		want    []string
	}{
		{"the reporter answers", []ecosystem.Plugin{quietPlugin{}, fakeInert{[]string{"/usr/bin/bsah"}}},
			[]string{"/usr/bin/bsah"}},
		{"the reporter found nothing inert", []ecosystem.Plugin{fakeInert{nil}}, nil},
		{"nobody built a closure", []ecosystem.Plugin{quietPlugin{}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &Result{Runtime: &RuntimeAssertion{DlopenAssumeNoneFor: []string{"/usr/bin/bsah"}}}
			recordInertAssertions(res, tc.plugins)
			if strings.Join(res.Runtime.DlopenInert, ",") != strings.Join(tc.want, ",") {
				t.Errorf("DlopenInert = %v, want %v", res.Runtime.DlopenInert, tc.want)
			}
		})
	}
}

// A run that asserted nothing has no assertion to annotate, and must not grow
// one on the way past.
func TestRecordInertAssertionsLeavesAnUnassertedRunAlone(t *testing.T) {
	res := &Result{}
	recordInertAssertions(res, []ecosystem.Plugin{fakeInert{[]string{"/usr/bin/bsah"}}})
	if res.Runtime != nil {
		t.Errorf("Runtime = %+v on a run that asserted nothing", res.Runtime)
	}
}

// TestManifestEntrypointLeadsTheSentence. The override is the claim every other
// clause sits on top of -- it decides which program the roots and the policies
// are talking about -- so a reader who disagrees with it can stop there.
func TestManifestEntrypointLeadsTheSentence(t *testing.T) {
	a := &RuntimeAssertion{
		Entrypoint:     []string{"/usr/bin/calico-node"},
		Cmd:            []string{"-felix"},
		EntrypointFrom: "deploy.yaml",
		ExecAssumeNone: true,
	}
	got := a.Sentence()
	for _, want := range []string{"/usr/bin/calico-node -felix", "deploy.yaml", "not the entrypoint its config declares"} {
		if !strings.Contains(got, want) {
			t.Errorf("sentence does not contain %q: %q", want, got)
		}
	}
	if i, j := strings.Index(got, "deploy.yaml"), strings.Index(got, "asserted to run nothing else"); i > j {
		t.Errorf("the override is stated after the assertions that depend on it: %q", got)
	}
}

// TestManifestThatOverrodeNothingStillSaysSo is the same asymmetry the inert
// dlopen name has. A manifest aimed at the wrong images, or one whose
// containers all inherit their entrypoints, cannot make a conclusion wrong --
// but it produces a report identical to one where no manifest was read, and the
// user believes they narrowed something they did not.
func TestManifestThatOverrodeNothingStillSaysSo(t *testing.T) {
	a := &RuntimeAssertion{EntrypointFrom: "deploy.yaml"}
	got := a.Sentence()
	if got == "" {
		t.Fatal("a manifest that overrode nothing produced no sentence, so the report cannot be told from one where no manifest was read")
	}
	if !strings.Contains(got, "says nothing about how this image is started") {
		t.Errorf("sentence does not say the manifest left this image alone: %q", got)
	}
	if !strings.Contains(got, "config declares is what runs") {
		t.Errorf("sentence does not say what runs instead: %q", got)
	}
}

// TestManifestThatClearsTheEntrypointIsNotTheSameAsOneThatSaysNothing keeps
// nil and empty apart in the sentence, where collapsing them would report a
// container that deliberately runs no command as one the manifest never
// mentioned.
func TestManifestThatClearsTheEntrypointIsNotTheSameAsOneThatSaysNothing(t *testing.T) {
	cleared := (&RuntimeAssertion{Entrypoint: []string{}, EntrypointFrom: "deploy.yaml"}).Sentence()
	silent := (&RuntimeAssertion{EntrypointFrom: "deploy.yaml"}).Sentence()
	if cleared == silent {
		t.Fatalf("both render as %q", cleared)
	}
	if !strings.Contains(cleared, "no command at all") {
		t.Errorf("a cleared entrypoint does not say so: %q", cleared)
	}
}

// TestNoManifestLeavesTheSentenceAlone: the clause must not appear on a run
// that read no deployment source, or every existing report grows a sentence
// about a file nobody named.
func TestNoManifestLeavesTheSentenceAlone(t *testing.T) {
	a := &RuntimeAssertion{Roots: []string{"/usr/bin/app"}, ExecAssumeNone: true}
	if got := a.Sentence(); strings.Contains(got, "config declares") || strings.Contains(got, "per ") {
		t.Errorf("a run with no deployment source rendered a clause about one: %q", got)
	}
}

// TestArgsOnlyOverrideDoesNotClaimToReplaceTheEntrypoint is the sentence half of
// the distinction elfgraph already keeps: a source that replaced the arguments
// and not the program has not replaced the entrypoint, and the image's own is
// still what runs. Reported as a replacement, the clause describes an assertion
// nobody made and points a reviewer at the wrong binary.
func TestArgsOnlyOverrideDoesNotClaimToReplaceTheEntrypoint(t *testing.T) {
	got := (&RuntimeAssertion{Cmd: []string{"--serve"}, EntrypointFrom: "deploy.yaml"}).Sentence()
	if strings.Contains(got, "not the entrypoint its config declares") {
		t.Errorf("replacing only the arguments is reported as replacing the entrypoint: %q", got)
	}
	if !strings.Contains(got, "--serve") {
		t.Errorf("the arguments that were asserted are not in the sentence: %q", got)
	}
	if !strings.Contains(got, "deploy.yaml") {
		t.Errorf("the sentence does not say where the claim came from: %q", got)
	}
}

// TestClearedArgsAreNotTheSameAsAClearedEntrypoint. `cmd=` and `--cmd=` say the
// image starts with no arguments; its entrypoint still runs. "Replaced with no
// command at all" says nothing runs, which would have the reader looking for a
// conclusion the closure never drew.
func TestClearedArgsAreNotTheSameAsAClearedEntrypoint(t *testing.T) {
	args := (&RuntimeAssertion{Cmd: []string{}, EntrypointFrom: "--cmd"}).Sentence()
	entry := (&RuntimeAssertion{Entrypoint: []string{}, EntrypointFrom: "--entrypoint"}).Sentence()
	if strings.Contains(args, "no command at all") {
		t.Errorf("dropping the arguments is reported as running nothing: %q", args)
	}
	if !strings.Contains(args, "no arguments") {
		t.Errorf("dropping the arguments is not said: %q", args)
	}
	if !strings.Contains(entry, "no command at all") {
		t.Errorf("a cleared entrypoint is not said: %q", entry)
	}
}

// TestFlagOverrideReadsAsASentence. The source is not always a filename -- the
// same override arrives from the command line -- and the clause has to survive
// that, since it is the one the reader is meant to disagree with.
func TestFlagOverrideReadsAsASentence(t *testing.T) {
	got := (&RuntimeAssertion{
		Entrypoint:     []string{"/usr/bin/server"},
		Cmd:            []string{"--serve"},
		EntrypointFrom: "--entrypoint and --cmd",
		ExecAssumeNone: true,
	}).Sentence()
	want := "the image runs /usr/bin/server --serve per --entrypoint and --cmd, not the entrypoint its config declares"
	if !strings.Contains(got, want) {
		t.Errorf("sentence = %q, want it to contain %q", got, want)
	}
}
