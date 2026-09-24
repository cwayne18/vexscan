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
