package analyze

import (
	"strings"
	"testing"

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
