package ospkg

import (
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/target"
)

// The plugin is where an inert --dlopen-assume-none name has to survive to, and
// the only reason it is carried this far is that nothing else in a scan would
// mention it. The assertion removes no taint, so no verdict moves, no evidence
// line appears, and a report from a run with a typo in the flag is otherwise
// byte-identical to one from the run the user meant. See
// elfgraph.TaintInertAssertion.

// inertImage is one dlopen caller the closure reaches and one program that
// does not dlopen, so a name can match either, neither, or the wrong one.
func inertImage(t *testing.T, names ...string) *Plugin {
	t.Helper()
	img := inertTree(t)
	loader := exe()
	loader.Dlopen = true
	loader.Soname = "libloader.so.1"

	plugin := New(Options{
		Roots: []string{"/usr/bin/loader"},
		ReadELF: fakeELF{
			"/usr/bin/app":    exe(),
			"/usr/bin/loader": loader,
			"/usr/bin/cpio":   exe(),
		}.read,
		DlopenAssumeNoneFor: names,
	})
	statuses(t, plugin, img, []ecosystem.Subject{{Raw: ""}})
	return plugin
}

func inertTree(t *testing.T) *target.Image {
	t.Helper()
	return debianImage(t,
		target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		[]debPkg{{name: "cpio", version: "2.13-1", files: []string{"/usr/bin/cpio"}}},
		map[string]string{"/usr/bin/app": "", "/usr/bin/loader": ""})
}

// TestPluginReportsAnInertDlopenAssertion: a name that found no caller has to
// come back out of the plugin, because the report has no other way to learn it.
func TestPluginReportsAnInertDlopenAssertion(t *testing.T) {
	p := inertImage(t, "/usr/bin/loder")
	got := p.InertAssertions()
	if len(got) != 1 || got[0] != "/usr/bin/loder" {
		t.Fatalf("InertAssertions() = %v, want the misspelled name", got)
	}
}

// TestPluginReportsNothingInertWhenTheNameMatched: the readback must not accuse
// a working assertion of having done nothing.
func TestPluginReportsNothingInertWhenTheNameMatched(t *testing.T) {
	if got := inertImage(t, "/usr/bin/loader").InertAssertions(); len(got) != 0 {
		t.Errorf("InertAssertions() = %v after the name discharged a caller", got)
	}
}

// TestPluginReportsNothingInertWithNoClosure: a plugin that never opened a tree
// has not established that anything was inert, and saying otherwise would turn
// "nobody looked" into "the name is wrong".
func TestPluginReportsNothingInertWithNoClosure(t *testing.T) {
	p := New(Options{DlopenAssumeNoneFor: []string{"/usr/bin/loder"}})
	if got := p.InertAssertions(); got != nil {
		t.Errorf("InertAssertions() = %v before any closure was built", got)
	}
}
