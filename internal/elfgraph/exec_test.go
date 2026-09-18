package elfgraph

import (
	"slices"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// execTree is an image whose entrypoint is /app/server, with a /usr/bin/su that
// needs libpam and a libpam nothing else references. It is the shape the whole
// probe exists for: without an exec, su and libpam are dead code; with one,
// they may be the most important thing in the image.
func execTree(t *testing.T) (target.RootFS, fakeELF, Options) {
	t.Helper()
	objs := fakeELF{
		"/app/server":          exe(),
		"/usr/bin/su":          exe("libpam.so.0"),
		"/usr/lib/libpam.so.0": lib(),
	}
	files := map[string]string{}
	for p := range objs {
		files[p] = ""
	}
	return tree(t, files), objs, Options{
		Config: target.ImageConfig{Entrypoint: []string{"/app/server"}},
	}
}

// prober returns an ExecProber that answers for one path and knows nothing
// about anything else, which is the shape of the real one: it speaks for Go
// binaries and declines on everything else.
func prober(subject string, pr ExecProbe, ok bool) ExecProber {
	return func(_ target.RootFS, p string, programs []string) (ExecProbe, bool) {
		if p != subject {
			return ExecProbe{}, false
		}
		out := pr
		// Mimic a real prober: only offer targets the image actually has.
		var keep []string
		for _, t := range pr.Targets {
			if slices.Contains(programs, t) {
				keep = append(keep, t)
			}
		}
		out.Targets = keep
		return out, ok
	}
}

// The case the closure was always silently wrong about. An entrypoint that can
// exec must not produce a clean answer, because the program it runs loads
// libraries in a process this package never looks at.
func TestAnEntrypointThatCanExecBlocksConclusions(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.ExecProber = prober("/app/server", ExecProbe{
		CanSpawn: true,
		Why:      "it links syscall.forkExec",
		Targets:  []string{"/usr/bin/su"},
	}, true)
	g := build(t, fsys, objs, opts)

	tt := hasTaint(g, TaintExec)
	if tt == nil {
		t.Fatalf("no exec taint; taints are %v", g.Taints())
	}
	if !tt.Blocking || !tt.Global {
		t.Errorf("exec taint is Blocking=%v Global=%v, want both true: an exec'd program can load anything", tt.Blocking, tt.Global)
	}
	if tt.Discharged {
		t.Error("a blocking exec taint is marked discharged")
	}
	if !strings.Contains(tt.Detail, "syscall.forkExec") {
		t.Errorf("detail does not say what was found: %q", tt.Detail)
	}
}

// A target named in the binary is rooted, so the libraries it needs are in the
// closure rather than reported as dead code. This is what makes
// --exec-policy=assume-none worth offering: the narrowed closure it unblocks
// has the exec'd program in it.
func TestAMentionedExecTargetIsRootedWithItsLibraries(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.ExecProber = prober("/app/server", ExecProbe{
		CanSpawn: true,
		Why:      "it links syscall.forkExec",
		Targets:  []string{"/usr/bin/su"},
	}, true)
	g := build(t, fsys, objs, opts)

	reachable(t, g, "/app/server", "/usr/bin/su", "/usr/lib/libpam.so.0")
	if n, _ := g.Node("/usr/bin/su"); n == nil || !n.Root {
		t.Fatal("/usr/bin/su was not rooted")
	}
	if tt := hasTaint(g, TaintExec); tt == nil || !strings.Contains(tt.Detail, "/usr/bin/su") {
		t.Errorf("the rooted target is not named in the evidence: %v", tt)
	}
}

// Rooting the targets must not be mistaken for having found them all. A list
// recovered from string literals cannot include a name built at runtime, so
// the taint blocks whether the list is empty or full.
func TestFindingTargetsDoesNotDischargeTheExecTaint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []string
	}{
		{"with a target", []string{"/usr/bin/su"}},
		{"with none", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys, objs, opts := execTree(t)
			opts.ExecProber = prober("/app/server", ExecProbe{
				CanSpawn: true, Why: "it links syscall.forkExec", Targets: tc.targets,
			}, true)
			g := build(t, fsys, objs, opts)

			tt := hasTaint(g, TaintExec)
			if tt == nil || !tt.Blocking {
				t.Fatalf("exec taint is not blocking: %v", tt)
			}
			if len(g.BlockingTaints()) == 0 {
				t.Error("BlockingTaints is empty for an image whose entrypoint execs")
			}
		})
	}
}

// The other half, and the reason this is worth building: an entrypoint proven
// unable to exec records that fact. A clean report that never checked and a
// clean report that checked are different claims, and only the second one
// closes the gap.
func TestAnEntrypointProvenUnableToExecIsRecordedAsDischarged(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.ExecProber = prober("/app/server", ExecProbe{
		Why: "it is a pure-Go binary with no process-spawning calls",
	}, true)
	g := build(t, fsys, objs, opts)

	tt := hasTaint(g, TaintExec)
	if tt == nil {
		t.Fatalf("nothing recorded for an entrypoint that was proven unable to exec; taints are %v", g.Taints())
	}
	if tt.Blocking || tt.Global {
		t.Errorf("a proven-clean entrypoint blocked: Blocking=%v Global=%v", tt.Blocking, tt.Global)
	}
	if !tt.Discharged {
		t.Error("the proof is not marked discharged, so the report cannot tell it from an image nothing checked")
	}
	unreachable(t, g, "/usr/bin/su", "/usr/lib/libpam.so.0")
}

// A prober that cannot speak for the binary must leave the closure exactly as
// it was. Blocking on "this entrypoint is written in C" would block every image
// with a compiled non-Go entrypoint, on a suspicion that applies to all of them
// equally and is therefore no information at all.
func TestAnUnrecognisedEntrypointChangesNothing(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.ExecProber = prober("/app/server", ExecProbe{}, false)
	g := build(t, fsys, objs, opts)

	if tt := hasTaint(g, TaintExec); tt != nil {
		t.Errorf("an unreadable entrypoint produced an exec taint: %v", tt)
	}
	unreachable(t, g, "/usr/bin/su")
}

// A probe that reports a result without saying how it got there produces a
// taint whose detail cannot be audited -- and in the discharged direction, one
// indistinguishable in the output from a real proof.
func TestAProbeWithNoReasonEstablishesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		pr   ExecProbe
	}{
		{"claiming a spawn", ExecProbe{CanSpawn: true}},
		{"claiming none", ExecProbe{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys, objs, opts := execTree(t)
			opts.ExecProber = prober("/app/server", tc.pr, true)
			g := build(t, fsys, objs, opts)
			if tt := hasTaint(g, TaintExec); tt != nil {
				t.Errorf("an unexplained probe was believed: %v", tt)
			}
		})
	}
}

// The escape hatch, matching --dlopen-policy: the user asserts the exec targets
// are accounted for, the observation stays in the record, and it stops gating.
func TestExecAssumeNoneRecordsWithoutBlocking(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.ExecPolicy = ExecAssumeNone
	opts.ExecProber = prober("/app/server", ExecProbe{
		CanSpawn: true, Why: "it links syscall.forkExec", Targets: []string{"/usr/bin/su"},
	}, true)
	g := build(t, fsys, objs, opts)

	tt := hasTaint(g, TaintExec)
	if tt == nil {
		t.Fatal("assume-none dropped the observation instead of demoting it")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("assume-none left the taint blocking: %v", tt)
	}
	if !tt.Discharged {
		t.Error("the waived taint is not marked discharged")
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints = %v under --exec-policy=assume-none", g.BlockingTaints())
	}
	// The assertion is about what it execs, so the target is still rooted.
	reachable(t, g, "/usr/bin/su", "/usr/lib/libpam.so.0")
}

// An escalated image has already rooted every executable and recorded a
// blocking taint for not knowing what it runs. Probing there would cost the I/O
// of reading every binary in the image to reach a conclusion already reached,
// and would add a second sentence saying what the first one said.
func TestEscalatedImagesAreNotProbed(t *testing.T) {
	fsys, objs, _ := execTree(t)
	objs["/bin/sh"] = exe()
	files := map[string]string{}
	for p := range objs {
		files[p] = ""
	}
	fsys = tree(t, files)

	probed := 0
	g := build(t, fsys, objs, Options{
		Config: target.ImageConfig{Entrypoint: []string{"/bin/sh", "-c", "exec /app/server"}},
		ExecProber: func(_ target.RootFS, _ string, _ []string) (ExecProbe, bool) {
			probed++
			return ExecProbe{CanSpawn: true, Why: "counted"}, true
		},
	})
	if probed != 0 {
		t.Errorf("probed %d roots in an escalated image, want 0", probed)
	}
	if hasTaint(g, TaintShellEntrypoint) == nil {
		t.Fatal("the shell entrypoint taint is missing, so this test is not measuring what it claims")
	}
}

// A path the binary mentions that is not a program in this image -- a config
// file, a directory, a string that happens to look like a path -- is not a root.
func TestOnlyRealProgramsAreRootedAsExecTargets(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.ExecProber = func(_ target.RootFS, p string, _ []string) (ExecProbe, bool) {
		if p != "/app/server" {
			return ExecProbe{}, false
		}
		return ExecProbe{
			CanSpawn: true,
			Why:      "it links syscall.forkExec",
			// The library is real and in the graph, but it is not a program;
			// the other two are not in the image at all.
			Targets: []string{"/usr/lib/libpam.so.0", "/etc/passwd", "/usr/bin/nope"},
		}, true
	}
	g := build(t, fsys, objs, opts)

	if n, _ := g.Node("/usr/lib/libpam.so.0"); n != nil && n.Root {
		t.Error("a shared library was rooted as an exec target")
	}
	unreachable(t, g, "/usr/lib/libpam.so.0", "/usr/bin/su")
	if tt := hasTaint(g, TaintExec); tt == nil || !strings.Contains(tt.Detail, "no program path") {
		t.Errorf("evidence does not say that nothing was rooted: %v", tt)
	}
}

// A plugin root is not an entrypoint. It was rooted because some library in the
// closure opens files of its kind by name, which says the process may load it,
// not that the image runs it as a program -- so the question "what does this
// start" is not one to ask of it, and asking it of every admitted plugin would
// read every NSS, PAM and gconv module in the image to no purpose.
func TestOnlyEntrypointsAreProbedAndNotPluginRoots(t *testing.T) {
	objs := fakeELF{
		"/app/server": exe(),
		"/usr/lib/node_modules/thing/build/Release/thing.node": lib(),
	}
	files := map[string]string{}
	for p := range objs {
		files[p] = ""
	}

	var probed []string
	g := build(t, tree(t, files), objs, Options{
		Config: target.ImageConfig{Entrypoint: []string{"/app/server"}},
		// Answers for everything, so the guard in probeExec is the only thing
		// that can keep the plugin out.
		ExecProber: func(_ target.RootFS, p string, _ []string) (ExecProbe, bool) {
			probed = append(probed, p)
			return ExecProbe{CanSpawn: true, Why: "counted"}, true
		},
	})

	if n, _ := g.Node("/usr/lib/node_modules/thing/build/Release/thing.node"); n == nil || !n.Root {
		t.Fatal("the plugin was not rooted, so this test is not measuring what it claims")
	}
	if !slices.Equal(probed, []string{"/app/server"}) {
		t.Errorf("probed %v, want only the entrypoint", probed)
	}
}

// --roots names a program the user says runs, so it is as much an entrypoint as
// the config's own and gets the same question asked of it.
func TestRootsNamedByTheUserAreProbedToo(t *testing.T) {
	fsys, objs, opts := execTree(t)
	opts.Roots = []string{"/usr/bin/su"}
	opts.ExecProber = prober("/usr/bin/su", ExecProbe{
		CanSpawn: true, Why: "it links syscall.forkExec",
	}, true)
	g := build(t, fsys, objs, opts)

	tt := hasTaint(g, TaintExec)
	if tt == nil || tt.Path != "/usr/bin/su" {
		t.Fatalf("a --roots program was not probed: %v", tt)
	}
}
