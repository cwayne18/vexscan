package elfgraph

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// overrideTree is the shape the override exists for: an image whose config
// entrypoint is a shell, and which also contains the program a deployment
// actually starts. The shell needs a library nothing else does, so whether the
// shell was rooted is answerable by looking at one node.
func overrideTree(t *testing.T) (target.RootFS, fakeELF) {
	t.Helper()
	return tree(t, map[string]string{
			"/bin/bash":               "",
			"/usr/bin/tini":           "",
			"/usr/bin/server":         "",
			"/usr/lib/libshell.so.1":  "",
			"/usr/lib/libserver.so.1": "",
		}), fakeELF{
			"/bin/bash":               exe("libshell.so.1"),
			"/usr/bin/tini":           exe(),
			"/usr/bin/server":         exe("libserver.so.1"),
			"/usr/lib/libshell.so.1":  lib(),
			"/usr/lib/libserver.so.1": lib(),
		}
}

// bashConfig is the image as built: bash is the entrypoint, and /usr/bin/server
// is a file nothing in the config mentions.
func bashConfig() target.ImageConfig {
	return target.ImageConfig{Entrypoint: []string{"/bin/bash"}, Cmd: []string{"-c", "exec server"}}
}

func rootedAt(g *Graph, p string) bool {
	n, ok := g.Node(p)
	return ok && n.Root
}

func isReachable(g *Graph, p string) bool {
	n, ok := g.Node(p)
	return ok && n.Reachable
}

// TestManifestEntrypointReplacesTheConfigEntrypoint is the whole feature. The
// config says bash; the deployment says server; bash must not be a root, and
// the library only bash reaches must not be reachable.
//
// This is the one test in the file that would pass with the override modelled
// as an extra root and still be measuring nothing, so it checks the negative --
// bash gone -- and not merely that server arrived.
func TestManifestEntrypointReplacesTheConfigEntrypoint(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           bashConfig(),
		Entrypoint:       []string{"/usr/bin/server"},
		Cmd:              []string{},
		EntrypointSource: "deploy.yaml",
	})

	if !rootedAt(g, "/usr/bin/server") {
		t.Error("the command the deployment gives is not a root, so the override rooted nothing")
	}
	if rootedAt(g, "/bin/bash") {
		t.Error("the config entrypoint is still a root, so the override added rather than replaced")
	}
	if isReachable(g, "/usr/lib/libshell.so.1") {
		t.Error("the library only the config entrypoint reaches is still reachable")
	}
	if !isReachable(g, "/usr/lib/libserver.so.1") {
		t.Error("the library the deployment's command reaches is not reachable")
	}
}

// TestNoOverrideLeavesTheConfigEntrypointAlone is the other half: absent an
// override, nothing about the existing behaviour moves. Without it the test
// above passes for a build that ignores the config entirely.
func TestNoOverrideLeavesTheConfigEntrypointAlone(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{Config: bashConfig()})

	if !rootedAt(g, "/bin/bash") {
		t.Error("the config entrypoint is not a root when nothing overrode it")
	}
	if !isReachable(g, "/usr/lib/libshell.so.1") {
		t.Error("the config entrypoint's library is not reachable when nothing overrode it")
	}
}

// TestManifestArgsAloneKeepTheConfigEntrypoint pins the reason Entrypoint and
// Cmd are two fields. Kubernetes `args:` replaces CMD and leaves ENTRYPOINT
// running; folding both into one argv would read an args-only container as a
// container that replaced the entrypoint with its arguments.
func TestManifestArgsAloneKeepTheConfigEntrypoint(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/usr/bin/server"}, Cmd: []string{"--serve"}},
		Cmd:              []string{"--other"},
		EntrypointSource: "deploy.yaml",
	})

	if !rootedAt(g, "/usr/bin/server") {
		t.Error("setting args alone lost the config's own entrypoint")
	}
}

// TestManifestCommandAloneKeepsTheConfigCmd is the mirror: a container that
// sets command and not args still gets the image's CMD appended, which is what
// Kubernetes does and what decides whether a wrapper's forwarded command is
// visible at all.
func TestManifestCommandAloneKeepsTheConfigCmd(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/bin/bash"}, Cmd: []string{"/usr/bin/server"}},
		Entrypoint:       []string{"/usr/bin/tini", "--"},
		EntrypointSource: "deploy.yaml",
	})

	// tini is a transparent exec wrapper: peeling it reaches the argv token
	// after it, which here is the config's Cmd -- present only if overriding
	// command did not clear args along with it. The assertion is on the library
	// and not on the root, because an escalating closure roots every program in
	// the image and would answer yes either way.
	if !isReachable(g, "/usr/lib/libserver.so.1") {
		t.Error("overriding command dropped the config's Cmd, so the wrapper forwarded to nothing")
	}
	if isReachable(g, "/usr/lib/libshell.so.1") {
		t.Error("the closure escalated, so this measured nothing")
	}
}

// TestEmptyManifestCommandIsNotAnAbsentOne keeps nil and empty apart at the
// graph. A container that sets `command: []` has replaced the entrypoint with
// nothing, which is unknowable, not "use the image's".
func TestEmptyManifestCommandIsNotAnAbsentOne(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           bashConfig(),
		Entrypoint:       []string{},
		Cmd:              []string{},
		EntrypointSource: "deploy.yaml",
	})

	if rootedAt(g, "/bin/bash") && !rootedAt(g, "/usr/bin/server") {
		t.Fatal("an empty override fell back to the config entrypoint instead of being read as one that names nothing")
	}
	var found Taint
	for _, ta := range g.Taints() {
		if ta.Kind == TaintNoEntrypoint {
			found = ta
		}
	}
	if found.Kind == "" {
		t.Fatal("an override that names no command raised no no-entrypoint taint")
	}
	if !strings.Contains(found.Detail, "deploy.yaml names no command") {
		t.Errorf("the taint blames the image config for a command the deployment cleared: %q", found.Detail)
	}
}

// TestManifestShellCommandStillEscalates is the guard against the override
// being treated as more trustworthy than a config entrypoint. A deployment is
// perfectly free to say `command: ["/bin/sh", "-c", ...]`, and that says as
// little about what runs as a /bin/sh ENTRYPOINT does.
func TestManifestShellCommandStillEscalates(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/usr/bin/server"}},
		Entrypoint:       []string{"/bin/bash", "-c", "exec server"},
		EntrypointSource: "deploy.yaml",
	})

	var shell Taint
	for _, ta := range g.Taints() {
		if ta.Kind == TaintShellEntrypoint {
			shell = ta
		}
	}
	if shell.Kind == "" {
		t.Fatal("a shell named by the deployment raised no shell-entrypoint taint")
	}
	if shell.Discharged {
		t.Error("the shell taint was discharged with no --roots and no exec assertion")
	}
	// Escalation roots every program, which is what makes the answer safe.
	if !rootedAt(g, "/usr/bin/server") {
		t.Error("the shell command did not escalate, so a program it could start is unrooted")
	}
}

// TestOverriddenEntrypointSaysSoInTheTaint pins the wording. The evidence line
// is where a reviewer meets this assertion; one that reads identically to a
// finding about the image's own config invites the conclusion to be checked
// against the wrong thing.
func TestOverriddenEntrypointSaysSoInTheTaint(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/usr/bin/server"}},
		Entrypoint:       []string{"/bin/bash"},
		EntrypointSource: "deploy.yaml",
	})

	for _, ta := range g.Taints() {
		if ta.Kind != TaintShellEntrypoint {
			continue
		}
		if !strings.Contains(ta.Detail, "deploy.yaml") {
			t.Errorf("the taint does not say the entrypoint came from the deployment: %q", ta.Detail)
		}
		if !strings.Contains(ta.Detail, "replaces the image's own") {
			t.Errorf("the taint does not say the image's own entrypoint is not running: %q", ta.Detail)
		}
		return
	}
	t.Fatal("no shell-entrypoint taint to check")
}

// TestUnresolvableOverriddenEntrypointFailsClosed: a deployment naming a
// command this image does not have is the typo case, and it must widen the
// closure rather than narrow it. With no --roots to stand on there is nothing
// to hold the conclusion up, so it escalates.
func TestUnresolvableOverriddenEntrypointFailsClosed(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/usr/bin/server"}},
		Entrypoint:       []string{"/usr/bin/sevrer"},
		EntrypointSource: "deploy.yaml",
	})

	if !rootedAt(g, "/bin/bash") {
		t.Error("an unresolvable override narrowed the closure instead of escalating it")
	}
	var got Taint
	for _, ta := range g.Taints() {
		if ta.Kind == TaintNoEntrypoint {
			got = ta
		}
	}
	if got.Kind == "" || got.Discharged {
		t.Errorf("an unresolvable override left no blocking no-entrypoint taint: %+v", got)
	}
}

// TestManifestArgsAreTheOnesThatRun. The args half has to replace the config's
// and not merely survive it: a wrapper entrypoint forwards to whatever argv
// token follows, so getting this wrong roots the program the image was built
// to run rather than the one the deployment asked for.
func TestManifestArgsAreTheOnesThatRun(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/usr/bin/tini", "--"}, Cmd: []string{"/bin/bash"}},
		Cmd:              []string{"/usr/bin/server"},
		EntrypointSource: "deploy.yaml",
	})

	if !isReachable(g, "/usr/lib/libserver.so.1") {
		t.Error("the args the deployment gives did not reach the wrapper, so the override was ignored")
	}
	if isReachable(g, "/usr/lib/libshell.so.1") {
		t.Error("the config's own Cmd still runs, so the args override added rather than replaced")
	}
}

// TestArgsOnlyOverrideDoesNotClaimToReplaceTheEntrypoint. An args-only
// container runs the image's entrypoint, and a message saying the deployment
// replaced it describes an assertion nobody made.
func TestArgsOnlyOverrideDoesNotClaimToReplaceTheEntrypoint(t *testing.T) {
	fsys, objs := overrideTree(t)
	g := build(t, fsys, objs, Options{
		Config:           target.ImageConfig{Entrypoint: []string{"/bin/bash"}},
		Cmd:              []string{"-c", "true"},
		EntrypointSource: "deploy.yaml",
	})

	for _, ta := range g.Taints() {
		if ta.Kind != TaintShellEntrypoint {
			continue
		}
		if strings.Contains(ta.Detail, "replaces the image's own") {
			t.Errorf("an args-only override is reported as having replaced the entrypoint: %q", ta.Detail)
		}
		return
	}
	t.Fatal("no shell-entrypoint taint to check")
}
