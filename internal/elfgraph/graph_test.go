package elfgraph

import (
	"debug/elf"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// The graph tests use a fake ELF reader over a tree of empty files. Resolution
// order, ABI matching, rpath inheritance and taint scoping are where this
// package gets things wrong, and none of them need a real object file to
// exercise -- while building fixtures for each case would mean shipping a
// dozen binaries to test string handling.

type fakeELF map[string]*Info

func (f fakeELF) read(_ target.RootFS, name string) (*Info, error) {
	if i, ok := f[name]; ok {
		return i, nil
	}
	return nil, ErrNotELF
}

// lib describes a dynamic object of the default ABI (64-bit x86-64).
func lib(needed ...string) *Info {
	return &Info{
		Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_DYN,
		Dynamic: true, Needed: needed,
	}
}

// exe is lib plus a program interpreter, which is what makes it dynamic
// rather than static.
func exe(needed ...string) *Info {
	i := lib(needed...)
	i.Type = elf.ET_EXEC
	i.Interp = "/lib64/ld-linux-x86-64.so.2"
	return i
}

// tree writes files (and optionally symlinks, as "target" values prefixed with
// "->") into a temp dir and returns a RootFS over it.
func tree(t *testing.T, entries map[string]string) target.RootFS {
	t.Helper()
	root := t.TempDir()
	// Symlinks last, so their parents already exist.
	var links []string
	for name, content := range entries {
		if strings.HasPrefix(content, "->") {
			links = append(links, name)
			continue
		}
		write(t, root, name, content)
	}
	sort.Strings(links)
	for _, name := range links {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(strings.TrimPrefix(entries[name], "->"), p); err != nil {
			t.Fatal(err)
		}
	}
	return target.NewDirFS(root)
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func build(t *testing.T, fsys target.RootFS, objs fakeELF, opts Options) *Graph {
	t.Helper()
	opts.ReadELF = objs.read
	g, err := Build(fsys, opts)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func reachable(t *testing.T, g *Graph, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, n := range g.Nodes() {
		if n.Reachable {
			got[n.Path] = true
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s is not reachable; reachable set is %v", w, keys(got))
		}
	}
}

func unreachable(t *testing.T, g *Graph, want ...string) {
	t.Helper()
	for _, w := range want {
		n, ok := g.Node(w)
		if !ok {
			t.Errorf("%s is not in the graph at all", w)
			continue
		}
		if n.Reachable {
			t.Errorf("%s is reachable but should not be (pulled in by %v)", w, n.NeededBy)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasTaint(g *Graph, kind TaintKind) *Taint {
	for i := range g.Taints() {
		if t := g.Taints()[i]; t.Kind == kind {
			return &t
		}
	}
	return nil
}

func TestClosureFollowsNeeded(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/usr/bin/app":                             "",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":    "",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3": "",
		"/usr/lib/x86_64-linux-gnu/libxml2.so.2":   "",
		"/etc/passwd":                              "root:x:0:0",
	})
	objs := fakeELF{
		"/usr/bin/app":                             exe("libssl.so.3"),
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":    lib("libcrypto.so.3"),
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3": lib(),
		"/usr/lib/x86_64-linux-gnu/libxml2.so.2":   lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	reachable(t, g, "/usr/bin/app",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
	// libxml2 is installed and nothing loads it. That is the entire point of
	// the package: an image can carry a vulnerable library it never opens.
	unreachable(t, g, "/usr/lib/x86_64-linux-gnu/libxml2.so.2")

	if n, _ := g.Node("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"); len(n.NeededBy) != 1 ||
		n.NeededBy[0] != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("libcrypto does not record who pulled it in: %v", n.NeededBy)
	}
	if len(g.Taints()) != 0 {
		t.Errorf("a fully resolved closure should be untainted, got %v", g.Taints())
	}
}

// TestUnresolvedNeededIsScopedToItsSoname: a missing library is a hole in the
// closure, but only around itself. Treating it as a global blocker would make
// one broken image answer "cannot tell" about every package in it.
func TestUnresolvedNeededIsScopedToItsSoname(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/bin/app": ""})
	objs := fakeELF{"/usr/bin/app": exe("libghost.so.1")}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := hasTaint(g, TaintUnresolvedNeeded)
	if tt == nil {
		t.Fatal("a DT_NEEDED that resolved to nothing produced no taint")
	}
	if tt.Soname != "libghost.so.1" || !tt.Blocking {
		t.Errorf("taint = %+v, want it scoped to libghost.so.1 and blocking", *tt)
	}
	if tt.Global {
		t.Error("an unresolved soname is not a global blocker")
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints should hold only global ones, got %v", g.BlockingTaints())
	}
	if n, _ := g.Node("/usr/bin/app"); n.Needed["libghost.so.1"] != "" {
		t.Errorf("unresolved soname recorded as %q", n.Needed["libghost.so.1"])
	}
}

// TestABIMustMatch: a multiarch image carries an i386 and an x86-64 copy of the
// same soname. Picking either one by name alone links a package into a closure
// it has nothing to do with.
func TestABIMustMatch(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/usr/lib/i386-linux-gnu/libz.so.1":   "",
		"/usr/lib/x86_64-linux-gnu/libz.so.1": "",
		"/usr/bin/app":                        "",
	})
	i386 := &Info{Class: elf.ELFCLASS32, Machine: elf.EM_386, Type: elf.ET_DYN, Dynamic: true}
	objs := fakeELF{
		"/usr/bin/app":                        exe("libz.so.1"),
		"/usr/lib/i386-linux-gnu/libz.so.1":   i386,
		"/usr/lib/x86_64-linux-gnu/libz.so.1": lib(),
	}
	// i386 sorts first, so a name-only match would find the wrong one.
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{
		Entrypoint: []string{"/usr/bin/app"},
		Env:        []string{"LD_LIBRARY_PATH=/usr/lib/i386-linux-gnu:/usr/lib/x86_64-linux-gnu"},
	}})

	reachable(t, g, "/usr/lib/x86_64-linux-gnu/libz.so.1")
	unreachable(t, g, "/usr/lib/i386-linux-gnu/libz.so.1")
}

func TestRPathIsInheritedButRunPathIsNot(t *testing.T) {
	files := map[string]string{
		"/opt/app/bin/app":     "",
		"/opt/app/lib/liba.so": "",
		"/opt/app/lib/libb.so": "",
	}
	// app has DT_RPATH=$ORIGIN/../lib; liba needs libb but names no path of
	// its own. Under DT_RPATH the child inherits the search list, so libb
	// resolves.
	app := exe("liba.so")
	app.RPath = []string{"$ORIGIN/../lib"}
	objs := fakeELF{
		"/opt/app/bin/app":     app,
		"/opt/app/lib/liba.so": lib("libb.so"),
		"/opt/app/lib/libb.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/opt/app/bin/app"}}})
	reachable(t, g, "/opt/app/lib/liba.so", "/opt/app/lib/libb.so")

	// Same tree, but the search list arrives as DT_RUNPATH. The linker does
	// not hand DT_RUNPATH down, so liba cannot find libb.
	app2 := exe("liba.so")
	app2.RunPath = []string{"$ORIGIN/../lib"}
	objs2 := fakeELF{
		"/opt/app/bin/app":     app2,
		"/opt/app/lib/liba.so": lib("libb.so"),
		"/opt/app/lib/libb.so": lib(),
	}
	g2 := build(t, tree(t, files), objs2, Options{Config: target.ImageConfig{Entrypoint: []string{"/opt/app/bin/app"}}})
	reachable(t, g2, "/opt/app/lib/liba.so")
	unreachable(t, g2, "/opt/app/lib/libb.so")
	if hasTaint(g2, TaintUnresolvedNeeded) == nil {
		t.Error("liba's unsatisfiable libb should be recorded, not silently dropped")
	}
}

// TestRunPathOverridesRPathOnTheSameObject: glibc ignores DT_RPATH entirely
// when DT_RUNPATH is present.
func TestRunPathOverridesRPathOnTheSameObject(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/opt/old/libz.so.1": "",
		"/opt/new/libz.so.1": "",
		"/usr/bin/app":       "",
	})
	app := exe("libz.so.1")
	app.RPath = []string{"/opt/old"}
	app.RunPath = []string{"/opt/new"}
	objs := fakeELF{
		"/usr/bin/app":       app,
		"/opt/old/libz.so.1": lib(),
		"/opt/new/libz.so.1": lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	reachable(t, g, "/opt/new/libz.so.1")
	unreachable(t, g, "/opt/old/libz.so.1")
}

func TestSearchOrderPrefersRPathOverTheDefaultDirs(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/opt/vendor/libssl.so.3": "",
		"/usr/lib/libssl.so.3":    "",
		"/usr/bin/app":            "",
	})
	app := exe("libssl.so.3")
	app.RPath = []string{"/opt/vendor"}
	objs := fakeELF{
		"/usr/bin/app":            app,
		"/opt/vendor/libssl.so.3": lib(),
		"/usr/lib/libssl.so.3":    lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	reachable(t, g, "/opt/vendor/libssl.so.3")
	unreachable(t, g, "/usr/lib/libssl.so.3")
}

func TestLdSoConfDirectoriesAreSearched(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/etc/ld.so.conf":               "include /etc/ld.so.conf.d/*.conf\n# a comment\n",
		"/etc/ld.so.conf.d/vendor.conf": "/opt/vendor/lib\n",
		"/opt/vendor/lib/libv.so.1":     "",
		"/usr/bin/app":                  "",
	})
	objs := fakeELF{
		"/usr/bin/app":              exe("libv.so.1"),
		"/opt/vendor/lib/libv.so.1": lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	reachable(t, g, "/opt/vendor/lib/libv.so.1")
}

// TestUsrMergeCanonicalization is the constraint that makes package file lists
// usable at all: dpkg and rpm record /lib/x86_64-linux-gnu/libc.so.6 on systems
// where /lib is a symlink into /usr. Comparing that string against a walked
// tree finds nothing, and finding nothing reads as "this package ships no
// code" -- a clean bill of health produced by a symlink.
func TestUsrMergeCanonicalization(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/usr/lib/x86_64-linux-gnu/libc.so.6": "",
		"/usr/bin/app":                        "",
		"/lib":                                "->usr/lib",
	})
	objs := fakeELF{
		"/usr/bin/app":                        exe("libc.so.6"),
		"/usr/lib/x86_64-linux-gnu/libc.so.6": lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	const dpkgPath = "/lib/x86_64-linux-gnu/libc.so.6"
	if got := g.Canon(dpkgPath); got != "/usr/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("Canon(%q) = %q", dpkgPath, got)
	}
	if !g.Reachable(dpkgPath) {
		t.Errorf("the path dpkg records for libc does not resolve to the reachable node")
	}

	// And the same for a whole file list, which is how the OS plugin asks.
	fset := g.Classify([]string{dpkgPath, "/usr/share/doc/libc6/copyright", "/lib/x86_64-linux-gnu"})
	if len(fset.ELF) != 1 || fset.ELF[0] != "/usr/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("Classify ELF = %v", fset.ELF)
	}
	if len(fset.Reachable) != 1 {
		t.Errorf("Classify Reachable = %v", fset.Reachable)
	}
}

func TestClassifyIgnoresPackagesWithNoCode(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/share/zoneinfo/UTC": "", "/usr/bin/app": ""})
	g := build(t, fsys, fakeELF{"/usr/bin/app": exe()},
		Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	fset := g.Classify([]string{"/usr/share/zoneinfo/UTC"})
	if len(fset.ELF) != 0 || len(fset.Reachable) != 0 {
		t.Errorf("a data-only package should own no ELF: %+v", fset)
	}
}

func TestShellEntrypointRootsEveryExecutable(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/bin/sh":                   "",
		"/usr/bin/curl":             "",
		"/usr/bin/psql":             "",
		"/usr/lib/libq.so":          "",
		"/usr/lib/apt/methods/http": "",
		"/usr/lib/libtls.so.1":      "",
	})
	objs := fakeELF{
		"/bin/sh":          exe(),
		"/usr/bin/curl":    exe(),
		"/usr/bin/psql":    exe("libq.so"),
		"/usr/lib/libq.so": lib(),
		// A program well outside the PATH, forked by another program and
		// referenced by no DT_NEEDED. This is the shape that makes apt's
		// transport methods -- and the four libraries only they link -- look
		// like dead code to a PATH-only escalation.
		"/usr/lib/apt/methods/http": exe("libtls.so.1"),
		"/usr/lib/libtls.so.1":      lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{
		Entrypoint: []string{"/bin/sh", "-c", "exec /usr/bin/psql"},
	}})

	tt := hasTaint(g, TaintShellEntrypoint)
	if tt == nil {
		t.Fatal("a shell entrypoint was not recorded")
	}
	// The escalation is the conservative response; the taint itself does not
	// also have to block, or every image with a shell wrapper would answer
	// "cannot tell" about everything.
	if tt.Blocking {
		t.Error("shell-entrypoint escalates the roots; it should not also block")
	}
	reachable(t, g, "/bin/sh", "/usr/bin/curl", "/usr/bin/psql", "/usr/lib/libq.so",
		"/usr/lib/apt/methods/http", "/usr/lib/libtls.so.1")
}

// wrapperFixture is the shared tree for the exec-wrapper tests: the wrappers
// themselves, an application that links one library, and an off-PATH program
// (with a library only it links) that stands in for apt's transport methods.
// A precise closure leaves that off-PATH program dead; an escalation reaches it,
// so it is the discriminator between "saw through the wrapper" and "gave up and
// rooted everything".
func wrapperFixture(t *testing.T) (target.RootFS, fakeELF) {
	t.Helper()
	fsys := tree(t, map[string]string{
		"/usr/bin/tini":             "",
		"/usr/bin/gosu":             "",
		"/usr/bin/env":              "",
		"/usr/bin/app":              "",
		"/usr/lib/libq.so":          "",
		"/usr/lib/apt/methods/http": "",
		"/usr/lib/libtls.so.1":      "",
	})
	objs := fakeELF{
		"/usr/bin/tini":             exe(),
		"/usr/bin/gosu":             exe(),
		"/usr/bin/env":              exe(),
		"/usr/bin/app":              exe("libq.so"),
		"/usr/lib/libq.so":          lib(),
		"/usr/lib/apt/methods/http": exe("libtls.so.1"),
		"/usr/lib/libtls.so.1":      lib(),
	}
	return fsys, objs
}

// The init shims and privilege-drop wrappers exec a specific later argv token
// and load no application code of their own, so the closure roots the program
// they forward to and stays precise. Before this, an image run under tini or
// gosu escalated to rooting everything, which is most of what runs Java and Node
// in production.
func TestExecWrapperResolvesToRealEntrypoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"tini with separator", []string{"/usr/bin/tini", "--", "/usr/bin/app"}},
		{"tini without options", []string{"/usr/bin/tini", "/usr/bin/app"}},
		{"gosu drops privilege", []string{"gosu", "postgres", "/usr/bin/app"}},
		{"env with assignment", []string{"/usr/bin/env", "FOO=bar", "/usr/bin/app"}},
		{"env with flag", []string{"/usr/bin/env", "-i", "/usr/bin/app"}},
		{"nested tini then gosu", []string{"/usr/bin/tini", "--", "gosu", "postgres", "/usr/bin/app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys, objs := wrapperFixture(t)
			g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: tc.argv}})

			if tt := hasTaint(g, TaintShellEntrypoint); tt != nil {
				t.Errorf("wrapper was treated as a shell and escalated: %s", tt.Detail)
			}
			if tt := hasTaint(g, TaintNoEntrypoint); tt != nil {
				t.Errorf("wrapper left the entrypoint unresolved: %s", tt.Detail)
			}
			reachable(t, g, "/usr/bin/app", "/usr/lib/libq.so")
			// The off-PATH program stays dead, which it would not under an
			// escalation. That is the proof the closure stayed precise.
			unreachable(t, g, "/usr/lib/apt/methods/http", "/usr/lib/libtls.so.1")
		})
	}
}

// The parser only steps over argument shapes it is certain of. A wrapper used in
// a way it cannot read -- env -S, which re-splits a string; tini with options
// and no -- separator; gosu with no command -- is left in place, and the shell
// check escalates. Guessing here would risk rooting the wrong token and calling
// live code dead, so the ambiguous case has to fail closed.
func TestAmbiguousWrapperStillEscalates(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"env split-string", []string{"/usr/bin/env", "-S", "/usr/bin/app --flag"}},
		{"tini bare option", []string{"/usr/bin/tini", "-s", "/usr/bin/app"}},
		{"gosu without command", []string{"gosu", "postgres"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys, objs := wrapperFixture(t)
			g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: tc.argv}})

			if hasTaint(g, TaintShellEntrypoint) == nil {
				t.Fatal("an unparseable wrapper did not fall back to escalation")
			}
			// Escalation reaches the off-PATH program; that is the fail-closed
			// behavior the invariant depends on.
			reachable(t, g, "/usr/lib/apt/methods/http", "/usr/lib/libtls.so.1")
		})
	}
}

// A shell wrapper is not an exec wrapper: it runs arbitrary code and must still
// escalate even though the peeling ran first.
func TestShellScriptEntrypointStillEscalatesAfterPeeling(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/usr/bin/tini":             "",
		"/entrypoint.sh":            "",
		"/usr/lib/apt/methods/http": "",
	})
	objs := fakeELF{
		"/usr/bin/tini":             exe(),
		"/entrypoint.sh":            exe(),
		"/usr/lib/apt/methods/http": exe(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{
		Entrypoint: []string{"/usr/bin/tini", "--", "/entrypoint.sh"},
	}})

	if hasTaint(g, TaintShellEntrypoint) == nil {
		t.Fatal("a .sh script behind tini was not recognized as a shell entrypoint")
	}
	// tini was still peeled and rooted; the script behind it escalated.
	reachable(t, g, "/usr/bin/tini", "/usr/lib/apt/methods/http")
}

// TestEscalationRootsProgramsNotLibraries: "every executable is a root" has to
// mean every program anywhere, but it must not quietly mean every ELF file --
// an unused library is the finding this package exists to produce.
func TestEscalationRootsProgramsNotLibraries(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/libexec/helper": "", "/opt/vendor/libidle.so.1": ""})
	objs := fakeELF{"/usr/libexec/helper": exe(), "/opt/vendor/libidle.so.1": lib()}
	g := build(t, fsys, objs, Options{})

	reachable(t, g, "/usr/libexec/helper")
	unreachable(t, g, "/opt/vendor/libidle.so.1")
}

func TestNoEntrypointEscalates(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/bin/tool": "", "/usr/lib/libunused.so": ""})
	objs := fakeELF{"/usr/bin/tool": exe(), "/usr/lib/libunused.so": lib()}
	g := build(t, fsys, objs, Options{})

	if hasTaint(g, TaintNoEntrypoint) == nil {
		t.Fatal("an image config with no Entrypoint and no Cmd was not recorded")
	}
	reachable(t, g, "/usr/bin/tool")
	unreachable(t, g, "/usr/lib/libunused.so")
}

func TestMissingEntrypointEscalatesRatherThanFindingNothing(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/bin/tool": ""})
	g := build(t, tree(t, map[string]string{"/usr/bin/tool": ""}), fakeELF{"/usr/bin/tool": exe()},
		Options{Config: target.ImageConfig{Entrypoint: []string{"/app/server"}}})
	_ = fsys

	tt := hasTaint(g, TaintNoEntrypoint)
	if tt == nil {
		t.Fatal("an entrypoint that is not in the image was not recorded")
	}
	if !strings.Contains(tt.Detail, "/app/server") {
		t.Errorf("taint does not name the missing entrypoint: %s", tt.Detail)
	}
	reachable(t, g, "/usr/bin/tool")
}

func TestEntrypointResolvesThroughPATH(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/local/bin/server": "", "/usr/bin/server": ""})
	objs := fakeELF{"/usr/local/bin/server": exe(), "/usr/bin/server": exe()}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Cmd: []string{"server"}}})

	// The default PATH puts /usr/local/bin ahead of /usr/bin, and so does exec.
	if roots := g.Roots(); len(roots) != 1 || roots[0] != "/usr/local/bin/server" {
		t.Errorf("roots = %v, want just /usr/local/bin/server", roots)
	}
}

// pluginPaths are one object from each runtime-loaded plugin family, keyed by
// the soname of the library that opens it. The two with no loader are the
// families rooted unconditionally.
var pluginPaths = map[string][]string{
	"libc.so.6": {
		"/usr/lib/x86_64-linux-gnu/libnss_files.so.2",
		"/usr/lib/x86_64-linux-gnu/gconv/UTF-16.so",
	},
	"libpam.so.0": {
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
	},
	"libcrypto.so.3": {
		"/usr/lib/x86_64-linux-gnu/engines-3/afalg.so",
		"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so",
	},
	"": {
		"/app/node_modules/bcrypt/build/Release/bcrypt.node",
		"/usr/lib/python3/dist-packages/cryptography/hazmat/_rust.so",
		"/usr/lib/python3.11/lib-dynload/_ssl.so",
	},
}

// pluginTree builds an image holding every plugin in pluginPaths plus the three
// loader libraries, with the entrypoint needing whichever loaders are named.
func pluginTree(t *testing.T, needs ...string) *Graph {
	t.Helper()
	files := map[string]string{"/usr/bin/app": "", "/usr/lib/libplain.so": ""}
	objs := fakeELF{"/usr/bin/app": exe(needs...), "/usr/lib/libplain.so": lib()}
	for soname, paths := range pluginPaths {
		if soname != "" {
			p := "/usr/lib/x86_64-linux-gnu/" + soname
			files[p], objs[p] = "", lib()
		}
		for _, p := range paths {
			files[p], objs[p] = "", lib()
		}
	}
	return build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
}

// TestPluginsAreRootedWhenTheirLoaderIsReachable: nothing has a DT_NEEDED on an
// NSS module or an OpenSSL provider. A closure that only followed DT_NEEDED
// would call every one of them dead code, so once the library that opens them
// is in the closure they are rooted by name.
func TestPluginsAreRootedWhenTheirLoaderIsReachable(t *testing.T) {
	g := pluginTree(t, "libc.so.6", "libpam.so.0", "libcrypto.so.3")

	for _, paths := range pluginPaths {
		reachable(t, g, paths...)
	}
	if got := g.GatedPlugins(); len(got) != 0 {
		t.Errorf("GatedPlugins() = %+v with every loader reachable, want none", got)
	}
	// An ordinary library that nothing needs stays unreachable, or the rule
	// would have swallowed the whole point of the closure.
	unreachable(t, g, "/usr/lib/libplain.so")
}

// TestPluginsAreLeftOutWhenNothingCanOpenThem is the rule that makes the one
// above safe to apply as widely as it is.
//
// A plugin is opened by one library -- an NSS module by libc, a PAM module by
// libpam, an engine by libcrypto -- so an image whose closure reaches none of
// them contains no code that could open one. Rooting them anyway is not
// conservative, it is wrong: on a SLE BCI image with a pure-Go entrypoint the
// plugin roots drag libpam and libcrypto into a closure the entrypoint cannot
// reach, and those two then dlopen-taint every finding in the image.
func TestPluginsAreLeftOutWhenNothingCanOpenThem(t *testing.T) {
	g := pluginTree(t) // an entrypoint that needs nothing at all

	for soname, paths := range pluginPaths {
		if soname == "" {
			// No single library opens these, so they are still rooted.
			reachable(t, g, paths...)
			continue
		}
		unreachable(t, g, paths...)
		unreachable(t, g, "/usr/lib/x86_64-linux-gnu/"+soname)
	}

	gated := g.GatedPlugins()
	if len(gated) != 5 {
		t.Fatalf("GatedPlugins() = %+v, want the five plugins with a named loader", gated)
	}
	// Left out, but not left unsaid: the caller reports these, and it cannot if
	// the graph does not say which library was missing.
	for _, gp := range gated {
		if gp.What == "" || gp.Loader == "" {
			t.Errorf("gated plugin %+v does not say what it is or what would have opened it", gp)
		}
	}
}

// TestPluginAdmissionReachesAFixpoint: a loader can arrive through a plugin.
// libcrypto is here only because an NSS module needs it, and the NSS module is
// only a root because libc is reachable -- so a single admission pass would
// stop before the OpenSSL provider, and the closure would depend on the order
// the table happens to be written in.
func TestPluginAdmissionReachesAFixpoint(t *testing.T) {
	files := map[string]string{}
	objs := fakeELF{}
	add := func(p string, i *Info) { files[p], objs[p] = "", i }

	add("/usr/bin/app", exe("libc.so.6"))
	add("/usr/lib/x86_64-linux-gnu/libc.so.6", lib())
	add("/usr/lib/x86_64-linux-gnu/libnss_odd.so.2", lib("libcrypto.so.3"))
	add("/usr/lib/x86_64-linux-gnu/libcrypto.so.3", lib())
	add("/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so", lib())

	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	reachable(t, g,
		"/usr/lib/x86_64-linux-gnu/libnss_odd.so.2",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so",
	)
}

// TestEscalationAdmitsEveryPlugin: gating narrows an image that said what it
// runs, and nothing else. An image that did not say roots every program, which
// reaches the loaders, which admits the plugins -- so the case the gating could
// be wrong about is exactly the case it does not apply to.
func TestEscalationAdmitsEveryPlugin(t *testing.T) {
	files := map[string]string{
		"/usr/bin/other":                                 "",
		"/usr/lib/x86_64-linux-gnu/libpam.so.0":          "",
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so": "",
	}
	objs := fakeELF{
		"/usr/bin/other":                                 exe("libpam.so.0"),
		"/usr/lib/x86_64-linux-gnu/libpam.so.0":          lib(),
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so": lib(),
	}
	// No entrypoint at all, so every program is a root.
	g := build(t, tree(t, files), objs, Options{})

	reachable(t, g, "/usr/lib/x86_64-linux-gnu/security/pam_unix.so")
	if got := g.GatedPlugins(); len(got) != 0 {
		t.Errorf("GatedPlugins() = %+v under escalation, want none", got)
	}
}

// TestAPluginRootedAnotherWayIsNotReportedAsLeftOut: --roots names a PAM module
// in an image that loads no libpam. It is a root, so it is reachable -- and it
// must not also be listed as something no loader could open, because the
// evidence would then contradict the closure it is attached to.
func TestAPluginRootedAnotherWayIsNotReportedAsLeftOut(t *testing.T) {
	const mod = "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"
	files := map[string]string{"/usr/bin/app": "", mod: ""}
	objs := fakeELF{"/usr/bin/app": exe(), mod: lib()}

	g := build(t, tree(t, files), objs, Options{
		Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		Roots:  []string{mod},
	})

	reachable(t, g, mod)
	if got := g.GatedPlugins(); len(got) != 0 {
		t.Errorf("GatedPlugins() = %+v for a module --roots put in the closure", got)
	}
}

// TestSonameStemMatchingDoesNotOverreach: libcryptsetup is not libcrypto, and a
// prefix test that thought it was would admit every OpenSSL provider in an
// image that has no OpenSSL in its closure at all.
func TestSonameStemMatchingDoesNotOverreach(t *testing.T) {
	tests := []struct {
		soname, stem string
		want         bool
	}{
		{"libcrypto.so", "libcrypto.so", true},
		{"libcrypto.so.3", "libcrypto.so", true},
		{"libcrypto.so.1.1", "libcrypto.so", true},
		{"libcryptsetup.so.12", "libcrypto.so", false},
		{"libc.so.6", "libc.so", true},
		{"libcap.so.2", "libc.so", false},
		{"libcurl.so.4", "libc.so", false},
		{"libpam.so.0.84.2", "libpam.so", true},
		{"libpam_misc.so.0", "libpam.so", false},
	}
	for _, tt := range tests {
		if got := matchesSoname(tt.soname, tt.stem); got != tt.want {
			t.Errorf("matchesSoname(%q, %q) = %v, want %v", tt.soname, tt.stem, got, tt.want)
		}
	}
}

func TestDlopenTaint(t *testing.T) {
	files := map[string]string{"/usr/bin/app": "", "/usr/lib/libplug.so": ""}
	plug := lib()
	plug.Dlopen = true
	objs := fakeELF{"/usr/bin/app": exe("libplug.so"), "/usr/lib/libplug.so": plug}

	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	tt := hasTaint(g, TaintDlopen)
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("dlopen taint = %+v, want a global blocker by default", tt)
	}

	// --dlopen-policy=assume-none is the user asserting the risk away. The
	// observation is still recorded: the record is what makes the assertion
	// auditable later.
	g2 := build(t, tree(t, files), objs, Options{
		Config:       target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		DlopenPolicy: DlopenAssumeNone,
	})
	tt2 := hasTaint(g2, TaintDlopen)
	if tt2 == nil {
		t.Fatal("assume-none dropped the observation entirely")
	}
	if tt2.Blocking || tt2.Global {
		t.Errorf("assume-none left the taint blocking: %+v", *tt2)
	}
	if len(g2.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints = %v under assume-none", g2.BlockingTaints())
	}
	// Discharged, not merely non-blocking: this one would have blocked, and a
	// reader has to be able to see that the clean rests on the assertion.
	if !tt2.Discharged {
		t.Errorf("assume-none demoted the taint without marking it discharged: %+v", *tt2)
	}
	if !strings.Contains(tt2.Detail, "assume-none") {
		t.Errorf("detail does not say the policy is what demoted it: %q", tt2.Detail)
	}
	if tt.Discharged {
		t.Errorf("the default-policy taint is marked discharged: %+v", *tt)
	}
}

// TestUnreachableDlopenDoesNotTaint: a plugin loader sitting unused on disk
// says nothing about what the running program does.
func TestUnreachableDlopenDoesNotTaint(t *testing.T) {
	plug := lib()
	plug.Dlopen = true
	g := build(t, tree(t, map[string]string{"/usr/bin/app": "", "/usr/lib/libplug.so": ""}),
		fakeELF{"/usr/bin/app": exe(), "/usr/lib/libplug.so": plug},
		Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	if tt := hasTaint(g, TaintDlopen); tt != nil {
		t.Errorf("an unreachable dlopen caller tainted the graph: %+v", *tt)
	}
}

// dlopenTaintFor returns the dlopen taint raised by a specific caller, since a
// graph with more than one dlopen caller carries more than one such taint and
// hasTaint would return whichever came first.
func dlopenTaintFor(g *Graph, path string) *Taint {
	for i := range g.Taints() {
		if t := g.Taints()[i]; t.Kind == TaintDlopen && t.Path == path {
			return &t
		}
	}
	return nil
}

// libcryptoCaller is an OpenSSL libcrypto: a dynamic object that imports dlopen
// (to load providers and engines) and declares the libcrypto soname the
// allowlist matches on.
func libcryptoCaller(needed ...string) *Info {
	i := lib(needed...)
	i.Dlopen = true
	i.Soname = "libcrypto.so.3"
	return i
}

// TestBoundedLoaderDlopenDischarged: libcrypto calls dlopen, but only to load
// providers and engines from ossl-modules/engines directories vexscan already
// roots and walks. Everything it can reach is therefore already in the closure,
// so its dlopen taint is recorded rather than allowed to block -- without any
// blanket assume-none over other callers.
func TestBoundedLoaderDlopenDischarged(t *testing.T) {
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
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/x86_64-linux-gnu/libcrypto.so.3")
	if tt == nil {
		t.Fatal("libcrypto raised no dlopen taint at all")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("a bounded loader still blocks: %+v", *tt)
	}
	// Discharged, not merely non-blocking: it would have blocked globally, and
	// the analysis answered it. A reader has to see the clean rests on that.
	if !tt.Discharged {
		t.Errorf("bounded loader demoted without being marked discharged: %+v", *tt)
	}
	if !strings.Contains(tt.Detail, "OpenSSL") || !strings.Contains(tt.Detail, "ossl-modules") {
		t.Errorf("detail does not name the family and its dirs: %q", tt.Detail)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints() = %v, want none", g.BlockingTaints())
	}
}

// TestBoundedLoaderRedirectStaysBlocking: the bound holds only while nothing
// points the loader outside its known dirs. Each of OpenSSL's redirect
// environment variables, set in the image config, means a provider or engine
// could come from a directory nothing rooted -- so the closure is a lower bound
// again and the taint must keep blocking.
func TestBoundedLoaderRedirectStaysBlocking(t *testing.T) {
	for _, env := range []string{
		"OPENSSL_MODULES=/opt/mods",
		"OPENSSL_ENGINES=/opt/engines",
		"OPENSSL_CONF=/opt/openssl.cnf",
	} {
		t.Run(env, func(t *testing.T) {
			files := map[string]string{
				"/usr/bin/app":                    "",
				"/usr/lib/libcrypto.so.3":         "",
				"/usr/lib/ossl-modules/legacy.so": "",
			}
			objs := fakeELF{
				"/usr/bin/app":                    exe("libcrypto.so.3"),
				"/usr/lib/libcrypto.so.3":         libcryptoCaller(),
				"/usr/lib/ossl-modules/legacy.so": lib(),
			}
			g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{
				Entrypoint: []string{"/usr/bin/app"},
				Env:        []string{env},
			}})

			tt := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
			if tt == nil || !tt.Blocking || !tt.Global {
				t.Fatalf("with %s set, dlopen taint = %+v, want a global blocker", env, tt)
			}
			if len(g.BlockingTaints()) == 0 {
				t.Errorf("with %s set, BlockingTaints() is empty", env)
			}
		})
	}
}

// TestUnrecognisedDlopenCallerStaysBlocking: the discharge is keyed to a strict
// soname allowlist, not to a plugin directory being present. A library that is
// not a recognised loader keeps the global block even in an image whose
// ossl-modules dir is fully rooted, because being installed next to plugins
// says nothing about what a library dlopens.
func TestUnrecognisedDlopenCallerStaysBlocking(t *testing.T) {
	other := lib()
	other.Dlopen = true
	other.Soname = "libplugthing.so.1"
	files := map[string]string{
		"/usr/bin/app":                    "",
		"/usr/lib/libplugthing.so.1":      "",
		"/usr/lib/ossl-modules/legacy.so": "",
	}
	objs := fakeELF{
		"/usr/bin/app":                    exe("libplugthing.so.1"),
		"/usr/lib/libplugthing.so.1":      other,
		"/usr/lib/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libplugthing.so.1")
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("unrecognised loader dlopen taint = %+v, want a global blocker", tt)
	}
}

// TestBoundedLoaderWithoutPluginDirStaysBlocking: the discharge rests on the
// plugins actually having been rooted here, not on their being rooted in some
// canonical image. A libcrypto with no ossl-modules or engines directory on
// disk roots no providers, so there is nothing to prove the closure is complete
// and the taint keeps blocking.
func TestBoundedLoaderWithoutPluginDirStaysBlocking(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":            "",
		"/usr/lib/libcrypto.so.3": "",
	}
	objs := fakeELF{
		"/usr/bin/app":            exe("libcrypto.so.3"),
		"/usr/lib/libcrypto.so.3": libcryptoCaller(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("libcrypto with no plugin dir = %+v, want a global blocker", tt)
	}
}

// TestBoundedLoaderMixedWithUnrecognisedCaller: the taint is per-caller, so a
// discharged bounded loader does not clear the image while an unrecognised
// caller is also reachable. The application binary here dlopens too, and it can
// load anything, so the global block survives -- exactly the composition that
// makes discharging individual loaders safe.
func TestBoundedLoaderMixedWithUnrecognisedCaller(t *testing.T) {
	app := exe("libcrypto.so.3")
	app.Dlopen = true // the app itself calls dlopen, and it is not a known loader
	files := map[string]string{
		"/usr/bin/app":                    "",
		"/usr/lib/libcrypto.so.3":         "",
		"/usr/lib/ossl-modules/legacy.so": "",
	}
	objs := fakeELF{
		"/usr/bin/app":                    app,
		"/usr/lib/libcrypto.so.3":         libcryptoCaller(),
		"/usr/lib/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	crypto := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
	if crypto == nil || crypto.Blocking || crypto.Global {
		t.Errorf("libcrypto was not discharged in the mixed image: %+v", crypto)
	}
	appTaint := dlopenTaintFor(g, "/usr/bin/app")
	if appTaint == nil || !appTaint.Blocking || !appTaint.Global {
		t.Fatalf("app dlopen taint = %+v, want a global blocker", appTaint)
	}
	if len(g.BlockingTaints()) == 0 {
		t.Error("the global block did not survive an unrecognised caller")
	}
}

// TestBoundedLoaderConfigOverrideStaysBlocking: an environment variable is not
// the only way to point OpenSSL outside its rooted dirs -- openssl.cnf can name
// a provider or engine by absolute path with no variable set, and the dlopen
// taint is what guards against exactly that. A config that could do so keeps the
// caller blocking even when the dirs are rooted and no env is set. The path
// varies by distribution: Debian/SUSE/Alpine at /etc/ssl, RHEL/UBI at
// /etc/pki/tls, and the guard must read whichever the image actually ships.
func TestBoundedLoaderConfigOverrideStaysBlocking(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		cnf  string
	}{
		{"provider module path", "/etc/ssl/openssl.cnf", "[legacy_sect]\nmodule = /opt/legacy.so\nactivate = 1\n"},
		{"dynamic engine path", "/etc/ssl/openssl.cnf", "[engine_sect]\ndynamic_path = /opt/eng.so\n"},
		{"modulesdir override", "/etc/ssl/openssl.cnf", "[provider_sect]\nMODULESDIR = /opt/modules\n"},
		{"include delegates", "/etc/ssl/openssl.cnf", ".include /etc/ssl/extra.cnf\n"},
		// RHEL/UBI family: OPENSSLDIR=/etc/pki/tls, and no /etc/ssl/openssl.cnf
		// exists. Reading only the Debian paths would miss this entirely and
		// discharge on the whole enterprise base-image family.
		{"rhel openssldir", "/etc/pki/tls/openssl.cnf", "[legacy_sect]\nmodule = /usr/lib64/foo.so\n"},
		// NCONF joins a line ending in backslash with the next, so a directive
		// split across two physical lines is one directive at load time and a
		// per-physical-line scan would match neither half.
		{"line continuation", "/etc/ssl/openssl.cnf", "[engine_sect]\ndynamic_pa\\\nth = /evil.so\n"},
		// A dynamic engine can be aimed with SO_PATH instead of dynamic_path.
		{"engine so_path", "/etc/ssl/openssl.cnf", "[foo_engine]\nSO_PATH = /evil.so\nLOAD\n"},
		// A vendor ctrl directive under any key still resolves to an absolute
		// shared object the closure never walked.
		{"absolute so value", "/etc/ssl/openssl.cnf", "[foo_engine]\nvendor_ctrl = /opt/pkcs11.so.1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"/usr/bin/app":                    "",
				"/usr/lib/libcrypto.so.3":         "",
				"/usr/lib/ossl-modules/legacy.so": "",
				tc.path:                           tc.cnf,
			}
			objs := fakeELF{
				"/usr/bin/app":                    exe("libcrypto.so.3"),
				"/usr/lib/libcrypto.so.3":         libcryptoCaller(),
				"/usr/lib/ossl-modules/legacy.so": lib(),
			}
			g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

			tt := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
			if tt == nil || !tt.Blocking || !tt.Global {
				t.Fatalf("with an overriding config, dlopen taint = %+v, want a global blocker", tt)
			}
		})
	}
}

// TestBoundedLoaderRhelNoConfigStillDischarges: an absent config is not an
// override -- OpenSSL falls back to name-based loading from the compiled-in
// modulesdir, which is rooted. A RHEL-layout image that ships no openssl.cnf at
// any known path must still discharge, or adding the RHEL path would just turn
// the whole enterprise family into a permanent block.
func TestBoundedLoaderRhelNoConfigStillDischarges(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":                      "",
		"/usr/lib64/libcrypto.so.3":         "",
		"/usr/lib64/ossl-modules/legacy.so": "",
	}
	objs := fakeELF{
		"/usr/bin/app":                      exe("libcrypto.so.3"),
		"/usr/lib64/libcrypto.so.3":         libcryptoCaller(),
		"/usr/lib64/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib64/libcrypto.so.3")
	if tt == nil {
		t.Fatal("libcrypto raised no dlopen taint at all")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("a RHEL image with no openssl.cnf kept the loader blocking: %+v", *tt)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints() = %v, want none", g.BlockingTaints())
	}
}

// TestBoundedLoaderNameOnlyConfigStillDischarges: the guard must not be so blunt
// that a stock openssl.cnf blocks. The default config activates providers by
// name, which maps into the rooted dirs -- the assumption vexscan already makes
// -- so a config with no absolute module path still discharges.
func TestBoundedLoaderNameOnlyConfigStillDischarges(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":                    "",
		"/usr/lib/libcrypto.so.3":         "",
		"/usr/lib/ossl-modules/legacy.so": "",
		"/etc/ssl/openssl.cnf": "# stock config\n" +
			"[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n" +
			"[default_sect]\nactivate = 1\n[legacy_sect]\nactivate = 1\n",
	}
	objs := fakeELF{
		"/usr/bin/app":                    exe("libcrypto.so.3"),
		"/usr/lib/libcrypto.so.3":         libcryptoCaller(),
		"/usr/lib/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
	if tt == nil {
		t.Fatal("libcrypto raised no dlopen taint at all")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("a name-only config kept the loader blocking: %+v", *tt)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints() = %v, want none", g.BlockingTaints())
	}
}

// TestBoundedLoaderUnreadableConfigStaysBlocking: a config that is there but
// cannot be read is the one case where the scan learns nothing, and "learned
// nothing" must not be spelled the same as "found nothing". Reading it as clean
// would make an unreadable openssl.cnf strictly better for the image's score
// than a readable one, which is the incentive exactly backwards.
func TestBoundedLoaderUnreadableConfigStaysBlocking(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":                    "",
		"/usr/lib/libcrypto.so.3":         "",
		"/usr/lib/ossl-modules/legacy.so": "",
		// A directory where the config should be: present, and ReadFile fails
		// with something that is not fs.ErrNotExist. Standing in for any
		// unreadable config without depending on the uid the tests run as.
		"/etc/ssl/openssl.cnf/placeholder": "x",
	}
	objs := fakeELF{
		"/usr/bin/app":                    exe("libcrypto.so.3"),
		"/usr/lib/libcrypto.so.3":         libcryptoCaller(),
		"/usr/lib/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("with an unreadable openssl.cnf, dlopen taint = %+v, want a global blocker", tt)
	}
	if len(g.BlockingTaints()) == 0 {
		t.Error("BlockingTaints() is empty despite a config that could not be checked")
	}
}

// TestBoundedLoaderScansEveryConfigPath: OPENSSLDIR differs by distro family, so
// vexscan does not know which of the candidate paths is the one OpenSSL will
// read -- it reads all of them. An image can carry a stale /etc/ssl/openssl.cnf
// from a base layer beside the /etc/pki/tls/openssl.cnf its OpenSSL actually
// loads, and stopping at the first file found would let the stale clean one
// shadow the live redirecting one.
func TestBoundedLoaderScansEveryConfigPath(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":                    "",
		"/usr/lib/libcrypto.so.3":         "",
		"/usr/lib/ossl-modules/legacy.so": "",
		// Scanned first, and entirely innocent.
		"/etc/ssl/openssl.cnf": "[provider_sect]\nlegacy = legacy_sect\n[legacy_sect]\nactivate = 1\n",
		// Scanned last, and points a provider outside the rooted dirs.
		"/etc/pki/tls/openssl.cnf": "[legacy_sect]\nmodule = /opt/legacy.so\n",
	}
	objs := fakeELF{
		"/usr/bin/app":                    exe("libcrypto.so.3"),
		"/usr/lib/libcrypto.so.3":         libcryptoCaller(),
		"/usr/lib/ossl-modules/legacy.so": lib(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libcrypto.so.3")
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("a clean config shadowed a redirecting one: dlopen taint = %+v, want a global blocker", tt)
	}
}

// libpamCaller is a libpam: it imports dlopen (to load PAM modules) and declares
// the soname the allowlist matches on.
func libpamCaller(needed ...string) *Info {
	i := lib(needed...)
	i.Dlopen = true
	i.Soname = "libpam.so.0"
	return i
}

// pamImage is the file and object layout shared by the PAM tests: an app linking
// libpam, and one module in the rooted security dir. Extra files -- the pam
// configuration under test -- are merged in.
func pamImage(extra map[string]string) (map[string]string, fakeELF) {
	files := map[string]string{
		"/usr/bin/app":                  "",
		"/usr/lib/libpam.so.0":          "",
		"/usr/lib/security/pam_unix.so": "",
		"/usr/lib/security/pam_deny.so": "",
	}
	for k, v := range extra {
		files[k] = v
	}
	return files, fakeELF{
		"/usr/bin/app":                  exe("libpam.so.0"),
		"/usr/lib/libpam.so.0":          libpamCaller(),
		"/usr/lib/security/pam_unix.so": lib(),
		"/usr/lib/security/pam_deny.so": lib(),
	}
}

// TestBoundedLoaderPamDischarged: libpam's module directory is compiled in and
// no environment variable moves it, so a stock pam.d -- every stanza naming its
// module bare -- means everything libpam can load is already rooted. This is the
// second-most common blocker after OpenSSL on any image built on a distro base,
// because libpam arrives with the base userland whether the workload uses it or
// not.
func TestBoundedLoaderPamDischarged(t *testing.T) {
	files, objs := pamImage(map[string]string{
		"/etc/pam.d/common-auth": "# stock\nauth\trequired\tpam_unix.so nullok\n" +
			"auth\t[success=1 default=ignore]\tpam_deny.so\n",
		"/etc/pam.d/other": "@include common-auth\n",
	})
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libpam.so.0")
	if tt == nil {
		t.Fatal("libpam raised no dlopen taint at all")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("a stock pam.d kept libpam blocking: %+v", *tt)
	}
	if !tt.Discharged {
		t.Errorf("libpam demoted without being marked discharged: %+v", *tt)
	}
	if !strings.Contains(tt.Detail, "PAM") || !strings.Contains(tt.Detail, "security") {
		t.Errorf("detail does not name the family and its dir: %q", tt.Detail)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints() = %v, want none", g.BlockingTaints())
	}
}

// TestBoundedLoaderPamAbsolutePathStaysBlocking: the one way out of PAM's bound
// is a stanza naming a module by absolute path, which libpam loads verbatim from
// a directory nothing rooted. Every place such a stanza can hide has to be read
// -- any file in /etc/pam.d, not just the service the workload happens to use,
// and the older /etc/pam.conf that a directory-based system still honours.
func TestBoundedLoaderPamAbsolutePathStaysBlocking(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"absolute module in a service file", map[string]string{
			"/etc/pam.d/sshd": "auth optional /opt/vendor/pam_vendor.so\n",
		}},
		// The scan must not stop at the first file: a clean common-auth beside a
		// redirecting one is still a redirecting image.
		{"absolute module in a second file", map[string]string{
			"/etc/pam.d/common-auth": "auth required pam_unix.so\n",
			"/etc/pam.d/sudo":        "session optional /usr/local/lib/pam_extra.so\n",
		}},
		{"absolute module in pam.conf", map[string]string{
			"/etc/pam.conf": "login auth required /opt/pam_vendor.so\n",
		}},
		// PAM honours a backslash continuation, so a stanza split across two
		// physical lines is one stanza at load time.
		{"line continuation", map[string]string{
			"/etc/pam.d/sshd": "auth optional /opt/ven\\\ndor.so\n",
		}},
		// A versioned soname is just as much an escape as a bare .so.
		{"versioned absolute module", map[string]string{
			"/etc/pam.d/sshd": "auth optional /opt/pam_vendor.so.1\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, objs := pamImage(tc.files)
			g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

			tt := dlopenTaintFor(g, "/usr/lib/libpam.so.0")
			if tt == nil || !tt.Blocking || !tt.Global {
				t.Fatalf("with an absolute module path, dlopen taint = %+v, want a global blocker", tt)
			}
			if len(g.BlockingTaints()) == 0 {
				t.Error("BlockingTaints() is empty despite a redirecting pam config")
			}
		})
	}
}

// TestBoundedLoaderPamNoConfigStillDischarges: absent configuration is not a
// redirect. A libpam with no stanzas anywhere loads no module at all, so there
// is nothing outside the closure for it to reach -- and treating "no pam.d" as
// an override would block every minimal image that links libpam without
// configuring it, which is most hardened images.
func TestBoundedLoaderPamNoConfigStillDischarges(t *testing.T) {
	files, objs := pamImage(nil)
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libpam.so.0")
	if tt == nil {
		t.Fatal("libpam raised no dlopen taint at all")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("an image with no pam config kept libpam blocking: %+v", *tt)
	}
}

// TestBoundedLoaderUnreadablePamStaysBlocking: the same fail-closed rule the
// OpenSSL scan follows, on the other family. Absent PAM configuration is not a
// redirect -- a libpam with no stanzas loads no module -- but configuration that
// exists and cannot be read is, because the scan cannot tell the two apart by
// looking, and only one of them is safe to discharge on.
func TestBoundedLoaderUnreadablePamStaysBlocking(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		// /etc/pam.d is a file, so the directory listing fails with something
		// that is not fs.ErrNotExist: the stanzas cannot be enumerated.
		{"pam.d cannot be listed", map[string]string{
			"/etc/pam.d": "not a directory",
		}},
		// /etc/pam.conf is a directory, so reading the file fails. A system with
		// a perfectly good /etc/pam.d still honours pam.conf, so an unreadable
		// one leaves a stanza the scan never saw.
		{"pam.conf cannot be read", map[string]string{
			"/etc/pam.d/common-auth":    "auth required pam_unix.so\n",
			"/etc/pam.conf/placeholder": "x",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, objs := pamImage(tc.files)
			g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

			tt := dlopenTaintFor(g, "/usr/lib/libpam.so.0")
			if tt == nil || !tt.Blocking || !tt.Global {
				t.Fatalf("with unreadable pam configuration, dlopen taint = %+v, want a global blocker", tt)
			}
			if len(g.BlockingTaints()) == 0 {
				t.Error("BlockingTaints() is empty despite pam configuration that could not be checked")
			}
		})
	}
}

// TestBoundedLoaderPamWithoutModuleDirStaysBlocking: the discharge rests on
// modules having actually been rooted here. A libpam with no security directory
// on disk roots none, so nothing demonstrates the closure is a complete account
// of what it loads, and the taint keeps blocking -- the same rule the OpenSSL
// family follows.
func TestBoundedLoaderPamWithoutModuleDirStaysBlocking(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":         "",
		"/usr/lib/libpam.so.0": "",
	}
	objs := fakeELF{
		"/usr/bin/app":         exe("libpam.so.0"),
		"/usr/lib/libpam.so.0": libpamCaller(),
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	tt := dlopenTaintFor(g, "/usr/lib/libpam.so.0")
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("libpam with no security dir = %+v, want a global blocker", tt)
	}
}

// TestStaticRootTaintsGlobally: on Alpine and distroless a static binary
// carries musl and openssl inside itself while the .so files sit unused. The
// closure would report those packages unreachable, and it would be wrong.
func TestStaticRootTaintsGlobally(t *testing.T) {
	static := &Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	g := build(t, tree(t, map[string]string{"/app/server": "", "/usr/lib/libssl.so.3": ""}),
		fakeELF{"/app/server": static, "/usr/lib/libssl.so.3": lib()},
		Options{Config: target.ImageConfig{Entrypoint: []string{"/app/server"}}})

	tt := hasTaint(g, TaintStaticELF)
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("static-elf taint = %+v, want a global blocker", tt)
	}
	if tt.Path != "/app/server" {
		t.Errorf("taint does not name the binary: %+v", *tt)
	}
}

// TestStaticUtilityIsRecordedButDoesNotBlock: every glibc distribution ships a
// statically linked ldconfig. If merely existing were enough to block, no
// Debian, Ubuntu or Red Hat image could ever produce a not_affected result --
// total conservatism bought with no safety, since what ldconfig carries inside
// it is glibc, and glibc is reachable in those images anyway.
func TestStaticUtilityIsRecordedButDoesNotBlock(t *testing.T) {
	static := &Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	g := build(t, tree(t, map[string]string{"/sbin/ldconfig": "", "/usr/bin/app": ""}),
		fakeELF{"/sbin/ldconfig": static, "/usr/bin/app": exe()},
		Options{Config: target.ImageConfig{Entrypoint: []string{"/bin/sh"}}})

	tt := hasTaint(g, TaintStaticELF)
	if tt == nil {
		t.Fatal("static binary was not recorded at all")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("a static non-entrypoint blocks conclusions: %+v", *tt)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints() = %v, want none", g.BlockingTaints())
	}
	// Not discharged: it never blocked, so nothing answered it. Marking it so
	// would put a static ldconfig in the evidence of every finding in every
	// glibc image, claiming a test that never ran.
	if tt.Discharged {
		t.Errorf("a taint that never blocked is marked discharged: %+v", *tt)
	}
}

// TestStaticRootDischargedByProbe: a static entrypoint a prober can account for
// -- a pure-Go CGO_ENABLED=0 build links no C library -- carries nothing
// hidden, so the taint is recorded rather than left to block. The prober is
// injected the same way ReadELF is, so no real Go binary is needed to exercise
// the discharge.
func TestStaticRootDischargedByProbe(t *testing.T) {
	static := &Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	opts := Options{
		Config: target.ImageConfig{Entrypoint: []string{"/app/server"}},
		StaticProber: func(_ target.RootFS, p string) (StaticProbe, bool) {
			if p != "/app/server" {
				return StaticProbe{}, false
			}
			return StaticProbe{Closed: true, Why: "it is a pure-Go binary built with CGO_ENABLED=0"}, true
		},
	}
	g := build(t, tree(t, map[string]string{"/app/server": "", "/usr/lib/libssl.so.3": ""}),
		fakeELF{"/app/server": static, "/usr/lib/libssl.so.3": lib()}, opts)

	tt := hasTaint(g, TaintStaticELF)
	if tt == nil {
		t.Fatal("a discharged static entrypoint must still be recorded")
	}
	if tt.Blocking || tt.Global {
		t.Errorf("prober said the binary is closed, but the taint still blocks: %+v", *tt)
	}
	if len(g.BlockingTaints()) != 0 {
		t.Errorf("BlockingTaints() = %v, want none once the entrypoint is discharged", g.BlockingTaints())
	}
	if !tt.Discharged {
		t.Errorf("a taint that would have blocked but for the probe is not marked discharged: %+v", *tt)
	}
	if !strings.Contains(tt.Detail, "CGO_ENABLED=0") {
		t.Errorf("detail does not record why the taint was discharged: %q", tt.Detail)
	}
}

// TestStaticRootProbeInconclusiveStillBlocks: a prober that cannot account for
// the binary -- a cgo build, an unrecognised file -- leaves the entrypoint
// blocking exactly as it would with no prober at all. The discharge is a
// narrowing of the conservative default, never a loosening of it.
func TestStaticRootProbeInconclusiveStillBlocks(t *testing.T) {
	static := &Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	opts := Options{
		Config:       target.ImageConfig{Entrypoint: []string{"/app/server"}},
		StaticProber: func(target.RootFS, string) (StaticProbe, bool) { return StaticProbe{}, false },
	}
	g := build(t, tree(t, map[string]string{"/app/server": "", "/usr/lib/libssl.so.3": ""}),
		fakeELF{"/app/server": static, "/usr/lib/libssl.so.3": lib()}, opts)

	tt := hasTaint(g, TaintStaticELF)
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("an unaccounted static entrypoint must stay a global blocker: %+v", tt)
	}
}

// TestStaticRootProbeWithNoReasonDoesNotDischarge: a probe that reports Closed
// without saying why is not a discharge. Honouring one would emit a
// non-blocking taint whose detail is byte-for-byte the blocking one's, leaving
// a filtered result indistinguishable from an unfiltered one -- the single
// failure mode the taint machinery exists to prevent.
func TestStaticRootProbeWithNoReasonDoesNotDischarge(t *testing.T) {
	static := &Info{Class: elf.ELFCLASS64, Machine: elf.EM_X86_64, Type: elf.ET_EXEC}
	files := map[string]string{"/app/server": "", "/usr/lib/libssl.so.3": ""}
	elves := func() fakeELF {
		return fakeELF{"/app/server": static, "/usr/lib/libssl.so.3": lib()}
	}
	cfg := target.ImageConfig{Entrypoint: []string{"/app/server"}}

	g := build(t, tree(t, files), elves(), Options{
		Config: cfg,
		StaticProber: func(target.RootFS, string) (StaticProbe, bool) {
			return StaticProbe{Closed: true}, true
		},
	})

	tt := hasTaint(g, TaintStaticELF)
	if tt == nil || !tt.Blocking || !tt.Global {
		t.Fatalf("a probe with no reason must leave the entrypoint blocking: %+v", tt)
	}

	// And it must read as an ordinary block, because that is what it is.
	plain := hasTaint(build(t, tree(t, files), elves(), Options{Config: cfg}), TaintStaticELF)
	if plain == nil {
		t.Fatal("unprobed run recorded no static-elf taint")
	}
	if tt.Detail != plain.Detail {
		t.Errorf("detail = %q, want the unprobed detail %q", tt.Detail, plain.Detail)
	}
}

// TestTheInterpreterIsReachable: ld.so is loaded by the kernel, not through
// DT_NEEDED, so nothing in the graph points at it. It belongs to glibc or musl
// -- the two packages most often asked about -- and reporting it unreachable in
// every image would be a systematic false negative.
func TestTheInterpreterIsReachable(t *testing.T) {
	fsys := tree(t, map[string]string{
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": "",
		"/lib64":       "->../usr/lib/x86_64-linux-gnu",
		"/usr/bin/app": "",
	})
	objs := fakeELF{
		"/usr/bin/app": exe(),
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": lib(),
	}
	g := build(t, fsys, objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})
	reachable(t, g, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
}

func TestExplicitRoots(t *testing.T) {
	fsys := tree(t, map[string]string{"/usr/bin/app": "", "/opt/job/runner": "", "/opt/job/libjob.so": ""})
	objs := fakeELF{
		"/usr/bin/app":       exe(),
		"/opt/job/runner":    exe("libjob.so"),
		"/opt/job/libjob.so": lib(),
	}
	runner := objs["/opt/job/runner"]
	runner.RunPath = []string{"$ORIGIN"}

	g := build(t, fsys, objs, Options{
		Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}},
		Roots:  []string{"/opt/job/runner"},
	})
	reachable(t, g, "/opt/job/runner", "/opt/job/libjob.so")
	if n, _ := g.Node("/opt/job/runner"); n.Why != "named by --roots" {
		t.Errorf("root reason = %q", n.Why)
	}
}

// A --roots path the closure cannot start from must block, not warn.
//
// The scenario is the one the exec taint sends users to: an entrypoint that can
// start another program, a user naming that program with --roots, and
// --exec-policy=assume-none to say the naming is complete. Mistype the path and
// the root is gone while the taint that was withholding conclusions is
// discharged -- so the run that concluded nothing and the run that concluded
// everything look the same. Nothing but this taint stands between the two.
func TestMissingRootBlocks(t *testing.T) {
	files := map[string]string{
		"/usr/bin/app":        "",
		"/opt/job/runner":     "",
		"/usr/bin/wrapper.sh": "#!/bin/sh\nexec app\n",
	}
	objs := fakeELF{"/usr/bin/app": exe(), "/opt/job/runner": exe()}
	cfg := target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}

	t.Run("absent path", func(t *testing.T) {
		g := build(t, tree(t, files), objs, Options{
			Config: cfg,
			Roots:  []string{"/opt/job/runnr"}, // one transposition from the real one
		})
		tt := hasTaint(g, TaintMissingRoot)
		if tt == nil {
			t.Fatalf("a --roots path naming nothing in the image raised no taint; taints are %v", g.Taints())
		}
		if !tt.Blocking {
			t.Error("the missing-root taint does not block, so a typo still buys conclusions")
		}
		if !tt.Global {
			t.Error("the missing-root taint is scoped; the root that went missing could have reached any package")
		}
		if !strings.Contains(tt.Detail, "/opt/job/runnr") {
			t.Errorf("detail does not name the path that failed: %q", tt.Detail)
		}
	})

	// The case that matters most: assume-none discharges the exec taint, and
	// this one has to survive that or the report is wrong and silent.
	t.Run("survives assume-none", func(t *testing.T) {
		g := build(t, tree(t, files), objs, Options{
			Config:     cfg,
			Roots:      []string{"/opt/job/runnr"},
			ExecPolicy: ExecAssumeNone,
		})
		if hasTaint(g, TaintMissingRoot) == nil || len(g.BlockingTaints()) == 0 {
			t.Fatalf("--exec-policy=assume-none cleared the missing root too; blocking taints are %v", g.BlockingTaints())
		}
	})

	// A file that is there but is not an ELF object is a different mistake --
	// pointing at the shell script rather than at what it runs -- and saying so
	// is the difference between a user fixing it and a user re-checking a path
	// that was never wrong.
	t.Run("present but not ELF", func(t *testing.T) {
		g := build(t, tree(t, files), objs, Options{
			Config: cfg,
			Roots:  []string{"/usr/bin/wrapper.sh"},
		})
		tt := hasTaint(g, TaintMissingRoot)
		if tt == nil {
			t.Fatalf("a --roots path that is not an ELF object raised no taint; taints are %v", g.Taints())
		}
		if !strings.Contains(tt.Detail, "not an ELF object") {
			t.Errorf("detail does not say the file was found but unusable: %q", tt.Detail)
		}
	})

	// The other direction. A root that resolves must not raise it, or every
	// correct run drowns in a warning and the taint stops meaning anything.
	t.Run("resolving root is clean", func(t *testing.T) {
		g := build(t, tree(t, files), objs, Options{
			Config: cfg,
			Roots:  []string{"/opt/job/runner"},
		})
		if tt := hasTaint(g, TaintMissingRoot); tt != nil {
			t.Errorf("a --roots path that resolved raised %v", tt)
		}
	})
}

// A missing root withholds not_present as well as not_in_execute_path: the
// program nobody could find may be the static binary carrying a copy of the
// vulnerable code, so the package's own symbol tables do not settle it either.
func TestMissingRootThreatensPresence(t *testing.T) {
	if !TaintMissingRoot.ThreatensPresence() {
		t.Error("TaintMissingRoot does not threaten presence, so an unfindable root still buys not_present")
	}
}

func TestNonELFFilesAreNotNodes(t *testing.T) {
	g := build(t, tree(t, map[string]string{
		"/usr/bin/app":        "",
		"/etc/hosts":          "127.0.0.1 localhost",
		"/usr/bin/wrapper.sh": "#!/bin/sh\nexec app\n",
	}), fakeELF{"/usr/bin/app": exe()}, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	if len(g.Nodes()) != 1 {
		t.Errorf("graph holds %d nodes, want only the one ELF file", len(g.Nodes()))
	}
	if _, ok := g.Node("/etc/hosts"); ok {
		t.Error("/etc/hosts is in the graph")
	}
}

func TestParseDlopenPolicy(t *testing.T) {
	for _, in := range []string{"", "taint", "assume-none"} {
		if _, err := ParseDlopenPolicy(in); err != nil {
			t.Errorf("ParseDlopenPolicy(%q) = %v", in, err)
		}
	}
	if _, err := ParseDlopenPolicy("ignore"); err == nil {
		t.Error("an unknown policy was accepted")
	}
}

// TestEscalationStandsDownForAssertedRoots pins the bargain in
// unknownEntrypoint. Escalation and a non-blocking taint go together: rooting
// every program cannot under-report, so nothing needs withholding. Dropping
// escalation is therefore allowed only against both halves of an assertion --
// roots that resolve, and --exec-policy=assume-none -- and the three ways of
// having only part of one must all still escalate.
func TestEscalationStandsDownForAssertedRoots(t *testing.T) {
	files := map[string]string{
		"/entry.sh":       "#!/bin/sh\nexec /usr/bin/app\n",
		"/bin/sh":         "",
		"/usr/bin/app":    "",
		"/usr/bin/unused": "",
	}
	objs := fakeELF{
		"/bin/sh":         exe(),
		"/usr/bin/app":    exe(),
		"/usr/bin/unused": exe(),
	}
	cfg := target.ImageConfig{Entrypoint: []string{"/bin/sh", "/entry.sh"}}

	escalated := func(g *Graph) int {
		n := 0
		for _, node := range g.Nodes() {
			if node.Kind == RootEscalated {
				n++
			}
		}
		return n
	}

	// The three partial assertions. Each must leave the over-approximation in
	// place: a narrow closure with nothing guarding it is how reachable code
	// gets reported as dead.
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"no assertion", Options{Config: cfg}},
		{"roots alone", Options{Config: cfg, Roots: []string{"/usr/bin/app"}}},
		{"assume-none alone", Options{Config: cfg, ExecPolicy: ExecAssumeNone}},
		// The interaction with TestMissingRootBlocks: a root that resolves to
		// nothing is not a root, so the assertion is not half-kept, it is
		// absent, and the closure must not narrow on the strength of it.
		{"unresolvable root with assume-none", Options{
			Config:     cfg,
			Roots:      []string{"/usr/bin/nope"},
			ExecPolicy: ExecAssumeNone,
		}},
	} {
		t.Run(tc.name+" still escalates", func(t *testing.T) {
			g := build(t, tree(t, files), objs, tc.opts)
			if escalated(g) == 0 {
				t.Fatalf("escalation stood down without both halves of the assertion; roots are %v", g.roots)
			}
			reachable(t, g, "/usr/bin/unused")
			tt := hasTaint(g, TaintShellEntrypoint)
			if tt == nil {
				t.Fatalf("no shell-entrypoint taint; taints are %v", g.Taints())
			}
			if tt.Discharged {
				t.Error("the taint reads as discharged, but nothing discharged it")
			}
		})
	}

	// A typo must still be caught on the way through, or the previous subtest
	// passes for the wrong reason -- escalating because the path was junk
	// rather than because the assertion was refused.
	t.Run("unresolvable root still blocks", func(t *testing.T) {
		g := build(t, tree(t, files), objs, Options{
			Config:     cfg,
			Roots:      []string{"/usr/bin/nope"},
			ExecPolicy: ExecAssumeNone,
		})
		if tt := hasTaint(g, TaintMissingRoot); tt == nil || !tt.Blocking {
			t.Fatalf("a --roots typo stopped blocking; taints are %v", g.Taints())
		}
	})

	t.Run("both halves stands down", func(t *testing.T) {
		g := build(t, tree(t, files), objs, Options{
			Config:     cfg,
			Roots:      []string{"/usr/bin/app"},
			ExecPolicy: ExecAssumeNone,
		})
		if n := escalated(g); n != 0 {
			t.Fatalf("still escalated %d program(s) despite both halves of the assertion", n)
		}
		reachable(t, g, "/usr/bin/app")
		// The whole point: a program the user did not name is no longer
		// treated as running.
		unreachable(t, g, "/usr/bin/unused")

		// Standing down must not make the reason disappear. The user has to be
		// able to see what their answer was spent on.
		tt := hasTaint(g, TaintShellEntrypoint)
		if tt == nil {
			t.Fatalf("the shell-entrypoint taint vanished; taints are %v", g.Taints())
		}
		if !tt.Discharged {
			t.Error("the taint is not marked discharged, so it reads as an open question")
		}
		if tt.Blocking {
			t.Error("the taint blocks despite the assertion that answers it")
		}
		if !strings.Contains(tt.Detail, "assume-none") || !strings.Contains(tt.Detail, "--roots") {
			t.Errorf("detail does not say which assertion it stood down for: %q", tt.Detail)
		}
	})
}
