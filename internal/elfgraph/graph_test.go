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

// TestPluginDirectoriesAreAlwaysRoots: nothing has a DT_NEEDED on an NSS module
// or an OpenSSL provider. A closure that only followed DT_NEEDED would call
// every one of them dead code.
func TestPluginDirectoriesAreAlwaysRoots(t *testing.T) {
	paths := []string{
		"/usr/lib/x86_64-linux-gnu/libnss_files.so.2",
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
		"/usr/lib/x86_64-linux-gnu/gconv/UTF-16.so",
		"/usr/lib/x86_64-linux-gnu/engines-3/afalg.so",
		"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so",
		"/app/node_modules/bcrypt/build/Release/bcrypt.node",
		"/usr/lib/python3/dist-packages/cryptography/hazmat/_rust.so",
		"/usr/lib/python3.11/lib-dynload/_ssl.so",
	}
	files := map[string]string{"/usr/bin/app": "", "/usr/lib/libplain.so": ""}
	objs := fakeELF{"/usr/bin/app": exe(), "/usr/lib/libplain.so": lib()}
	for _, p := range paths {
		files[p] = ""
		objs[p] = lib()
	}
	g := build(t, tree(t, files), objs, Options{Config: target.ImageConfig{Entrypoint: []string{"/usr/bin/app"}}})

	reachable(t, g, paths...)
	// An ordinary library that nothing needs stays unreachable, or the rule
	// would have swallowed the whole point of the closure.
	unreachable(t, g, "/usr/lib/libplain.so")
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
