package elfgraph

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// binDirs are where an escalated closure looks for executables to root at, on
// top of whatever the image config's PATH names.
var binDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin", "/opt/bin",
}

// shells are argv[0] basenames that run something other than themselves. The
// list is not exhaustive and does not need to be -- a shim that is missed just
// means a narrower closure rooted at the shim itself, and anything the shim
// launches that this package fails to reach shows up as a package with no
// reachable code, which is the conservative-in-the-wrong-direction case the
// list exists to prevent. Add to it freely.
var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true,
	"ksh": true, "csh": true, "fish": true, "busybox": true, "toybox": true,
	"tini": true, "tini-static": true, "dumb-init": true, "catatonit": true,
	"s6-svscan": true, "s6-supervise": true, "s6-overlay-suexec": true,
	"supervisord": true, "runit": true, "runsvdir": true,
	"env": true, "gosu": true, "su-exec": true, "setpriv": true,
	"runuser": true, "su": true, "sudo": true, "exec": true,
	"entrypoint": true, "start": true, "run": true,
}

// Options configures a closure build.
type Options struct {
	// Config is the image configuration. Entrypoint, Cmd, Env and WorkingDir
	// are all load-bearing: they decide the roots, the LD_LIBRARY_PATH, and how
	// a relative argv[0] resolves.
	Config target.ImageConfig

	// Roots are extra tree-absolute paths to treat as executed, from --roots.
	// This is the escape hatch for an image whose real entrypoint comes from
	// outside the config -- a Kubernetes command override, an init system.
	Roots []string

	// DlopenPolicy decides whether a reachable dlopen blocks conclusions.
	DlopenPolicy DlopenPolicy

	// ReadELF loads ELF metadata. Defaults to the debug/elf-backed reader.
	ReadELF Reader

	Logf func(string, ...any)
}

// Node is one ELF object in the image.
type Node struct {
	// Path is the tree-absolute path with every symlink already resolved, so
	// two names for one file are one node. Callers holding a path from
	// somewhere else -- a dpkg file list, say -- must put it through Canon
	// before looking it up, because dpkg records the pre-usrmerge /lib name for
	// files that now live under /usr/lib.
	Path string `json:"path"`

	Info *Info `json:"info"`

	// Root marks an object the closure starts from, with Why saying which rule
	// put it there and Kind saying how much that rule is worth.
	Root bool     `json:"root,omitempty"`
	Why  string   `json:"why,omitempty"`
	Kind RootKind `json:"root_kind,omitempty"`

	// Reachable is the answer this package exists to produce.
	Reachable bool `json:"reachable"`

	// Needed maps each DT_NEEDED soname to the node that satisfied it, or ""
	// when nothing did.
	Needed map[string]string `json:"needed,omitempty"`

	// NeededBy lists the objects that pulled this one in, which is the
	// explanation a reader wants when a finding says "reachable".
	NeededBy []string `json:"needed_by,omitempty"`
}

// RootKind ranks the reasons an object can be a root, because two of the
// conclusions this package draws depend on which reason applied.
type RootKind int

const (
	// RootPlugin is loaded by name at runtime -- an NSS module, an OpenSSL
	// provider. It is not a program, and asking whether it is "statically
	// linked" is a category error: it has no PT_INTERP because no shared
	// object does.
	RootPlugin RootKind = iota

	// RootEscalated is a program rooted only because the image does not say
	// what it runs.
	RootEscalated

	// RootExplicit is the image's own entrypoint, or a path the user named
	// with --roots. This is the image's actual purpose.
	RootExplicit
)

// Graph is the resolved shared-library closure of an image.
type Graph struct {
	fsys   target.RootFS
	config target.ImageConfig

	nodes  map[string]*Node
	order  []string
	roots  []string
	taints []Taint
}

// Build indexes every ELF object in the tree and resolves the closure rooted at
// what the image runs.
func Build(fsys target.RootFS, opts Options) (*Graph, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.ReadELF == nil {
		opts.ReadELF = ReadELF
	}
	if opts.DlopenPolicy == "" {
		opts.DlopenPolicy = DlopenTaint
	}

	g := &Graph{fsys: fsys, config: opts.Config, nodes: map[string]*Node{}}
	if err := g.index(opts); err != nil {
		return nil, err
	}
	opts.Logf("  %d ELF objects", len(g.order))

	g.markRoots(opts)
	g.walkClosure(opts)
	g.collectTaints(opts)

	opts.Logf("  %d of %d reachable from %d roots", g.CountReachable(), len(g.order), len(g.roots))
	return g, nil
}

// index finds every ELF object in the tree.
func (g *Graph) index(opts Options) error {
	err := g.fsys.Walk("/", func(name string, d fs.DirEntry) error {
		if d.IsDir() {
			if target.IsKernelFS(name) {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks are not read: Walk never follows them, so every regular
		// file is visited exactly once under its symlink-free path, and that
		// path is what a node is keyed by.
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := opts.ReadELF(g.fsys, name)
		if err != nil {
			if errors.Is(err, ErrNotELF) {
				return nil
			}
			// A file with ELF magic that will not parse. Not fatal -- one bad
			// object should not fail a whole image -- but worth saying, since
			// its dependencies are now unknown.
			opts.Logf("  ! %v", err)
			return nil
		}
		g.nodes[name] = &Node{Path: name, Info: info, Needed: map[string]string{}}
		g.order = append(g.order, name)
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking image filesystem: %w", err)
	}
	sort.Strings(g.order)
	return nil
}

// markRoots decides where execution starts.
func (g *Graph) markRoots(opts Options) {
	// Plugin directories are rooted unconditionally. Nothing has a DT_NEEDED
	// on an NSS module or a PAM module -- they are found by name at runtime --
	// so a closure that only followed DT_NEEDED would report every one of them
	// as dead code, which is exactly backwards.
	for _, p := range g.order {
		if why, ok := alwaysRoot(p); ok {
			g.addRoot(p, why, RootPlugin)
		}
	}

	for _, r := range opts.Roots {
		c := g.Canon(r)
		if _, ok := g.nodes[c]; !ok {
			opts.Logf("  ! --roots %s is not an ELF object in this image", r)
			continue
		}
		g.addRoot(c, "named by --roots", RootExplicit)
	}

	argv := opts.Config.Argv()
	if len(argv) == 0 {
		g.taints = append(g.taints, Taint{
			Kind:   TaintNoEntrypoint,
			Detail: "nothing declares an entrypoint -- no image config, or one that sets neither Entrypoint nor Cmd -- so every executable is treated as a root; name the real ones with --roots",
		})
		g.escalate(opts, "no entrypoint")
		return
	}

	argv0 := argv[0]
	base := path.Base(argv0)
	if shells[base] || strings.HasSuffix(base, ".sh") {
		g.taints = append(g.taints, Taint{
			Kind:   TaintShellEntrypoint,
			Detail: fmt.Sprintf("entrypoint %q runs something other than itself, so every executable is treated as a root", strings.Join(argv, " ")),
			Path:   argv0,
		})
		g.escalate(opts, "shell entrypoint")
		// The shim itself is still executed.
		if p, ok := g.lookupCommand(opts, argv0); ok {
			g.addRoot(p, "entrypoint", RootExplicit)
		}
		return
	}

	p, ok := g.lookupCommand(opts, argv0)
	if !ok {
		g.taints = append(g.taints, Taint{
			Kind:   TaintNoEntrypoint,
			Detail: fmt.Sprintf("entrypoint %q is not an ELF object in this image, so every executable is treated as a root", argv0),
			Path:   argv0,
		})
		g.escalate(opts, "unresolvable entrypoint")
		return
	}
	g.addRoot(p, "entrypoint", RootExplicit)

	// Later argv elements are arguments, not programs -- except for the common
	// wrapper shapes, which the shell check above already caught.
}

// escalate roots every program in the image. This is what an unknown
// entrypoint costs: a much larger closure, and far fewer packages that can be
// shown to be unreachable.
//
// "Every program" rather than "everything on the PATH" because the PATH is not
// where the interesting ones live. In debian:12 the only objects that link
// gnutls, p11-kit, idn2 and hogweed are apt's transport methods in
// /usr/lib/apt/methods -- forked by apt, named in no PATH, referenced by no
// DT_NEEDED. A PATH-only escalation reports four packages as unreachable that
// a single `apt-get update` would load.
func (g *Graph) escalate(opts Options, why string) {
	dirs := map[string]bool{}
	for _, d := range binDirs {
		dirs[d] = true
	}
	for _, d := range opts.Config.PathDirs() {
		dirs[d] = true
	}
	for _, p := range g.order {
		if g.nodes[p].Info.IsProgram() || dirs[path.Dir(p)] {
			g.addRoot(p, why, RootEscalated)
		}
	}
}

// lookupCommand resolves an argv[0] the way exec would: through PATH when it
// has no slash, against WorkingDir when it is relative.
func (g *Graph) lookupCommand(opts Options, argv0 string) (string, bool) {
	if strings.Contains(argv0, "/") {
		base := argv0
		if !path.IsAbs(base) {
			wd := opts.Config.WorkingDir
			if wd == "" {
				wd = "/"
			}
			base = path.Join(wd, base)
		}
		c := g.Canon(base)
		_, ok := g.nodes[c]
		return c, ok
	}
	for _, dir := range opts.Config.PathDirs() {
		c := g.Canon(path.Join(dir, argv0))
		if _, ok := g.nodes[c]; ok {
			return c, true
		}
	}
	return "", false
}

func (g *Graph) addRoot(p, why string, kind RootKind) {
	n := g.nodes[p]
	if n == nil {
		return
	}
	// A file can be rooted twice: an OpenSSL provider that is also on the
	// PATH, or -- the case that matters -- an entrypoint that the shell
	// escalation already swept up before the entrypoint itself was resolved.
	// The strongest reason wins, so a static entrypoint is still recognized as
	// the entrypoint.
	if n.Root && kind <= n.Kind {
		return
	}
	if !n.Root {
		g.roots = append(g.roots, p)
	}
	n.Root, n.Why, n.Kind = true, why, kind
}

// walkClosure resolves DT_NEEDED breadth-first from the roots.
func (g *Graph) walkClosure(opts Options) {
	sort.Strings(g.roots)

	type frame struct {
		path string
		// rpath is the expanded DT_RPATH inherited from the loading chain.
		rpath []string
	}
	queue := make([]frame, 0, len(g.roots))
	for _, r := range g.roots {
		queue = append(queue, frame{path: r})
	}

	ldconf := ldSoConf(g.fsys)
	ldLibraryPath := splitPathList(envValue(opts.Config, "LD_LIBRARY_PATH"))

	seen := map[string]bool{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur.path] {
			// A node reached twice keeps the inherited rpath from its first
			// arrival. The two can differ, and the second one is dropped --
			// which can only lose a resolution, never invent one, so the
			// error direction is an unresolved-needed taint rather than a
			// spuriously satisfied dependency.
			continue
		}
		seen[cur.path] = true

		n := g.nodes[cur.path]
		if n == nil {
			continue
		}
		n.Reachable = true

		// The program interpreter is loaded by the kernel, not through
		// DT_NEEDED, so nothing in the graph points at it. Without this a CVE
		// in the dynamic loader -- which is part of glibc or musl, the two
		// packages most likely to be asked about -- would report as unreachable
		// in every image.
		if n.Info.Interp != "" {
			if c := g.Canon(n.Info.Interp); g.nodes[c] != nil {
				g.nodes[c].NeededBy = appendUnique(g.nodes[c].NeededBy, n.Path)
				queue = append(queue, frame{path: c})
			}
		}

		if len(n.Info.Needed) == 0 {
			continue
		}

		origin := path.Dir(n.Path)
		ownRPath := expandRunPath(n.Info.RPath, origin, n.Info)
		runPath := expandRunPath(n.Info.RunPath, origin, n.Info)

		// glibc's order. DT_RUNPATH is not inherited, and its presence turns
		// off DT_RPATH entirely for this object -- including the rpath handed
		// down by whatever loaded it.
		var dirs []string
		childRPath := cur.rpath
		if len(runPath) == 0 {
			dirs = append(dirs, ownRPath...)
			dirs = append(dirs, cur.rpath...)
			childRPath = append(append([]string{}, ownRPath...), cur.rpath...)
		}
		dirs = append(dirs, ldLibraryPath...)
		dirs = append(dirs, runPath...)
		dirs = append(dirs, ldconf...)
		dirs = append(dirs, defaultLibDirs(n.Info.Class, n.Info.Machine)...)

		for _, soname := range n.Info.Needed {
			dep, ok := g.resolve(n, soname, dirs)
			n.Needed[soname] = dep
			if !ok {
				continue
			}
			d := g.nodes[dep]
			d.NeededBy = appendUnique(d.NeededBy, n.Path)
			queue = append(queue, frame{path: dep, rpath: childRPath})
		}
	}
}

// resolve finds the file a DT_NEEDED entry names.
func (g *Graph) resolve(from *Node, soname string, dirs []string) (string, bool) {
	// A soname containing a slash is used as a path, and the search list is
	// skipped entirely.
	if strings.Contains(soname, "/") {
		c := g.Canon(soname)
		if n, ok := g.nodes[c]; ok && sameABI(from.Info, n.Info) {
			return c, true
		}
		return "", false
	}

	tried := map[string]bool{}
	for _, dir := range dirs {
		cand := path.Join(dir, soname)
		if tried[cand] {
			continue
		}
		tried[cand] = true

		c := g.Canon(cand)
		n, ok := g.nodes[c]
		if !ok {
			continue
		}
		// A multiarch image carries an i386 and an x86_64 copy of the same
		// soname in different directories. Taking the wrong one links a
		// package into a closure it has nothing to do with.
		if !sameABI(from.Info, n.Info) {
			continue
		}
		return c, true
	}
	return "", false
}

func sameABI(a, b *Info) bool {
	return a.Class == b.Class && a.Machine == b.Machine
}

// collectTaints records what the finished closure could not account for.
func (g *Graph) collectTaints(opts Options) {
	for _, p := range g.order {
		n := g.nodes[p]
		if !n.Reachable {
			continue
		}
		for _, soname := range sortedNeeded(n.Needed) {
			if n.Needed[soname] != "" {
				continue
			}
			g.taints = append(g.taints, Taint{
				Kind:     TaintUnresolvedNeeded,
				Detail:   fmt.Sprintf("%s needs %s, which is not in the image", p, soname),
				Path:     p,
				Soname:   soname,
				Blocking: true,
			})
		}
		if n.Info.Dlopen {
			g.taints = append(g.taints, Taint{
				Kind:     TaintDlopen,
				Detail:   fmt.Sprintf("%s calls dlopen, so what it loads is decided at runtime", p),
				Path:     p,
				Blocking: opts.DlopenPolicy != DlopenAssumeNone,
				Global:   opts.DlopenPolicy != DlopenAssumeNone,
			})
		}
		if n.Kind >= RootEscalated && n.Info.Static() {
			// Only a static *entrypoint* blocks. That is the case the closure
			// genuinely cannot see through: the workload itself carries its
			// libraries inside it, so an unreferenced .so on disk proves
			// nothing about whether the same code is running.
			//
			// A static utility that merely exists is a different matter. Every
			// glibc distribution ships a static ldconfig; treating that as a
			// global blocker would mean no Red Hat image could ever produce a
			// not_affected result, which is a great deal of conservatism in
			// exchange for no safety -- ldconfig contains glibc, and glibc is
			// reachable in those images anyway. It is still recorded.
			explicit := n.Kind == RootExplicit
			detail := fmt.Sprintf("%s is statically linked, so the libraries it uses are inside it and not on disk", p)
			if !explicit {
				detail += " (not the entrypoint, so this is recorded rather than blocking)"
			}
			g.taints = append(g.taints, Taint{
				Kind:     TaintStaticELF,
				Detail:   detail,
				Path:     p,
				Blocking: explicit,
				Global:   explicit,
			})
		}
	}
}

// Canon resolves a tree path through symlinks and returns the tree-absolute
// path a node would be keyed by.
//
// Callers must use it on any path that came from outside this package. A dpkg
// file list records /lib/x86_64-linux-gnu/libc.so.6 on a system where /lib is
// a symlink into /usr; comparing that string against a walked tree finds
// nothing, and finding nothing reads as "this package ships no code".
func (g *Graph) Canon(name string) string {
	host, err := g.fsys.HostPath(name)
	if err != nil {
		return path.Clean("/" + name)
	}
	return target.Rel(g.fsys.Root(), host)
}

// Node returns the node at a path, canonicalizing it first.
func (g *Graph) Node(name string) (*Node, bool) {
	n, ok := g.nodes[g.Canon(name)]
	return n, ok
}

// Reachable reports whether the dynamic linker would load this file.
func (g *Graph) Reachable(name string) bool {
	n, ok := g.Node(name)
	return ok && n.Reachable
}

// Classify sorts a package's file list into the ELF objects it owns and the
// subset of those the closure reaches. Paths that are not ELF -- man pages,
// configuration, scripts -- are simply absent from both.
func (g *Graph) Classify(files []string) FileSet {
	var out FileSet
	seen := map[string]bool{}
	for _, f := range files {
		c := g.Canon(f)
		if seen[c] {
			continue
		}
		seen[c] = true
		n, ok := g.nodes[c]
		if !ok {
			continue
		}
		out.ELF = append(out.ELF, c)
		if n.Reachable {
			out.Reachable = append(out.Reachable, c)
		}
	}
	sort.Strings(out.ELF)
	sort.Strings(out.Reachable)
	return out
}

// FileSet is what Classify found about one package's files.
type FileSet struct {
	// ELF are the object files the package installs.
	ELF []string
	// Reachable are the ones the closure loads.
	Reachable []string
}

// Nodes returns every indexed object, in path order.
func (g *Graph) Nodes() []*Node {
	out := make([]*Node, 0, len(g.order))
	for _, p := range g.order {
		out = append(out, g.nodes[p])
	}
	return out
}

// Roots returns the paths the closure started from, in path order.
func (g *Graph) Roots() []string { return append([]string{}, g.roots...) }

// Taints returns everything the closure could not account for.
func (g *Graph) Taints() []Taint { return append([]Taint{}, g.taints...) }

// BlockingTaints returns the global taints that stop a not_affected conclusion
// for any package. Scoped ones -- an unresolved soname -- are left out; a
// caller judging one package asks about the sonames that package installs.
func (g *Graph) BlockingTaints() []Taint {
	var out []Taint
	for _, t := range g.taints {
		if t.Blocking && t.Global {
			out = append(out, t)
		}
	}
	return out
}

// CountReachable is the size of the closure.
func (g *Graph) CountReachable() int {
	n := 0
	for _, p := range g.order {
		if g.nodes[p].Reachable {
			n++
		}
	}
	return n
}

// alwaysRoot reports whether a path is a plugin the runtime loads by name
// rather than by DT_NEEDED, and therefore has to be rooted even though nothing
// in the image refers to it.
func alwaysRoot(p string) (string, bool) {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(base, "libnss_") && isSharedObject(base):
		return "glibc NSS module, loaded by name", true
	case strings.HasPrefix(base, "pam_") && strings.Contains(p, "/security/"):
		return "PAM module, loaded by name", true
	case strings.Contains(p, "/gconv/"):
		return "iconv character-set converter, loaded by name", true
	case strings.Contains(p, "/engines-"):
		return "OpenSSL engine, loaded by name", true
	case strings.Contains(p, "/ossl-modules/"):
		return "OpenSSL provider, loaded by name", true
	case strings.HasSuffix(base, ".node"):
		return "Node.js native addon, loaded by require", true
	case isSharedObject(base) && (strings.Contains(p, "/site-packages/") ||
		strings.Contains(p, "/dist-packages/") || strings.Contains(p, "/lib-dynload/")):
		return "Python extension module, loaded by import", true
	}
	return "", false
}

func isSharedObject(base string) bool {
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

func envValue(c target.ImageConfig, key string) []string {
	v, ok := c.LookupEnv(key)
	if !ok {
		return nil
	}
	return []string{v}
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

func sortedNeeded(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
