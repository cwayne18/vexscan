// Package modgraph answers one question about an image: starting from what the
// container actually runs, which source modules can be imported?
//
// It is internal/elfgraph for languages that resolve imports at runtime rather
// than at link time, and the public surface is deliberately the same --
// Build, Classify, Nodes, Roots, Taints, BlockingTaints, CountReachable -- so
// that a plugin's evaluate.go reads the same whether the closure it consults
// was built from DT_NEEDED entries or from import statements.
//
// The two differ in one structural way. elfgraph indexes every ELF object in
// the image and then marks the reachable subset, because the index is also the
// resolver's input: a soname is found by looking through everything. Nothing
// resolves imports that way -- a specifier is resolved by probing a search
// path -- and a Python image can hold a hundred thousand .py files, so this
// package walks lazily from the roots outward and never reads a file no root
// can reach. Classify therefore asks the Language whether a path is a module
// rather than looking it up in an index that does not exist.
//
// Language knowledge lives outside this package, behind the Language
// interface, because the same code that resolves a Python import needs to know
// where site-packages is and so does the Python inventory. Discovering it
// twice, in two packages, is how the two come to disagree.
package modgraph

import (
	"path"
	"sort"

	"github.com/cwayne18/vexscan/internal/target"
)

// Language is everything modgraph does not know: what the image runs, what a
// file imports, where a specifier points, and what counts as code.
//
// Implementations hold their own filesystem and image config -- they are
// constructed by the plugin that already discovered both -- so the methods
// take only what varies per call.
type Language interface {
	// ID names the language, for evidence lines.
	ID() string

	// Roots turns the image config into entry modules, or explains through
	// taints why it could not. extra is the user's --roots values.
	//
	// A Language that cannot find an entrypoint is expected to escalate --
	// root every installed module -- and say so with a taint, never to return
	// an empty root set. No roots means nothing is reachable, which reads as
	// an image where no code runs.
	Roots(extra []string) ([]Root, []Taint, error)

	// Imports lists the specifiers one file references, plus any taint the
	// file itself raises (a computed import, a body that would not parse).
	Imports(file string) ([]Spec, []Taint, error)

	// Resolve maps a specifier referenced from a file onto the files it loads.
	// A specifier can resolve to more than one path -- a PEP 420 namespace
	// package merges across sys.path entries -- and ok is false when it
	// resolved to nothing, which the caller records as an unresolved-import
	// taint scoped to that specifier.
	Resolve(from string, spec Spec) ([]string, bool)

	// IsModule reports whether a path is code this language would load. It is
	// what makes a file eligible to be counted at all, and it must not read
	// the file: it is called once per file in an inventory.
	IsModule(path string) bool
}

// Spec is one import as written in the source.
type Spec struct {
	// Name is the specifier verbatim: "yaml", ".loader", "@scope/pkg/sub".
	Name string

	// Line is where it appears, for evidence. Zero when unknown.
	Line int

	// Dynamic marks a specifier that came from importlib.import_module or
	// require() with a literal argument. It resolves like any other import --
	// the argument is right there -- and is only flagged so evidence can say
	// how the edge was found.
	Dynamic bool

	// Optional marks a specifier that may legitimately resolve to nothing, and
	// so raises no taint when it does. "from pkg import Thing" produces one:
	// Thing might be a submodule, and might equally be a class defined in
	// pkg/__init__.py. Without this every such line would report a missing
	// module, and a taint that fires on correct code teaches a reader to
	// ignore taints.
	Optional bool
}

// RootKind says why a file is a root, which is what lets output distinguish
// "this runs" from "this might run, because we could not tell what does".
type RootKind string

const (
	// RootEntry is the image's actual entrypoint, or something reached from
	// it. This is the only kind that means the code demonstrably runs.
	RootEntry RootKind = "entrypoint"

	// RootPlugin is a file the runtime loads by name rather than by import:
	// sitecustomize.py, a path added by a .pth file, a declared entry point.
	RootPlugin RootKind = "plugin"

	// RootEscalated is a root added because the entrypoint could not be
	// understood. It always arrives with a taint.
	RootEscalated RootKind = "escalated"

	// RootExplicit is a --roots value.
	RootExplicit RootKind = "explicit"
)

// Root is one starting point for the closure.
type Root struct {
	Path string
	Why  string
	Kind RootKind
}

// Node is one module the closure touched.
type Node struct {
	// Path is the canonical tree-absolute path.
	Path string

	// Root, Why and Kind describe how the walk started here, if it did.
	Root bool
	Why  string
	Kind RootKind

	// Reachable says the walk arrived here. Every node in the graph is
	// reachable -- unlike elfgraph, which indexes unreachable objects too --
	// but the field is kept so evaluate.go reads the same in both.
	Reachable bool

	// Imports records what this file resolved to, keyed by specifier. A
	// specifier that resolved to nothing maps to nil and is also a taint.
	Imports map[string][]string

	// ImportedBy is every file that imported this one, in discovery order.
	// Empty for a root nothing else reaches.
	ImportedBy []string
}

// Options configure Build.
type Options struct {
	// Roots are extra entry files or module names from --roots, passed to the
	// Language because resolving them is language-specific.
	Roots []string

	// Dynamic decides whether a computed import blocks a conclusion.
	Dynamic DynamicPolicy

	// Logf, if set, receives progress lines.
	Logf func(format string, args ...any)
}

// Graph is the reachable module closure.
type Graph struct {
	fsys  target.RootFS
	lang  Language
	nodes map[string]*Node
	order []string
	roots []string

	taints []Taint
}

// Build walks the import graph from the language's roots.
func Build(fsys target.RootFS, lang Language, opts Options) (*Graph, error) {
	if opts.Dynamic == "" {
		opts.Dynamic = DynamicTaint
	}
	g := &Graph{fsys: fsys, lang: lang, nodes: map[string]*Node{}}

	roots, taints, err := lang.Roots(opts.Roots)
	if err != nil {
		return nil, err
	}
	g.addTaints(taints, opts)

	for _, r := range roots {
		g.addRoot(r)
	}
	if opts.Logf != nil {
		opts.Logf("  %s: %d roots", lang.ID(), len(g.roots))
	}

	g.walk(opts)

	if opts.Logf != nil {
		opts.Logf("  %s: %d modules reachable, %d taints", lang.ID(), g.CountReachable(), len(g.taints))
	}
	return g, nil
}

// addRoot records a starting point. A path rooted twice -- the entrypoint that
// is also a --roots value -- keeps the first reason, the way elfgraph does,
// because the first is the more specific one.
func (g *Graph) addRoot(r Root) {
	c := g.Canon(r.Path)
	n := g.node(c)
	if n.Root {
		return
	}
	n.Root, n.Why, n.Kind = true, r.Why, r.Kind
	g.roots = append(g.roots, c)
}

// walk is the breadth-first closure. Files are read only when reached, which
// is the whole reason this package does not index first.
func (g *Graph) walk(opts Options) {
	queue := append([]string{}, g.roots...)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		n := g.node(cur)
		if n.Reachable {
			continue
		}
		n.Reachable = true

		specs, taints, err := g.lang.Imports(cur)
		if err != nil {
			// A file that is reached and cannot be read hides everything it
			// would have imported. That is a hole in the closure, and a hole
			// in the closure must never read as "nothing is downstream".
			g.addTaints([]Taint{{
				Kind:     TaintUnreadable,
				Detail:   "reachable module could not be read: " + err.Error(),
				Path:     cur,
				Blocking: true,
				Global:   true,
			}}, opts)
			continue
		}
		g.addTaints(taints, opts)

		for _, s := range specs {
			targets, ok := g.lang.Resolve(cur, s)
			if n.Imports == nil {
				n.Imports = map[string][]string{}
			}
			if !ok {
				n.Imports[s.Name] = nil
				if s.Optional {
					continue
				}
				// Scoped, not global: one specifier that points at nothing
				// says nothing about the rest of the image. Recording it as
				// global here is how a single typo'd optional import would
				// taint every package in the scan.
				g.addTaints([]Taint{{
					Kind:     TaintUnresolvedImport,
					Detail:   "import resolved to no file: " + s.Name,
					Path:     cur,
					Spec:     s.Name,
					Blocking: true,
				}}, opts)
				continue
			}
			for _, t := range targets {
				c := g.Canon(t)
				g.node(c).ImportedBy = appendOnce(g.node(c).ImportedBy, cur)
				n.Imports[s.Name] = appendOnce(n.Imports[s.Name], c)
				if !g.node(c).Reachable {
					queue = append(queue, c)
				}
			}
		}
	}
}

// addTaints applies policy and records. Policy lives here rather than in each
// Language so that --dynamic-import-policy means the same thing in every
// ecosystem, and so a Language cannot forget to honour it.
func (g *Graph) addTaints(ts []Taint, opts Options) {
	for _, t := range ts {
		if t.Kind == TaintDynamicImport && opts.Dynamic == DynamicAssumeNone {
			// The user asserted the risk away. The observation still belongs
			// in the record -- a reader has to be able to see what the
			// assertion covered -- it just no longer blocks.
			t.Blocking, t.Global = false, false
		}
		g.taints = append(g.taints, t)
	}
}

// node returns the node at a canonical path, creating it.
func (g *Graph) node(c string) *Node {
	if n, ok := g.nodes[c]; ok {
		return n
	}
	n := &Node{Path: c}
	g.nodes[c] = n
	g.order = append(g.order, c)
	return n
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Canon resolves a path to its tree-absolute form, following symlinks the way
// the runtime would.
func (g *Graph) Canon(name string) string {
	if g.fsys == nil {
		return path.Clean("/" + name)
	}
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

// Reachable reports whether the runtime could import this file.
func (g *Graph) Reachable(name string) bool {
	n, ok := g.Node(name)
	return ok && n.Reachable
}

// Classify sorts a distribution's file list into the modules it owns and the
// subset of those the closure reaches. Data files, licences and stubs are
// simply absent from both.
//
// Module comes from the Language rather than from a lookup, because an
// unreachable module was never visited and so has no node. That asymmetry is
// load-bearing: a distribution whose modules are all unreached must report
// "installed, nothing imports it", and it could not if unreached modules were
// invisible here.
func (g *Graph) Classify(files []string) FileSet {
	var out FileSet
	seen := map[string]bool{}
	for _, f := range files {
		c := g.Canon(f)
		if seen[c] || !g.lang.IsModule(c) {
			continue
		}
		seen[c] = true
		out.Module = append(out.Module, c)
		if n, ok := g.nodes[c]; ok && n.Reachable {
			out.Reachable = append(out.Reachable, c)
		}
	}
	sort.Strings(out.Module)
	sort.Strings(out.Reachable)
	return out
}

// FileSet is Classify's answer.
type FileSet struct {
	// Module are the source files the distribution installs.
	Module []string
	// Reachable are the ones the closure imports.
	Reachable []string
}

// Nodes returns every module the closure touched, in discovery order.
func (g *Graph) Nodes() []*Node {
	out := make([]*Node, 0, len(g.order))
	for _, p := range g.order {
		out = append(out, g.nodes[p])
	}
	return out
}

// Roots returns the paths the closure started from, in the order they were
// added: entrypoint first, then plugins, then explicit ones.
func (g *Graph) Roots() []string { return append([]string{}, g.roots...) }

// Taints returns everything the closure could not account for.
func (g *Graph) Taints() []Taint { return append([]Taint{}, g.taints...) }

// BlockingTaints returns the global taints that stop a not_affected conclusion
// for any distribution. Scoped ones are left out; a caller judging one
// distribution asks TaintsFor about the names that distribution owns.
func (g *Graph) BlockingTaints() []Taint {
	var out []Taint
	for _, t := range g.taints {
		if t.Blocking && t.Global {
			out = append(out, t)
		}
	}
	return out
}

// TaintsFor returns the taints that bear on one distribution: the global ones,
// plus any scoped to a specifier or import name it owns.
//
// The scoped half is what keeps one package's plugin loader from tainting the
// whole image, and the global half is what stops that scoping from being a
// loophole.
func (g *Graph) TaintsFor(importNames []string) []Taint {
	owns := map[string]bool{}
	for _, n := range importNames {
		owns[n] = true
	}
	var out []Taint
	for _, t := range g.taints {
		switch {
		case t.Global:
			out = append(out, t)
		case t.Spec != "" && owns[topLevel(t.Spec)]:
			out = append(out, t)
		default:
			for _, s := range t.Scope {
				if owns[s] {
					out = append(out, t)
					break
				}
			}
		}
	}
	return out
}

// topLevel is the first component of a dotted or slashed specifier, which is
// the part that names a distribution's import root.
func topLevel(spec string) string {
	for i := 0; i < len(spec); i++ {
		if spec[i] == '.' || spec[i] == '/' {
			if i == 0 {
				continue // a relative import: "."
			}
			return spec[:i]
		}
	}
	return spec
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
