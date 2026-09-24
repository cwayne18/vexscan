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
	// outside the config -- an init system, a wrapper the config does not name.
	//
	// Roots *add*. The config entrypoint is still rooted alongside them, which
	// is the right default -- naming a program that also runs is not a claim
	// that the declared one does not. When the declared one genuinely does not
	// run, that is Entrypoint below, and the difference is the whole closure:
	// on a hardened image whose config entrypoint is /bin/bash, --roots leaves
	// bash rooted, and bash's dlopen is what blocks conclusions about every
	// package in the image.
	Roots []string

	// Entrypoint and Cmd replace the config's own, rather than adding to them,
	// and EntrypointSource says where they came from -- "deploy.yaml". A nil
	// field leaves the config's in place; an empty non-nil one is an override
	// that deliberately names nothing.
	//
	// They are two fields and not one argv because Kubernetes overrides them
	// separately: `command:` replaces ENTRYPOINT and `args:` replaces CMD, and
	// a container that sets only `args:` still runs the image's ENTRYPOINT.
	// Flattening them would have to guess which half a single list meant.
	//
	// This exists because a Kubernetes `command:` does not supplement the image
	// ENTRYPOINT, it replaces it: the ENTRYPOINT process is never executed, and
	// neither is anything it would have loaded. Modelling that as an extra root
	// gets the wrong answer in the direction that matters, leaving a shell
	// rooted -- and every library only that shell reaches -- in a deployment
	// where the shell is never run.
	//
	// It is an assertion, not a finding. The closure loses roots because of it,
	// so a wrong one can under-report, and it is recorded in the report's
	// conditional-conclusions note for the same reason --roots is. What it is
	// not is a licence to assume anything further: the override is fed through
	// the same wrapper peeling, shell detection and escalation as a config
	// argv, so a `command: ["/bin/sh", "-c", ...]` escalates exactly as a
	// /bin/sh ENTRYPOINT would.
	Entrypoint       []string
	Cmd              []string
	EntrypointSource string

	// DlopenPolicy decides whether a reachable dlopen blocks conclusions.
	DlopenPolicy DlopenPolicy

	// DlopenAssumeNoneFor names individual dlopen callers the user asserts load
	// nothing that matters, by tree-absolute path or by SONAME.
	//
	// It is the narrow form of DlopenAssumeNone, and exists because the blanket
	// one is usually far more than the user means. An image whose only
	// unanswered loader is /usr/bin/bash needs one claim about bash; saying
	// assume-none instead also waves off every library in the image that was
	// never examined, including any added to it later. The narrow claim is the
	// one a reviewer can check, so it is the one worth making easy to write.
	//
	// Naming a caller that does not exist, or one that calls no dlopen, is not
	// an error: it discharges nothing, which leaves the run more conservative
	// rather than less. See TaintInertAssertion for why it is still reported.
	//
	// Setting this together with DlopenPolicy=assume-none is refused by Build.
	DlopenAssumeNoneFor []string

	// ExecPolicy decides whether an entrypoint that can start another program
	// blocks conclusions.
	ExecPolicy ExecPolicy

	// ReadELF loads ELF metadata. Defaults to the debug/elf-backed reader.
	ReadELF Reader

	// StaticProber optionally inspects a statically linked entrypoint to decide
	// whether its contents can be accounted for from outside it. Nil is the
	// conservative default: with no prober, every static entrypoint blocks,
	// because the closure cannot see the libraries it carries inside itself.
	//
	// A prober is what lets that judgement be sharpened rather than always
	// assumed. The motivating case is a pure-Go binary built with
	// CGO_ENABLED=0: it is statically linked, so DT_NEEDED sees nothing, but it
	// links no C library at all -- so unlike a static musl+openssl binary it
	// cannot hold a hidden copy of the vulnerable code, and the unreferenced
	// .so on disk really is the answer.
	StaticProber StaticProber

	// ExecProber optionally inspects an entrypoint to decide whether it can start
	// another program. Nil leaves the question unasked, which is what every
	// version of this package before it did.
	//
	// It exists because the closure models one process image and not a process
	// tree, and that gap has always been the largest unmeasured thing in the
	// answer. An entrypoint that execs /usr/bin/su loads libpam in a process this
	// package never looks at, and until something asks, the report cannot tell
	// the difference between an image where that happens and one where it
	// cannot. A prober turns the gap into one of three statements -- it does, it
	// provably does not, or this is not a binary I can read -- and only the first
	// two are worth saying.
	ExecProber ExecProber

	Logf func(string, ...any)
}

// overridden reports whether the run replaced the image's declared command.
func (o Options) overridden() bool { return o.Entrypoint != nil || o.Cmd != nil }

// argv is the command line the image will actually be started with: the
// config's, with either half replaced by an override that named one.
//
// Nil and empty are kept apart on purpose. A container that sets `args: []`
// says the image's CMD is dropped; one that sets no args at all says nothing
// about it. Reading both as "empty" would silently discard a CMD the deployment
// still runs, and the argv is what roots the closure.
func (o Options) argv() []string {
	entrypoint, cmd := o.Config.Entrypoint, o.Config.Cmd
	if o.Entrypoint != nil {
		entrypoint = o.Entrypoint
	}
	if o.Cmd != nil {
		cmd = o.Cmd
	}
	argv := make([]string, 0, len(entrypoint)+len(cmd))
	argv = append(argv, entrypoint...)
	return append(argv, cmd...)
}

// ExecProbe is what an ExecProber concluded about one entrypoint.
type ExecProbe struct {
	// CanSpawn reports that the binary contains code that starts another
	// program, so the closure is a lower bound on what the image runs.
	CanSpawn bool

	// Why explains the conclusion, in either direction, for the taint's evidence
	// line. Required: a probe that reports a result without saying how it
	// reached it produces a taint whose detail cannot be audited, and both
	// directions of this test are load-bearing enough to need one. A probe with
	// no Why is treated as having established nothing.
	Why string

	// Targets are program paths the binary mentions, as candidates for what it
	// might exec. They are rooted, because rooting too much only widens the
	// closure, and they are named in the evidence so a user deciding whether to
	// pass --exec-policy=assume-none has a list to check --roots against.
	//
	// Never complete, and not treated as though it were: a target assembled at
	// runtime or resolved through PATH leaves no absolute path in the file, so
	// the taint blocks whether this is empty or not.
	Targets []string
}

// ExecProber inspects the program at a tree-absolute path and reports whether
// it can start another program. programs are the tree-absolute paths of every
// executable in the image, offered so a prober can look for the ones its
// subject mentions.
//
// The second result is false when nothing could be established -- a binary the
// prober cannot read, or one whose language leaves no trace of the answer -- in
// which case no taint is recorded and the closure behaves as it always has.
type ExecProber func(fsys target.RootFS, path string, programs []string) (ExecProbe, bool)

// StaticProbe is what a StaticProber concluded about one static entrypoint.
type StaticProbe struct {
	// Closed reports that the binary links no library that could hide a copy of
	// a vulnerable shared object, so the static-elf taint it would otherwise
	// raise is recorded rather than allowed to block.
	Closed bool

	// Why explains the conclusion in the taint's evidence line, so the
	// discharge is auditable next to what it discharged.
	//
	// Required when Closed is true, and enforced rather than documented: a
	// probe that clears a binary without saying why produces a taint whose
	// detail reads exactly like the blocking one, and a result that was
	// filtered has to be distinguishable from a result that was not. A Closed
	// probe with no Why is therefore treated as having established nothing.
	Why string
}

// StaticProber inspects the static entrypoint at a tree-absolute path and
// reports what could be established about it. The second result is false when
// nothing could be -- an unreadable file, or one the prober does not recognise
// -- in which case the taint blocks as it would with no prober at all.
type StaticProber func(fsys target.RootFS, path string) (StaticProbe, bool)

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

	// pending are the runtime-loaded plugins waiting for their loader to turn
	// up in the closure, and after the walk has finished the ones whose loader
	// never did. See admitPlugins.
	pending []pendingPlugin
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
	if opts.ExecPolicy == "" {
		opts.ExecPolicy = ExecTaint
	}
	// Refused rather than resolved, because there is no reading of the pair
	// that is not a mistake. The blanket policy subsumes every name, so the
	// names would change nothing and the report would carry a precise-looking
	// list of callers beside an assertion that covered all of them -- the
	// narrow claim's audit trail attached to the broad claim's conclusions.
	if opts.DlopenPolicy == DlopenAssumeNone && len(opts.DlopenAssumeNoneFor) > 0 {
		return nil, fmt.Errorf("--dlopen-policy=assume-none waves off every dlopen caller, "+
			"so naming %s with --dlopen-assume-none asserts both less and more than you mean: use one or the other",
			strings.Join(opts.DlopenAssumeNoneFor, ", "))
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
	if summary := g.gatedSummary(); summary != "" {
		opts.Logf("  %s", summary)
	}
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
	// Plugins are rooted by name, because nothing has a DT_NEEDED on an NSS
	// module or a PAM module and a closure that only followed DT_NEEDED would
	// report every one of them as dead code.
	//
	// Rooted by name, but not unconditionally. A plugin is loaded *by* one
	// specific library -- NSS modules and gconv converters by libc, PAM modules
	// by libpam, engines and providers by libcrypto -- and if the closure does
	// not reach that library, nothing in this image can load the plugin. Those
	// wait in g.pending until the walk says otherwise; the families whose loader
	// this package cannot name are rooted here and now. See admitPlugins.
	for _, p := range g.order {
		fam, ok := pluginClass(p)
		if !ok {
			continue
		}
		if fam.loader == "" {
			g.addRoot(p, fam.what+", loaded by name", RootPlugin)
			continue
		}
		g.pending = append(g.pending, pendingPlugin{path: p, fam: fam})
	}

	// A --roots path that does not resolve blocks rather than warns. The user
	// named a program they say execution starts at; the closure does not have
	// it, so the closure is short a root, and a closure short a root reports
	// code it would have reached as unreachable. Warning and carrying on is the
	// worst of the options -- the run where this happens is exactly the run
	// where --exec-policy=assume-none has also been passed, so nothing else is
	// left to withhold the conclusion. See TaintMissingRoot.
	var rooted int
	for _, r := range opts.Roots {
		c := g.Canon(r)
		if _, ok := g.nodes[c]; !ok {
			detail := fmt.Sprintf("--roots %s names nothing in this image, so the closure is missing a root and cannot be trusted to be complete; check the path, or drop it", r)
			if _, err := g.fsys.Stat(c); err == nil {
				detail = fmt.Sprintf("--roots %s is in this image but is not an ELF object -- a script, or a wrapper -- so the closure cannot start from it, and whatever it goes on to run is outside the closure; name that program instead", r)
			}
			opts.Logf("  ! %s", detail)
			g.taints = append(g.taints, Taint{
				Kind:     TaintMissingRoot,
				Detail:   detail,
				Path:     r,
				Blocking: true,
				Global:   true,
			})
			continue
		}
		g.addRoot(c, "named by --roots", RootExplicit)
		rooted++
	}

	// The override is taken instead of the config's argv, not before it and not
	// after it. Everything past this line is the same code either way, which is
	// the point: an overridden entrypoint gets no weaker a reading than a
	// declared one, so a shell named by a manifest still escalates.
	argv, declared := opts.argv(), "no image config, or one that sets neither Entrypoint nor Cmd"
	if opts.overridden() {
		declared = opts.EntrypointSource + " names no command"
	}
	if len(argv) == 0 {
		if g.unknownEntrypoint(opts, rooted, TaintNoEntrypoint,
			"nothing declares an entrypoint -- "+declared,
			"", "no entrypoint") {
			return
		}
		g.probeExec(opts)
		return
	}

	// Peel the transparent exec wrappers -- tini, gosu, env and the like --
	// that stand between the config and the program that actually runs. Each
	// one execs a specific later argv token and loads no application code of
	// its own, so resolving through it reaches a real entrypoint that can root a
	// precise closure, where treating the wrapper as a shell would escalate to
	// rooting everything. A wrapper whose grammar cannot be parsed with
	// certainty is left in place, and the shell check below escalates as before.
	argv = g.peelWrappers(opts, argv)
	if len(argv) == 0 {
		if g.unknownEntrypoint(opts, rooted, TaintNoEntrypoint,
			"the entrypoint is an exec wrapper that forwards to no command, so what runs is unknown",
			"", "wrapper names no command") {
			return
		}
		g.probeExec(opts)
		return
	}

	// What the entrypoint is called in every message below. An overridden one
	// has to say so wherever it is named, not only in the report's condition
	// line: a reviewer reading "entrypoint \"/bin/bash\" runs something other
	// than itself" against an image whose ENTRYPOINT is bash has no way to tell
	// that sentence apart from the one about an entrypoint that is not running.
	// Entrypoint and not overridden: a container that set only `args:` is still
	// running the image's own entrypoint, and calling that one "the entrypoint
	// deploy.yaml gives, which replaces the image's own" would be the report
	// claiming the deployment answered a question it did not.
	noun := "entrypoint"
	if opts.Entrypoint != nil {
		noun = "the entrypoint " + opts.EntrypointSource + " gives, which replaces the image's own"
	}

	argv0 := argv[0]
	base := path.Base(argv0)
	if shells[base] || strings.HasSuffix(base, ".sh") {
		escalated := g.unknownEntrypoint(opts, rooted, TaintShellEntrypoint,
			fmt.Sprintf("%s, %q, runs something other than itself", noun, strings.Join(argv, " ")),
			argv0, "shell entrypoint")
		// The shim itself is still executed.
		if p, ok := g.lookupCommand(opts, argv0); ok {
			g.addRoot(p, noun, RootExplicit)
		}
		if !escalated {
			g.probeExec(opts)
		}
		return
	}

	p, ok := g.lookupCommand(opts, argv0)
	if !ok {
		if g.unknownEntrypoint(opts, rooted, TaintNoEntrypoint,
			fmt.Sprintf("%s, %q, is not an ELF object in this image", noun, argv0),
			argv0, "unresolvable entrypoint") {
			return
		}
		g.probeExec(opts)
		return
	}
	g.addRoot(p, noun, RootExplicit)

	// Later argv elements are arguments, not programs -- except for the common
	// wrapper shapes, which the shell check above already caught.

	g.probeExec(opts)
}

// unknownEntrypoint records that the closure cannot tell where execution
// starts, and either escalates or stands on the roots the user named. It
// reports whether it escalated.
//
// Escalation is safe to pair with a non-blocking taint because the two go
// together: a closure that roots every program in the image cannot
// under-report, so there is nothing left for the unknown entrypoint to reach
// and nothing to withhold. Dropping escalation while leaving the taint a note
// would break that bargain and leave a narrow closure with nothing guarding
// it -- the exact shape that reports reachable code as dead.
//
// So it is dropped only against an assertion, and only against both halves of
// one. --roots alone is not enough: it says where execution starts, not that
// nothing else does, and a shell is free to run things the user never named.
// --exec-policy=assume-none supplies the second half, and it is the same
// assertion TaintExec already accepts one program away -- a Go entrypoint that
// can exec is allowed to have its targets assumed accounted for, and there is
// no principled reason a shell that execs should be refused the same answer.
// Refusing it is what made a hardened image unanswerable: 491 of 668 objects
// rooted because the entrypoint was a shell script, so 144 of 145 findings came
// back reachable no matter what the user knew about the image.
//
// Both ways the taint is raised and both ways it is evidence. What changes is
// what it costs: escalating it is a note on a closure that already roots
// everything; standing on --roots it is a discharged taint, recorded as the
// ground the conclusion stands on rather than dropped.
func (g *Graph) unknownEntrypoint(opts Options, rooted int, kind TaintKind, what, p, why string) bool {
	if rooted == 0 || opts.ExecPolicy != ExecAssumeNone {
		g.taints = append(g.taints, Taint{
			Kind:   kind,
			Detail: what + ", so every executable is treated as a root; name the real ones with --roots and re-run with --exec-policy=assume-none",
			Path:   p,
		})
		g.escalate(opts, why)
		return true
	}
	g.taints = append(g.taints, Taint{
		Kind: kind,
		Detail: fmt.Sprintf("%s, but --roots names %s this image has and --exec-policy=assume-none says what they start is accounted for, "+
			"so the closure starts from those rather than from every executable in the image", what, plural(rooted, "program")),
		Path:       p,
		Discharged: true,
	})
	return false
}

// plural renders a count with its noun, for evidence a person reads.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// probeExec asks the prober whether the programs this image says it runs can
// run anything else, and roots whatever they name.
//
// Only the explicit roots are probed, and only on the path where the closure
// did not escalate. Every escalating branch above has already recorded a
// blocking taint and rooted every executable in the image, so an entrypoint
// that can exec tells a reader nothing they were not already told, and probing
// the several hundred binaries escalation rooted would be paid for in I/O to
// reach the same answer.
func (g *Graph) probeExec(opts Options) {
	if opts.ExecProber == nil {
		return
	}
	programs := g.programs()

	// Snapshotted, because rooting a candidate target appends to g.roots. The
	// subject is what the image says it runs; a program that program might exec
	// is already covered by the taint that rooting it came with, and chasing the
	// chain would probe every binary a big Go program happens to name.
	subjects := append([]string(nil), g.roots...)
	for _, p := range subjects {
		if g.nodes[p].Kind != RootExplicit {
			continue
		}
		// Why is part of the condition rather than only the message. A probe
		// that reports "cannot exec" without saying how it established that
		// produces a discharged taint indistinguishable from a real one, and a
		// discharge is exactly the claim a reader has to be able to check.
		pr, ok := opts.ExecProber(g.fsys, p, programs)
		if !ok || pr.Why == "" {
			continue
		}
		if !pr.CanSpawn {
			g.taints = append(g.taints, Taint{
				Kind:       TaintExec,
				Detail:     fmt.Sprintf("%s starts no other program: %s", p, pr.Why),
				Path:       p,
				Discharged: true,
			})
			continue
		}

		// Rooting the candidates before the walk, so the libraries they need are
		// in the closure. It does not discharge anything -- the list cannot be
		// complete -- but a closure that already contains the obvious targets is
		// the one worth having if the user goes on to assert --exec-policy=
		// assume-none.
		var rooted []string
		for _, t := range pr.Targets {
			c := g.Canon(t)
			if n, exists := g.nodes[c]; !exists || !n.Info.IsProgram() || c == p {
				continue
			}
			g.addRoot(c, fmt.Sprintf("named in %s, which can exec", p), RootExplicit)
			rooted = append(rooted, c)
		}

		assumed := opts.ExecPolicy == ExecAssumeNone
		detail := fmt.Sprintf("%s can start another program (%s), and the closure follows one process and not what it launches",
			p, pr.Why)
		switch {
		case len(rooted) > 0:
			detail += fmt.Sprintf("; it names %s, rooted here, but a target built at runtime or found on PATH leaves no name to find",
				strings.Join(rooted, ", "))
		default:
			detail += "; it names no program path this image has, so there is nothing to root on its behalf"
		}
		if assumed {
			detail += ". --exec-policy=assume-none says to take what it runs as accounted for"
		} else {
			detail += ". Name what it runs with --roots and re-run with --exec-policy=assume-none"
		}
		g.taints = append(g.taints, Taint{
			Kind:       TaintExec,
			Detail:     detail,
			Path:       p,
			Blocking:   !assumed,
			Global:     !assumed,
			Discharged: assumed,
		})
	}
}

// programs are the tree-absolute paths of every executable in the image, for a
// prober to look for mentions of.
func (g *Graph) programs() []string {
	var out []string
	for _, p := range g.order {
		if g.nodes[p].Info.IsProgram() {
			out = append(out, p)
		}
	}
	return out
}

// wrapperRule parses one exec wrapper's argument grammar and returns the argv it
// forwards to. ok is false when the grammar carries something this parser does
// not understand with certainty -- an option that might take an argument, a
// missing command -- in which case the caller leaves the wrapper in place and
// the closure escalates rather than risk rooting the wrong token.
type wrapperRule func(argv []string) (inner []string, ok bool)

// execWrappers are the argv-forwarding programs that stand in front of a real
// entrypoint. Each execs a specific later token and runs no application code of
// its own, so peeling it reaches the program whose reachability actually
// matters. Shells and process supervisors are deliberately absent: they run
// arbitrary or multiple programs and must still escalate.
var execWrappers = map[string]wrapperRule{
	"tini":        tiniRule,
	"tini-static": tiniRule,
	"dumb-init":   tiniRule,
	"catatonit":   tiniRule,
	"gosu":        gosuRule,
	"su-exec":     gosuRule,
	"env":         envRule,
}

// peelWrappers resolves through the transparent exec wrappers in front of the
// entrypoint, rooting each one it recognizes so the wrapper's own dependencies
// stay reachable, and returns the argv of the program that actually runs.
//
// A wrapper it cannot parse with certainty is returned unpeeled: the wrapper's
// base name is also in shells, so the caller's shell check escalates, which is
// the safe outcome. Each peel consumes at least the wrapper token, so the loop
// terminates.
func (g *Graph) peelWrappers(opts Options, argv []string) []string {
	for len(argv) > 0 {
		base := path.Base(argv[0])
		rule, ok := execWrappers[base]
		if !ok {
			return argv
		}
		inner, ok := rule(argv)
		if !ok {
			return argv
		}
		if p, ok := g.lookupCommand(opts, argv[0]); ok {
			g.addRoot(p, "exec wrapper: "+base, RootExplicit)
		}
		argv = inner
	}
	return argv
}

// tiniRule parses the init shims tini, dumb-init and catatonit: options, then an
// optional "--" separator, then the command. With a separator everything after
// it is the command; without one, the tail is the command only when it carries
// no option tokens, because an option that consumes an argument (tini's
// "-p SIGNAL") would otherwise make the first non-dash token look like the
// program when it is the option's value.
func tiniRule(argv []string) ([]string, bool) {
	rest := argv[1:]
	for i, t := range rest {
		if t == "--" {
			return rest[i+1:], true
		}
	}
	for _, t := range rest {
		if strings.HasPrefix(t, "-") {
			return nil, false
		}
	}
	return rest, true
}

// gosuRule parses gosu and su-exec, which take a user spec and then the command:
// "gosu postgres postgres". Neither has options, so a leading dash is unexpected
// and bails to escalation.
func gosuRule(argv []string) ([]string, bool) {
	if len(argv) < 3 || strings.HasPrefix(argv[1], "-") {
		return nil, false
	}
	return argv[2:], true
}

// envRule parses env: option flags and NAME=value assignments, then the command.
// Only the flags whose argument shape is certain are stepped over; anything else
// that begins with a dash -- notably -S/--split-string, which re-parses a single
// string into arguments -- bails to escalation rather than guess where the
// command begins.
func envRule(argv []string) ([]string, bool) {
	i := 1
	for i < len(argv) {
		t := argv[i]
		switch {
		case t == "--":
			i++
			if i >= len(argv) {
				return nil, false
			}
			return argv[i:], true
		case t == "-", t == "-i", t == "--ignore-environment", t == "-0", t == "--null":
			i++
		case t == "-u", t == "--unset", t == "-C", t == "--chdir":
			i += 2
		case strings.HasPrefix(t, "-"):
			return nil, false
		case isAssignment(t):
			i++
		default:
			return argv[i:], true
		}
	}
	return nil, false
}

// isAssignment reports whether a token is a NAME=value environment assignment
// rather than a command. The "=" has to come before any "/" so a path that
// contains one -- "a=b/c" is an assignment, "/opt/a=b" is a program -- is not
// mistaken for a variable.
func isAssignment(t string) bool {
	eq := strings.Index(t, "=")
	return eq > 0 && !strings.Contains(t[:eq], "/")
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

// walkClosure resolves DT_NEEDED breadth-first from the roots, admitting
// plugin roots as the loaders that would load them come into reach.
//
// The admission is a fixpoint rather than a second pass, because a loader can
// arrive through a plugin: libcrypto is reached from an OpenSSL engine, and an
// engine is only admitted once libcrypto is reached. The queue and the seen set
// are carried across rounds, so an object is still visited at most once and the
// whole thing costs one walk however many rounds it takes.
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
	for {
		// Each time the queue drains, ask which pending plugins the closure has
		// now earned. Nothing admitted means the fixpoint is reached and the
		// rest of g.pending is what no loader in this image could open.
		if len(queue) == 0 {
			admitted := g.admitPlugins()
			if len(admitted) == 0 {
				break
			}
			for _, p := range admitted {
				queue = append(queue, frame{path: p})
			}
			continue
		}

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

	// Plugins admitted mid-walk were appended after the initial sort.
	sort.Strings(g.roots)
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
			assumed := opts.DlopenPolicy == DlopenAssumeNone
			detail := fmt.Sprintf("%s calls dlopen, so what it loads is decided at runtime", p)

			// Before the blanket policy, try the narrower discharge: a known
			// loader family whose plugins live only in directories this graph
			// already roots and walked. When it applies, the closure is not a
			// lower bound for this caller -- everything it can dlopen is already
			// in it -- so the taint is recorded rather than allowed to block,
			// without asserting anything about any other caller. See loaders.go
			// for why each condition is load-bearing.
			bounded := ""
			if !assumed {
				bounded = g.boundedDlopenReason(n.Info.Soname, opts.Config)
			}

			named := matchDlopenAssertion(opts.DlopenAssumeNoneFor, p, n.Info.Soname)

			// The order of these cases is what decides which reason a reader
			// is given when more than one applies, and it puts the named
			// assertion last deliberately: it is the only one of the three
			// that is a claim rather than a finding. The bounded discharge is
			// something the graph worked out; this is something a human
			// promised. Reporting the promise over the proof would tell a
			// reviewer a clean row rests on an assertion when it does not,
			// which is a report being wrong about its own strength in the
			// direction that gets sound evidence discounted.
			switch {
			case assumed:
				detail += ", and --dlopen-policy=assume-none says to take that as loading nothing that matters here"
			case bounded != "":
				detail += ", but " + bounded
			case named != "":
				detail += ", and --dlopen-assume-none names " + named +
					", so the user asserts this caller loads nothing that matters here"
			}

			// A bounded discharge is a discharge in the same sense as the
			// pure-Go and assume-none ones: the taint would have blocked
			// globally, and something answered it. Recording it as such keeps
			// the clean verdict auditable -- a reader sees the closure rests on
			// the loader being confined, not on nothing ever having threatened.
			discharged := assumed || bounded != "" || named != ""
			g.taints = append(g.taints, Taint{
				Kind:       TaintDlopen,
				Detail:     detail,
				Path:       p,
				Blocking:   !discharged,
				Global:     !discharged,
				Discharged: discharged,
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
			blocking := explicit

			// A static entrypoint blocks because it may carry a copy of the
			// vulnerable code inside it, where DT_NEEDED cannot see it. A
			// prober can discharge exactly that: a binary it can account for --
			// a pure-Go CGO_ENABLED=0 build links no C library -- has nothing
			// hidden, so the unreferenced .so on disk is the real answer and
			// the taint is recorded rather than allowed to block.
			var probed string
			if blocking && opts.StaticProber != nil {
				// pr.Why is part of the condition, not just the message: an
				// unexplained discharge would be indistinguishable in the
				// output from no discharge at all.
				if pr, ok := opts.StaticProber(g.fsys, p); ok && pr.Closed && pr.Why != "" {
					blocking = false
					probed = pr.Why
				}
			}

			detail := fmt.Sprintf("%s is statically linked, so the libraries it uses are inside it and not on disk", p)
			switch {
			case probed != "":
				detail += ", but " + probed
			case !explicit:
				detail += " (not the entrypoint, so this is recorded rather than blocking)"
			}
			g.taints = append(g.taints, Taint{
				Kind:     TaintStaticELF,
				Detail:   detail,
				Path:     p,
				Blocking: blocking,
				Global:   blocking,
				// Only the entrypoint case is a discharge. A static utility
				// that is not a root never blocked, so recording it as
				// "answered" would claim a test that never ran.
				Discharged: explicit && !blocking,
			})
		}
	}
	g.collectInertAssertions(opts)
}

// collectInertAssertions records every --dlopen-assume-none name that answered
// no caller.
//
// The match is recomputed here over all dlopen callers rather than being
// collected as the taints were built, because a name is not inert merely
// because it lost. A caller the bounded-loader discharge already answered
// reports that answer instead of the assertion, which is right -- the graph's
// own finding is the better evidence -- but the user's name did find its
// caller, and telling them it matched nothing would send them looking for a
// typo that is not there.
func (g *Graph) collectInertAssertions(opts Options) {
	matched := map[string]bool{}
	for _, p := range g.order {
		n := g.nodes[p]
		if !n.Reachable || !n.Info.Dlopen {
			continue
		}
		if m := matchDlopenAssertion(opts.DlopenAssumeNoneFor, p, n.Info.Soname); m != "" {
			matched[m] = true
		}
	}

	for _, name := range opts.DlopenAssumeNoneFor {
		if matched[name] {
			continue
		}
		why := "is not a reachable object in this image"
		if _, ok := g.Node(name); ok {
			why = "is in this image but calls no dlopen the closure reached"
		}
		g.taints = append(g.taints, Taint{
			Kind: TaintInertAssertion,
			Detail: fmt.Sprintf("--dlopen-assume-none names %s, which %s, so the assertion discharged nothing",
				name, why),
			Path: name,
			// Never blocking, and never a discharge: nothing was answered and
			// nothing was waved away. See TaintInertAssertion.
			Blocking: false,
		})
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

// boundedDlopenReason decides whether a reachable dlopen caller can be
// discharged because it is a recognised loader family confined to plugin
// directories this graph already roots. It returns the evidence clause naming
// why when it can, and "" when it cannot -- in which case the caller keeps the
// global blocking dlopen taint.
//
// All three conditions from loaders.go are enforced here, and the order is
// cheapest-first. The soname allowlist is the identity check; a redirect env
// set in the config voids the bound; a config file that can name a module by
// absolute path voids it too; and the plugin dir must be present and rooted in
// THIS image, so the discharge rests on alwaysRoot having actually pulled the
// plugins into the closure rather than on the assumption that it would have.
func (g *Graph) boundedDlopenReason(soname string, cfg target.ImageConfig) string {
	fam, ok := boundedLoader(soname)
	if !ok {
		return ""
	}
	if fam.redirected(cfg) {
		// The image points the loader somewhere the closure did not follow, so
		// what it loads is no longer bounded to the rooted dirs. Stay blocking.
		return ""
	}
	if fam.configRedirect != nil && fam.configRedirect(g.fsys) {
		// An environment variable is not the only way to redirect this loader:
		// its config file can name a plugin by absolute path with no variable
		// set. When the config could do that -- or cannot be read to rule it
		// out -- the closure is a lower bound again, so stay blocking.
		return ""
	}
	rooted := g.rootedPluginDirs(fam.pluginDirs)
	if len(rooted) == 0 {
		return ""
	}
	return fam.reason(rooted)
}

// rootedPluginDirs returns the given plugin directories that hold at least one
// rooted plugin node in this graph. It is the proof that the loader family's
// plugins were actually rooted and walked here, not merely that they would be
// in some canonical image -- an OpenSSL build with no providers on disk roots
// nothing in ossl-modules, and its libcrypto stays blocking because the
// discharge has nothing to stand on.
//
// Only the dirs that really matched are returned, so the evidence line names
// the directories the bound rests on rather than the ones the family could have
// used. An image with engines and no providers should not be described as
// bounded by a directory it does not have.
func (g *Graph) rootedPluginDirs(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		for _, p := range g.order {
			n := g.nodes[p]
			if !n.Root || n.Kind != RootPlugin {
				continue
			}
			if strings.Contains(p, d) {
				out = append(out, strings.Trim(d, "/"))
				break
			}
		}
	}
	return out
}

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

// pluginFamily is a class of object the runtime opens by name rather than
// through DT_NEEDED, together with what does the opening.
type pluginFamily struct {
	// what names the family, with its article, for the root's Why line and for
	// the evidence on a package whose plugins were left out.
	what string
	// plural is what for more than one of them.
	plural string

	// loader is the soname stem of the one library that loads this family --
	// "libpam.so", which matches libpam.so.0 and libpam.so.0.84.2 alike -- or ""
	// when this package cannot name a single loader, in which case the plugin is
	// rooted unconditionally as it always was.
	loader string
}

// pluginFamilies are the runtime-loaded plugin classes, in match order.
//
// Only the families whose loader is a specific library are gated. The other two
// are loaded by a program -- a .node addon by whatever JavaScript runtime calls
// require, a site-packages extension by whatever embeds or is CPython -- and the
// set of programs that qualify is open-ended enough (node, bun, deno, electron;
// python3.11, uwsgi, anything linking libpython) that a rule naming them would
// be a guess. A guess in this direction is a false negative, so they keep the
// unconditional rooting and cost what they always cost.
var pluginFamilies = []struct {
	match func(p, base string) bool
	fam   pluginFamily
}{
	{
		func(p, base string) bool { return strings.HasPrefix(base, "libnss_") && isSharedObject(base) },
		pluginFamily{"a glibc NSS module", "glibc NSS modules", "libc.so"},
	},
	{
		func(p, base string) bool { return strings.HasPrefix(base, "pam_") && strings.Contains(p, "/security/") },
		pluginFamily{"a PAM module", "PAM modules", "libpam.so"},
	},
	{
		func(p, base string) bool { return strings.Contains(p, "/gconv/") },
		pluginFamily{"an iconv character-set converter", "iconv character-set converters", "libc.so"},
	},
	{
		func(p, base string) bool { return strings.Contains(p, "/engines-") },
		pluginFamily{"an OpenSSL engine", "OpenSSL engines", "libcrypto.so"},
	},
	{
		func(p, base string) bool { return strings.Contains(p, "/ossl-modules/") },
		pluginFamily{"an OpenSSL provider", "OpenSSL providers", "libcrypto.so"},
	},
	{
		func(p, base string) bool { return strings.HasSuffix(base, ".node") },
		pluginFamily{"a Node.js native addon", "Node.js native addons", ""},
	},
	{
		func(p, base string) bool {
			return isSharedObject(base) && (strings.Contains(p, "/site-packages/") ||
				strings.Contains(p, "/dist-packages/") || strings.Contains(p, "/lib-dynload/"))
		},
		pluginFamily{"a Python extension module", "Python extension modules", ""},
	},
}

// pluginClass reports whether a path is a plugin the runtime loads by name
// rather than by DT_NEEDED, and which family it belongs to.
func pluginClass(p string) (pluginFamily, bool) {
	base := path.Base(p)
	for _, r := range pluginFamilies {
		if r.match(p, base) {
			return r.fam, true
		}
	}
	return pluginFamily{}, false
}

// pendingPlugin is a plugin whose family has a named loader, waiting to see
// whether the closure reaches it.
type pendingPlugin struct {
	path string
	fam  pluginFamily
}

// admitPlugins roots the pending plugins whose loader the closure has reached,
// and returns them so the caller can walk on from there.
//
// This is the one place the closure decides *not* to look at code that is
// sitting in the image, so it is worth being exact about why it is sound. A
// plugin is not reached by DT_NEEDED from anything; it is opened by name, and
// by one specific library -- dlopen("libnss_files.so.2") lives in glibc,
// dlopen of a PAM module lives in libpam, an engine is opened by libcrypto. If
// no object the closure reaches is that library, then no code that runs in this
// image contains the call that would open the plugin, and the plugin is as dead
// as a library nothing has a DT_NEEDED on.
//
// What it does not cover is a program the closure never modelled execing
// something that does load the plugin. That is the same residual the closure
// already carries everywhere -- it models one process image, not a process tree
// -- and it is the case escalation exists for: an image whose entrypoint is a
// shell, or unknown, roots every program, which reaches libc and libpam and
// libcrypto, which admits every plugin. The narrowing only ever applies to an
// image that said what it runs.
func (g *Graph) admitPlugins() []string {
	if len(g.pending) == 0 {
		return nil
	}
	loaders := g.reachableLoaders()

	var admitted []string
	var still []pendingPlugin
	for _, pp := range g.pending {
		// Already in the closure by a stronger route: named with --roots, swept
		// up by escalation, or actually the target of somebody's DT_NEEDED. It
		// is not waiting on a loader, and reporting it as left out would put a
		// sentence in the evidence that the closure's own answer contradicts.
		if n := g.nodes[pp.path]; n != nil && (n.Root || n.Reachable) {
			continue
		}

		by, ok := loaders[pp.fam.loader]
		if !ok {
			still = append(still, pp)
			continue
		}
		g.addRoot(pp.path, fmt.Sprintf("%s, which %s opens by name", pp.fam.what, by), RootPlugin)
		admitted = append(admitted, pp.path)
	}
	g.pending = still
	return admitted
}

// reachableLoaders maps each loader soname stem a pending plugin is waiting on
// to a reachable object that provides it.
//
// Both DT_SONAME and the file name are matched, because the name is what
// DT_NEEDED resolution would have used for an object that declares no soname,
// and admitting a plugin on a weaker match errs towards a larger closure.
func (g *Graph) reachableLoaders() map[string]string {
	want := map[string]bool{}
	for _, pp := range g.pending {
		want[pp.fam.loader] = true
	}

	out := map[string]string{}
	for _, p := range g.order {
		n := g.nodes[p]
		if !n.Reachable {
			continue
		}
		for stem := range want {
			if _, done := out[stem]; done {
				continue
			}
			if matchesSoname(n.Info.Soname, stem) || matchesSoname(path.Base(p), stem) {
				out[stem] = p
			}
		}
	}
	return out
}

// matchesSoname reports whether a soname is a version of a stem: "libcrypto.so"
// matches libcrypto.so and libcrypto.so.3 but not libcryptsetup.so.12.
func matchesSoname(soname, stem string) bool {
	return soname == stem || strings.HasPrefix(soname, stem+".")
}

// GatedPlugin is a runtime-loaded plugin the closure left out because no object
// it reaches could open one.
type GatedPlugin struct {
	// Path is the plugin.
	Path string
	// What and Plural name its family, for prose.
	What, Plural string
	// Loader is the soname stem of the library that would have opened it, and
	// that the closure does not reach.
	Loader string
}

// GatedPlugins returns the plugins admitPlugins declined, in path order.
//
// Callers report them. A package whose only code is a PAM module no libpam
// could open is genuinely unreachable, but "the linker would not load it" is a
// thinner account than the one this package actually has, and the reader
// deciding whether to believe the row is owed the real one.
func (g *Graph) GatedPlugins() []GatedPlugin {
	out := make([]GatedPlugin, 0, len(g.pending))
	for _, pp := range g.pending {
		out = append(out, GatedPlugin{
			Path: pp.path, What: pp.fam.what, Plural: pp.fam.plural, Loader: pp.fam.loader,
		})
	}
	return out
}

// gatedSummary is the scan-log line for what the gating left out, or "" when it
// left out nothing.
func (g *Graph) gatedSummary() string {
	if len(g.pending) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, pp := range g.pending {
		counts[pp.fam.loader]++
	}
	stems := make([]string, 0, len(counts))
	for s := range counts {
		stems = append(stems, s)
	}
	sort.Slice(stems, func(i, j int) bool {
		if counts[stems[i]] != counts[stems[j]] {
			return counts[stems[i]] > counts[stems[j]]
		}
		return stems[i] < stems[j]
	})
	parts := make([]string, 0, len(stems))
	for _, s := range stems {
		parts = append(parts, fmt.Sprintf("%d need %s", counts[s], s))
	}
	return fmt.Sprintf("%d runtime-loaded plugin(s) left out, nothing reachable opens them: %s",
		len(g.pending), strings.Join(parts, ", "))
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

// InertAssertions are the --dlopen-assume-none names this image gave nothing to
// discharge, in the order the user gave them.
//
// It reads back the taints rather than being returned from Build because the
// caller that needs it is not the caller that builds the graph: the report
// states the assertion, and the assertion is only honest if it also says which
// parts of it did no work.
func (g *Graph) InertAssertions() []string {
	var out []string
	for _, t := range g.taints {
		if t.Kind == TaintInertAssertion {
			out = append(out, t.Path)
		}
	}
	return out
}
