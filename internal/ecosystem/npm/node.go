package npm

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/target"
)

// node is modgraph.Language for Node.js: it turns an image config into entry
// files and resolves require/import specifiers the way Node's module loader
// would.
//
// It sits beside the inventory for the same reason the Python one does. The
// resolver's whole job is walking node_modules directories, and node_modules
// is exactly what the inventory already found; discovering it twice is how the
// two come to disagree about which copy of a package a file sees.
type node struct {
	fsys target.RootFS
	cfg  target.ImageConfig
	res  langdb.Result

	// byDir indexes installed packages by their directory, so a resolved file
	// can be attributed to the package that owns it without a second walk.
	byDir map[string]langdb.Package

	// resolved memoizes resolution, keyed by the directory a specifier was
	// resolved from plus the specifier. Node's answer genuinely depends on
	// both -- that is what nested node_modules means -- so the importing
	// directory cannot be dropped from the key the way a Python sys.path
	// lookup can.
	resolved map[string][]string

	// scopes memoizes dependency closures by package directory. A computed
	// require is common enough in a real tree -- npm's own CLI has one -- that
	// walking the same closure once per file would be the plugin's slowest part.
	scopes map[string]scopeResult

	logf func(format string, args ...any)
}

// maxSource caps how much of one file is scanned. A .js larger than this is a
// bundle or a generated table, and a bundle's imports are not on disk under
// names an inventory knows -- which is what the bundled-entrypoint taint is
// for, not something a longer read would fix.
const maxSource = 8 << 20

// jsExts are the extensions Node probes, in the order it probes them.
var jsExts = []string{".js", ".json", ".node", ".mjs", ".cjs"}

func newNode(img *target.Image, res langdb.Result, logf func(string, ...any)) *node {
	n := &node{
		fsys:     img.FS,
		cfg:      img.Config,
		res:      res,
		byDir:    make(map[string]langdb.Package, len(res.Packages)),
		resolved: map[string][]string{},
		scopes:   map[string]scopeResult{},
		logf:     logf,
	}
	for _, pkg := range res.Packages {
		n.byDir[pkg.Dir] = pkg
	}
	return n
}

func (n *node) ID() string { return "node" }

// Roots turns argv into entry files.
func (n *node) Roots(extra []string) ([]modgraph.Root, []modgraph.Taint, error) {
	roots, taints := n.entryRoots()

	var explicit bool
	for _, e := range extra {
		for _, f := range n.explicitRoot(e) {
			roots = append(roots, modgraph.Root{Path: f, Why: "named by --roots", Kind: modgraph.RootExplicit})
			explicit = true
		}
	}

	// The same reasoning as the Python plugin's: --roots exists for exactly
	// the image these two taints describe, and answering "what runs is
	// unknown" after the user has said what runs would leave the flag unable
	// to change any conclusion. The assertion is recorded rather than dropped.
	if explicit {
		for i, t := range taints {
			switch t.Kind {
			case modgraph.TaintNoEntrypoint, modgraph.TaintForeignEntrypoint:
				taints[i].Detail = t.Detail + ", so the closure was rooted at --roots instead"
				taints[i].Blocking = false
				taints[i].Global = false
			}
		}
	}

	// A bundler compiles a program's dependencies into the program, so the
	// files carrying the vulnerable code are not on disk under the names the
	// inventory knows. An entrypoint that can see no node_modules at all is
	// how that looks from here, and saying so out loud is the difference
	// between a reported limitation and a scan that reads clean.
	taints = append(taints, n.bundledTaint(roots)...)

	if !hasRunnable(roots) {
		roots = append(roots, n.escalate()...)
	}
	return roots, taints, nil
}

// hasRunnable reports whether anything other than a package-declared hook was
// rooted.
func hasRunnable(roots []modgraph.Root) bool {
	for _, r := range roots {
		if r.Kind != modgraph.RootPlugin {
			return true
		}
	}
	return false
}

// entryRoots reads argv the way the kernel and the shell would.
func (n *node) entryRoots() ([]modgraph.Root, []modgraph.Taint) {
	argv := n.cfg.Argv()
	if len(argv) == 0 {
		return nil, []modgraph.Taint{{
			Kind:     modgraph.TaintNoEntrypoint,
			Detail:   "the image config has neither Entrypoint nor Cmd, so what it runs is unknown",
			Blocking: true,
			Global:   true,
		}}
	}

	base := path.Base(argv[0])
	switch {
	case base == "node" || base == "nodejs":
		return n.interpreterRoots(argv)
	case base == "npm" || base == "yarn" || base == "pnpm":
		return n.packageManagerRoots(argv)
	}

	// A bin shim -- the executables npm links into node_modules/.bin and
	// /usr/local/bin -- is a JavaScript file with a #! line. Rooting it is the
	// difference between analysing the application and giving up on every
	// image whose entrypoint is an installed command.
	if cmd := n.lookupCommand(argv[0]); cmd != "" && n.isNodeScript(cmd) {
		return []modgraph.Root{{
			Path: cmd,
			Why:  "the entrypoint is a Node script: " + strings.Join(argv, " "),
			Kind: modgraph.RootEntry,
		}}, nil
	}

	return nil, []modgraph.Taint{{
		Kind:     modgraph.TaintForeignEntrypoint,
		Detail:   fmt.Sprintf("the entrypoint %q is not node or a Node script, so what it requires is unknown", strings.Join(argv, " ")),
		Blocking: true,
		Global:   true,
	}}
}

// interpreterRoots reads a `node` command line: flags, then a script or -e.
func (n *node) interpreterRoots(argv []string) ([]modgraph.Root, []modgraph.Taint) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-e" || a == "--eval" || a == "-p" || a == "--print":
			return nil, []modgraph.Taint{{
				Kind:     modgraph.TaintDynamicImport,
				Detail:   "the entrypoint is node " + a + ", whose code is in the config rather than on disk",
				Blocking: true,
				Global:   true,
			}}

		case strings.HasPrefix(a, "-"):
			if takesValue(a) && i+1 < len(argv) {
				i++
			}

		default:
			files := n.resolveEntry(a)
			if len(files) == 0 {
				return nil, []modgraph.Taint{{
					Kind:     modgraph.TaintUnresolvedImport,
					Detail:   "the entrypoint script " + a + " is not in the image",
					Spec:     a,
					Blocking: true,
					Global:   true,
				}}
			}
			var roots []modgraph.Root
			for _, f := range files {
				roots = append(roots, modgraph.Root{Path: f, Why: "the entrypoint script", Kind: modgraph.RootEntry})
			}
			return roots, nil
		}
	}

	// Bare "node": a REPL. Nothing runs until someone types something, and
	// what they type can require anything installed.
	return nil, []modgraph.Taint{{
		Kind:     modgraph.TaintNoEntrypoint,
		Detail:   "the entrypoint is an interactive Node REPL, which can require anything installed",
		Blocking: true,
		Global:   true,
	}}
}

// packageManagerRoots reads `npm start` / `yarn run build` and follows the
// script it names back into the package.json that declares it.
//
// The script body is a shell command, not JavaScript, so only the part of it
// that looks like a node invocation is followed. That is the overwhelmingly
// common shape ("node server.js", "node dist/index.js"); anything else is a
// foreign entrypoint by another route and says so.
func (n *node) packageManagerRoots(argv []string) ([]modgraph.Root, []modgraph.Taint) {
	name := "start"
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "-") {
			continue
		}
		if a == "run" || a == "run-script" {
			if i+1 < len(argv) {
				name = argv[i+1]
			}
			break
		}
		if a == "start" || a == "test" {
			name = a
			break
		}
		// `npm exec`, `npm ci`, `npx something`: not a declared script.
		name = ""
		break
	}

	dir := n.cfg.WorkingDir
	if dir == "" {
		dir = "/"
	}
	script := ""
	if name != "" {
		script = n.packageScript(dir, name)
	}
	if script == "" {
		return nil, []modgraph.Taint{{
			Kind: modgraph.TaintForeignEntrypoint,
			Detail: fmt.Sprintf("the entrypoint %q runs a package script that could not be read from %s/package.json",
				strings.Join(argv, " "), dir),
			Blocking: true,
			Global:   true,
		}}
	}

	fields := strings.Fields(script)
	for i, f := range fields {
		if b := path.Base(f); b != "node" && b != "nodejs" {
			continue
		}
		sub := append([]string{"node"}, fields[i+1:]...)
		roots, taints := n.withWorkingDir(dir, func() ([]modgraph.Root, []modgraph.Taint) {
			return n.interpreterRoots(sub)
		})
		for i := range roots {
			roots[i].Why = fmt.Sprintf("the %q script runs %s", name, script)
		}
		return roots, taints
	}

	return nil, []modgraph.Taint{{
		Kind:     modgraph.TaintForeignEntrypoint,
		Detail:   fmt.Sprintf("the %q script is %q, which does not run node directly", name, script),
		Blocking: true,
		Global:   true,
	}}
}

// withWorkingDir runs f with the config's working directory temporarily set,
// so a script declared in /app/package.json resolves its relative paths
// against /app rather than against wherever the image happens to start.
func (n *node) withWorkingDir(dir string, f func() ([]modgraph.Root, []modgraph.Taint)) ([]modgraph.Root, []modgraph.Taint) {
	prev := n.cfg.WorkingDir
	n.cfg.WorkingDir = dir
	defer func() { n.cfg.WorkingDir = prev }()
	return f()
}

// packageScript reads one entry out of a package.json's "scripts".
func (n *node) packageScript(dir, name string) string {
	m, ok := n.manifest(path.Join(dir, "package.json"))
	if !ok {
		return ""
	}
	return strings.TrimSpace(m.Scripts[name])
}

// escalate roots every installed package's own entry point.
//
// This is what the graph does when it cannot tell what runs, and it differs
// from the Python plugin's escalation on purpose. Rooting every module file in
// node_modules would mean reading a hundred thousand files to establish
// something the entry points already establish: every installed package is
// reachable. A package whose manifest names no entry and that has no index
// falls back to its own files, so nothing can be silently left unreached.
func (n *node) escalate() []modgraph.Root {
	// Phrased as a noun: the evidence renders this as "<file> is <why>".
	const why = "an entry point of an installed package, rooted because this image's own entrypoint could not be resolved"
	var roots []modgraph.Root
	for _, pkg := range n.res.Packages {
		files := n.packageEntries(pkg)
		if len(files) == 0 {
			for _, f := range pkg.Files {
				if n.IsModule(f) {
					files = append(files, f)
				}
			}
		}
		for _, f := range files {
			roots = append(roots, modgraph.Root{Path: f, Why: why, Kind: modgraph.RootEscalated})
		}
	}
	return roots
}

// packageEntries are the files loading a package by name can start at: its
// main/exports entry and every executable it declares.
func (n *node) packageEntries(pkg langdb.Package) []string {
	var out []string
	out = append(out, n.packageMain(pkg.Dir)...)
	m, ok := n.manifest(path.Join(pkg.Dir, "package.json"))
	if ok {
		for _, rel := range m.binPaths() {
			out = append(out, n.probeFile(path.Join(pkg.Dir, rel))...)
		}
	}
	return dedupe(out)
}

// bundledTaint reports an entrypoint that can see no node_modules.
func (n *node) bundledTaint(roots []modgraph.Root) []modgraph.Taint {
	for _, r := range roots {
		if r.Kind != modgraph.RootEntry && r.Kind != modgraph.RootExplicit {
			continue
		}
		if len(n.nodeModulesAbove(path.Dir(r.Path))) > 0 {
			return nil
		}
	}
	// No entry root at all is a different failure, already reported by the
	// entrypoint taints. Only claim bundling when there is an entrypoint and
	// it has nowhere to resolve a bare specifier from.
	for _, r := range roots {
		if r.Kind == modgraph.RootEntry || r.Kind == modgraph.RootExplicit {
			return []modgraph.Taint{{
				Kind: modgraph.TaintBundled,
				Detail: fmt.Sprintf("no node_modules directory is visible from the entrypoint %s, so its dependencies were compiled into it and are not on disk under the names this inventory knows",
					r.Path),
				Path:     r.Path,
				Blocking: true,
				Global:   true,
			}}
		}
	}
	return nil
}

// explicitRoot accepts either a path or a bare package name from --roots.
func (n *node) explicitRoot(v string) []string {
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, ".") {
		if f := n.probeFile(path.Clean("/" + v)); len(f) > 0 {
			return f
		}
		if f := n.packageMain(path.Clean("/" + v)); len(f) > 0 {
			return f
		}
		return nil
	}
	// A bare name is a package: resolve it the way a program in the image's
	// working directory would.
	wd := n.cfg.WorkingDir
	if wd == "" {
		wd = "/"
	}
	files, _ := n.resolveBare(wd, v)
	return files
}

// resolveEntry turns a `node X` argument into files, honouring WorkingDir.
func (n *node) resolveEntry(arg string) []string {
	wd := n.cfg.WorkingDir
	if wd == "" {
		wd = "/"
	}
	var cands []string
	if strings.HasPrefix(arg, "/") {
		cands = []string{path.Clean(arg)}
	} else {
		cands = []string{path.Join(wd, arg), path.Clean("/" + arg)}
	}
	for _, c := range cands {
		if f := n.probeFile(c); len(f) > 0 {
			return f
		}
		if f := n.packageMain(c); len(f) > 0 {
			return f
		}
	}
	return nil
}

// lookupCommand resolves argv[0] through PATH.
func (n *node) lookupCommand(cmd string) string {
	if strings.Contains(cmd, "/") {
		c := path.Clean("/" + cmd)
		if _, err := n.fsys.Stat(c); err == nil {
			return c
		}
		return ""
	}
	for _, dir := range n.cfg.PathDirs() {
		c := path.Join(dir, cmd)
		if _, err := n.fsys.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// isNodeScript reports whether a file's #! line names node.
func (n *node) isNodeScript(file string) bool {
	data, err := n.fsys.ReadFile(file)
	if err != nil || !strings.HasPrefix(string(data), "#!") {
		return false
	}
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	for _, f := range strings.Fields(line) {
		if b := path.Base(f); b == "node" || b == "nodejs" {
			return true
		}
	}
	return false
}

// takesValue reports whether a node flag consumes the next argument.
func takesValue(flag string) bool {
	switch flag {
	case "-r", "--require", "--import", "--loader", "--experimental-loader",
		"--max-old-space-size", "--stack-size", "--conditions", "-C":
		return true
	}
	return false
}

// IsModule reports whether a path is something Node's loader would load.
//
// ".json" counts. A required JSON file is a module Node evaluates, and
// including it means a package reached only through its data still reads as
// reached -- the safe direction. What keeps a data-only package from looking
// like code is codeFiles in evaluate.go, which excludes JSON before the graph
// is ever consulted.
//
// ".ts" and ".d.ts" do not count: TypeScript is compiled before it runs, and
// a types-only package ships nothing Node can load.
func (n *node) IsModule(f string) bool {
	if strings.HasSuffix(f, ".d.ts") {
		return false
	}
	switch path.Ext(f) {
	case ".js", ".mjs", ".cjs", ".json", ".node":
		return true
	}
	return false
}

// Imports scans one file for what it loads.
func (n *node) Imports(file string) ([]modgraph.Spec, []modgraph.Taint, error) {
	switch path.Ext(file) {
	case ".js", ".mjs", ".cjs":
	case ".json":
		// Data. It requires nothing.
		return nil, nil, nil
	case ".node":
		// A compiled addon. What it links against is elfgraph's question, and
		// it is asked there.
		return nil, nil, nil
	default:
		// A bin shim has no extension at all. It is JavaScript when its #!
		// says so, and skipping it would break every image whose entrypoint is
		// an installed command.
		if !n.isNodeScript(file) {
			return nil, nil, nil
		}
	}

	info, err := n.fsys.Stat(file)
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > maxSource {
		return nil, nil, nil
	}
	data, err := n.fsys.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}

	sr := scanJS(data)
	var taints []modgraph.Taint
	if len(sr.computed) > 0 {
		detail := fmt.Sprintf("requires a module named at runtime (line %d)", sr.computed[0])
		owner := n.ownerDir(file)
		scope, complete := n.dynamicScope(owner)
		if owner != "" && complete && len(scope) > 0 {
			detail += ", which could be this package or anything it depends on"
		}
		taints = append(taints, modgraph.Taint{
			Kind:     modgraph.TaintDynamicImport,
			Detail:   detail,
			Path:     file,
			Scope:    scope,
			Blocking: true,
			// Application code, which no installed package owns, is bounded by
			// nothing: it can require anything in the image. So is a package
			// whose own dependency closure could not be walked.
			Global: owner == "" || !complete,
		})
	}
	return sr.specs, taints, nil
}

// ownerDir is the directory of the installed package a file belongs to, or ""
// when no installed package owns it -- that is, when it is application code.
func (n *node) ownerDir(file string) string {
	best := ""
	for dir := range n.byDir {
		if strings.HasPrefix(file, dir+"/") && len(dir) > len(best) {
			best = dir
		}
	}
	return best
}

// dynamicScope is the set of package names a computed require inside dir could
// load, and whether that set is known to be complete.
//
// Scoping a dynamic import to the package that contains it -- the obvious
// reading, and the one this plugin shipped first -- is worse than useless: it
// is inert. A taint only blocks a conclusion about a package in its scope, and
// the package running the computed require is reached by definition, so it was
// already going to be linked. Nothing else could ever be blocked, and npm's own
// CLI proved it: `require(cliEntry)` in lib/cli.js hid every one of npm's 68
// dependencies behind a taint that blocked none of them, and tar came back
// not_in_execute_path in an image that demonstrably loads it.
//
// What a computed require can actually reach is bounded, though, and the bound
// is written down: a bare specifier resolves only to something the package
// declares as a dependency, and from there to that dependency's own. So the
// scope is the transitive dependency closure, which stays narrow for a leaf
// package and correctly widens to everything for a top-level application.
//
// When any manifest in that walk cannot be read, or names a dependency that is
// not installed where the resolver can see it, the closure is not knowable and
// the caller must fall back to a global taint. Guessing small in that direction
// is what produces a false clean.
func (n *node) dynamicScope(dir string) (names []string, complete bool) {
	if hit, ok := n.scopes[dir]; ok {
		return hit.names, hit.complete
	}
	// Memoized before the walk as well as after: a dependency cycle is normal
	// in npm trees, and this is what stops one from recursing forever.
	n.scopes[dir] = scopeResult{complete: true}

	seenName := map[string]bool{}
	seenDir := map[string]bool{}
	complete = true

	queue := []string{dir}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seenDir[d] {
			continue
		}
		seenDir[d] = true

		pkg, ok := n.byDir[d]
		if !ok {
			continue
		}
		if !seenName[pkg.Name] {
			seenName[pkg.Name] = true
			names = append(names, pkg.Name)
		}

		m, ok := n.manifest(path.Join(d, "package.json"))
		if !ok {
			// The inventory found this package, so its manifest parsed once.
			// If it will not parse now, what it depends on is unknown.
			complete = false
			continue
		}
		for _, dep := range m.depNames() {
			found := false
			for _, nmDir := range n.nodeModulesAbove(d) {
				cand := path.Join(nmDir, dep)
				if _, ok := n.byDir[cand]; ok {
					queue = append(queue, cand)
					found = true
					break
				}
			}
			if !found {
				// A declared dependency the resolver cannot locate. It may be
				// installed somewhere this walk does not model, so the closure
				// cannot be called complete.
				complete = false
			}
		}
	}

	sort.Strings(names)
	n.scopes[dir] = scopeResult{names: names, complete: complete}
	return names, complete
}

// scopeResult memoizes one dependency closure.
type scopeResult struct {
	names    []string
	complete bool
}

// Resolve maps a specifier onto files, following Node's resolution algorithm.
func (n *node) Resolve(from string, spec modgraph.Spec) ([]string, bool) {
	name := spec.Name
	if isBuiltin(name) {
		// Compiled into the node binary: there is no file to find, and
		// reporting one missing would be a taint on correct code.
		return nil, true
	}

	dir := path.Dir(from)
	key := dir + "\x00" + name
	if cached, ok := n.resolved[key]; ok {
		return cached, len(cached) > 0
	}

	var out []string
	switch {
	case strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") || name == "." || name == "..":
		out = n.resolveRelative(dir, name)
	case strings.HasPrefix(name, "/"):
		out = n.resolveRelative("/", strings.TrimPrefix(name, "/"))
	case strings.HasPrefix(name, "#"):
		// A package-internal "imports" alias. The map is in the owning
		// package.json and is the same tractable-subset problem as "exports";
		// unlike exports it is rare, so it is left unresolved and scoped.
		out = nil
	default:
		out, _ = n.resolveBare(dir, name)
	}

	out = dedupe(out)
	n.resolved[key] = out
	return out, len(out) > 0
}

// resolveRelative applies Node's file-then-directory rules under one directory.
func (n *node) resolveRelative(dir, name string) []string {
	target := path.Join(dir, name)
	if f := n.probeFile(target); len(f) > 0 {
		return f
	}
	return n.packageMain(target)
}

// resolveBare walks node_modules upward from the importing directory, which is
// how Node decides *which copy* of a package a file sees. It returns the
// package directory it landed in alongside the files, because the mined-module
// layer needs to know which installed instance answered.
func (n *node) resolveBare(dir, name string) ([]string, string) {
	pkgName, sub := splitSpecifier(name)
	if pkgName == "" {
		return nil, ""
	}
	for _, nm := range n.nodeModulesAbove(dir) {
		base := path.Join(nm, pkgName)
		if info, err := n.fsys.Stat(base); err != nil || !info.IsDir() {
			continue
		}
		if files := n.resolveInPackage(base, sub); len(files) > 0 {
			return files, base
		}
		// The directory exists and nothing in it matched. Node would stop
		// here, and so does this: continuing would find a different copy of
		// the package than the one the runtime loads.
		return nil, base
	}
	return nil, ""
}

// resolveInPackage maps a subpath ("" for the package itself) onto files
// inside one installed package directory.
func (n *node) resolveInPackage(base, sub string) []string {
	m, hasManifest := n.manifest(path.Join(base, "package.json"))

	if sub == "" {
		if hasManifest {
			if files := n.fromExports(base, m, "."); files != nil {
				return files
			}
		}
		return n.packageMain(base)
	}

	if hasManifest && m.Exports != nil {
		if files := n.fromExports(base, m, "./"+sub); files != nil {
			return files
		}
		// An "exports" map that does not cover this subpath means Node would
		// refuse the require outright. Probing anyway over-approximates, which
		// is the safe direction: a file that is on disk and might be loaded is
		// better counted than a conclusion resting on a map this resolver only
		// partly understands.
	}
	target := path.Join(base, sub)
	if f := n.probeFile(target); len(f) > 0 {
		return f
	}
	return n.packageMain(target)
}

// packageMain resolves a directory the way Node does: its manifest's "main",
// then its index file.
func (n *node) packageMain(dir string) []string {
	if m, ok := n.manifest(path.Join(dir, "package.json")); ok {
		if main := strings.TrimSpace(m.Main); main != "" {
			target := path.Join(dir, main)
			if f := n.probeFile(target); len(f) > 0 {
				return f
			}
			// "main": "lib" is legal and means lib/index.js.
			if f := n.probeIndex(target); len(f) > 0 {
				return f
			}
		}
	}
	return n.probeIndex(dir)
}

// probeFile applies Node's extension probing to an exact path.
func (n *node) probeFile(target string) []string {
	if n.isFile(target) {
		return []string{target}
	}
	for _, ext := range jsExts {
		if f := target + ext; n.isFile(f) {
			return []string{f}
		}
	}
	return nil
}

// probeIndex looks for a directory's index file.
func (n *node) probeIndex(dir string) []string {
	for _, ext := range jsExts {
		if f := path.Join(dir, "index"+ext); n.isFile(f) {
			return []string{f}
		}
	}
	return nil
}

func (n *node) isFile(f string) bool {
	info, err := n.fsys.Stat(f)
	return err == nil && !info.IsDir()
}

// nodeModulesAbove lists the node_modules directories a file at dir can see,
// nearest first. That order is the resolution order, and it is the whole
// mechanism by which two versions of one package coexist in a tree.
func (n *node) nodeModulesAbove(dir string) []string {
	var out []string
	for d := path.Clean(dir); ; d = path.Dir(d) {
		if path.Base(d) != "node_modules" {
			nm := path.Join(d, "node_modules")
			if info, err := n.fsys.Stat(nm); err == nil && info.IsDir() {
				out = append(out, nm)
			}
		}
		if d == "/" {
			break
		}
	}
	return out
}

// splitSpecifier separates a bare specifier's package name from its subpath,
// keeping a scope attached to the name: "@scope/pkg/a/b" is package
// "@scope/pkg" and subpath "a/b".
func splitSpecifier(spec string) (name, sub string) {
	parts := strings.Split(spec, "/")
	if len(parts) == 0 {
		return "", ""
	}
	take := 1
	if strings.HasPrefix(parts[0], "@") {
		if len(parts) < 2 {
			// "@scope" alone is not a package.
			return "", ""
		}
		take = 2
	}
	return strings.Join(parts[:take], "/"), strings.Join(parts[take:], "/")
}

// manifest reads and caches a package.json.
func (n *node) manifest(file string) (packageJSON, bool) {
	data, err := n.fsys.ReadFile(file)
	if err != nil {
		return packageJSON{}, false
	}
	var m packageJSON
	if err := json.Unmarshal(data, &m); err != nil {
		return packageJSON{}, false
	}
	return m, true
}

// packageJSON is the part of a manifest the resolver needs. Every field is
// decoded loosely, because a field of the wrong type is common in the wild and
// must degrade to "this manifest does not say" rather than to a parse failure
// that loses the fields beside it.
type packageJSON struct {
	Name    string            `json:"name"`
	Main    string            `json:"main"`
	Bin     any               `json:"bin"`
	Exports any               `json:"exports"`
	Scripts map[string]string `json:"scripts"`

	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// depNames are every package this manifest declares it may load.
//
// devDependencies are deliberately excluded: they are absent from a production
// install by construction, so counting them would widen every dynamic-import
// scope by the whole test toolchain.
func (m packageJSON) depNames() []string {
	var out []string
	for _, set := range []map[string]string{m.Dependencies, m.OptionalDependencies, m.PeerDependencies} {
		for k := range set {
			out = append(out, k)
		}
	}
	return out
}

// binPaths lists the executables a manifest declares. "bin" is either a string
// or a name-to-path map.
func (m packageJSON) binPaths() []string {
	switch v := m.Bin.(type) {
	case string:
		return []string{v}
	case map[string]any:
		var out []string
		for _, p := range v {
			if s, ok := p.(string); ok {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// exportConditions are the "exports" keys this resolver honours, in the order
// it tries them. "require" comes first because the overwhelming majority of
// installed code in an image is CommonJS.
var exportConditions = []string{"require", "node", "default", "import"}

// fromExports resolves a subpath through a package's "exports" field, for the
// tractable subset of the specification: a plain string, a conditions map
// whose values are strings or nested conditions maps, a subpath map, and a
// lexically-expandable pattern.
//
// It returns nil -- not an empty slice -- when the map does not answer, which
// is how the caller tells "exports says nothing about this subpath" from
// "exports says this subpath is not exported". The distinction matters: the
// first falls back to probing, and the second would too, because a resolver
// that only partly understands the map has no business turning its silence
// into a conclusion.
func (n *node) fromExports(base string, m packageJSON, subpath string) []string {
	if m.Exports == nil {
		return nil
	}
	rel := resolveExports(m.Exports, subpath)
	if rel == "" {
		return nil
	}
	target := path.Join(base, rel)
	if f := n.probeFile(target); len(f) > 0 {
		return f
	}
	return nil
}

// resolveExports walks an "exports" value and returns the relative path it
// maps subpath to, or "" when it does not map it in a way this resolver can
// read.
func resolveExports(exports any, subpath string) string {
	switch v := exports.(type) {
	case string:
		// A bare string exports only the package root.
		if subpath == "." {
			return v
		}
		return ""

	case map[string]any:
		if isConditionsMap(v) {
			if subpath != "." {
				return ""
			}
			return pickCondition(v, ".")
		}
		if entry, ok := v[subpath]; ok {
			return exportTarget(entry, subpath)
		}
		// Patterns: "./*": "./src/*.js". Longest prefix wins, as the
		// specification says.
		bestKey, bestVal := "", ""
		for key, entry := range v {
			star := strings.IndexByte(key, '*')
			if star < 0 {
				continue
			}
			prefix, suffix := key[:star], key[star+1:]
			if !strings.HasPrefix(subpath, prefix) || !strings.HasSuffix(subpath, suffix) {
				continue
			}
			if len(prefix) < len(bestKey) {
				continue
			}
			tmpl := exportTarget(entry, subpath)
			if tmpl == "" || !strings.Contains(tmpl, "*") {
				continue
			}
			mid := subpath[len(prefix) : len(subpath)-len(suffix)]
			bestKey, bestVal = prefix, strings.ReplaceAll(tmpl, "*", mid)
		}
		return bestVal
	}
	return ""
}

// exportTarget reduces one "exports" entry to a relative path.
func exportTarget(entry any, subpath string) string {
	switch v := entry.(type) {
	case string:
		return v
	case map[string]any:
		return pickCondition(v, subpath)
	}
	// An array of fallbacks, or null for a blocked subpath. Neither is read.
	return ""
}

// pickCondition takes the first condition this resolver honours, recursing
// through nested conditions maps.
func pickCondition(m map[string]any, subpath string) string {
	for _, cond := range exportConditions {
		entry, ok := m[cond]
		if !ok {
			continue
		}
		if s := exportTarget(entry, subpath); s != "" {
			return s
		}
	}
	return ""
}

// isConditionsMap distinguishes {"require": "./x.js"} from {"./sub": "./x.js"}.
// The specification says the two cannot be mixed, and that every subpath key
// starts with a dot.
func isConditionsMap(m map[string]any) bool {
	for k := range m {
		return !strings.HasPrefix(k, ".")
	}
	return false
}

// builtins are Node's own modules, which ship no file. Without this list every
// `require("fs")` would report a module that is not in the image.
//
// The list does not need to be exhaustive across versions: a name missing from
// it produces a scoped unresolved-import taint on a name no package owns,
// which is noise rather than a wrong conclusion. A "node:" prefix is handled
// separately, since that spelling can only ever be a builtin.
var builtins = map[string]bool{
	"assert": true, "async_hooks": true, "buffer": true, "child_process": true,
	"cluster": true, "console": true, "constants": true, "crypto": true,
	"dgram": true, "diagnostics_channel": true, "dns": true, "domain": true,
	"events": true, "fs": true, "http": true, "http2": true, "https": true,
	"inspector": true, "module": true, "net": true, "os": true, "path": true,
	"perf_hooks": true, "process": true, "punycode": true, "querystring": true,
	"readline": true, "repl": true, "stream": true, "string_decoder": true,
	"sys": true, "timers": true, "tls": true, "trace_events": true, "tty": true,
	"url": true, "util": true, "v8": true, "vm": true, "wasi": true,
	"worker_threads": true, "zlib": true,
}

// isBuiltin reports whether a specifier names one of Node's own modules.
func isBuiltin(spec string) bool {
	if strings.HasPrefix(spec, "node:") {
		return true
	}
	top, _ := splitSpecifier(spec)
	return builtins[top]
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
