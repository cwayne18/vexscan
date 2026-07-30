package pypi

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/target"
)

// python is modgraph.Language for CPython: it turns an image config into entry
// modules and resolves import specifiers against a modelled sys.path.
//
// It lives next to the inventory rather than in modgraph because the resolver
// and the inventory need the same fact -- where site-packages is -- and two
// packages discovering that separately is how they come to disagree.
type python struct {
	fsys target.RootFS
	cfg  target.ImageConfig
	res  langdb.Result

	// search is the modelled sys.path, in order. Recorded so evidence can say
	// what was searched when an import did not resolve.
	search []string

	// pthTaints and pthRoots are what the .pth files in site-packages added.
	// They are computed at construction because a .pth line can extend
	// sys.path, and sys.path has to be settled before anything resolves.
	pthTaints []modgraph.Taint
	pthRoots  []modgraph.Root

	// entryPoints are the modules declared in entry_points.txt across every
	// installed distribution: what plugin discovery could return. Computed on
	// first use, since most images never ask.
	entryPoints []string
	epDone      bool

	// resolved memoizes resolution, which is by far the hot path: a large
	// image resolves the same "os" or "typing" import thousands of times.
	resolved map[string][]string

	// byImport and byName index the installed distributions, and scopes
	// memoizes the dependency closures computed from them. All three are built
	// on first use: a computed import is common, but an image with none of
	// them should not pay for the index.
	byImport map[string]langdb.Package
	byName   map[string]langdb.Package
	scopes   map[string]scopeResult

	logf func(format string, args ...any)
}

// scopeResult is one memoized dependency closure.
type scopeResult struct {
	names    []string
	complete bool
}

// maxSource caps how much of one file is scanned. A .py larger than this is
// generated data (a parser table, an embedded blob); reading it whole would
// cost more than the imports it could possibly declare are worth.
const maxSource = 4 << 20

func newPython(img *target.Image, res langdb.Result, logf func(string, ...any)) *python {
	p := &python{
		fsys:     img.FS,
		cfg:      img.Config,
		res:      res,
		resolved: map[string][]string{},
		logf:     logf,
	}
	p.buildSearchPath()
	return p
}

func (p *python) ID() string { return "python" }

// SearchPath is the modelled sys.path, for evidence.
func (p *python) SearchPath() []string { return append([]string{}, p.search...) }

// buildSearchPath models sys.path in the order the interpreter would build it,
// minus the script directory, which Roots prepends once it knows the script.
func (p *python) buildSearchPath() {
	var dirs []string
	if v, ok := p.cfg.LookupEnv("PYTHONPATH"); ok {
		for _, d := range strings.Split(v, ":") {
			if d = strings.TrimSpace(d); d != "" {
				dirs = append(dirs, path.Clean("/"+d))
			}
		}
	}

	// The stdlib comes before site-packages, as it does at runtime, so that a
	// distribution shadowing a stdlib name does not silently take its place in
	// the graph.
	stdlib := p.findStdlib()
	dirs = append(dirs, stdlib...)

	roots := append([]string{}, p.res.Roots...)
	sort.Strings(roots)
	dirs = append(dirs, roots...)

	p.search = dedupe(dirs)
	p.readPthFiles()
}

// findStdlib locates the interpreter's own library directory: the one holding
// os.py. It is found by looking rather than by assuming a version, because
// /usr/lib/python3.12 and /usr/local/lib/python3.13 are both normal and an
// image can hold two interpreters.
func (p *python) findStdlib() []string {
	var out []string
	for _, base := range []string{"/usr/lib", "/usr/local/lib", "/usr/lib64", "/opt/python/lib"} {
		entries, err := p.fsys.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "python") {
				continue
			}
			dir := path.Join(base, e.Name())
			if _, err := p.fsys.Stat(path.Join(dir, "os.py")); err != nil {
				continue
			}
			out = append(out, dir)
			// lib-dynload holds the stdlib's own extension modules, which are
			// where several CVE-bearing bindings live.
			if _, err := p.fsys.Stat(path.Join(dir, "lib-dynload")); err == nil {
				out = append(out, path.Join(dir, "lib-dynload"))
			}
		}
	}
	sort.Strings(out)
	return out
}

// readPthFiles applies the .pth files in every site-packages directory.
//
// A .pth line is either a path to add to sys.path or, if it starts with
// "import", a line of code the interpreter executes at startup. The first is
// modelled exactly; the second is modelled when it is a plain import and
// tainted when it is anything else, because arbitrary startup code can import
// anything.
func (p *python) readPthFiles() {
	for _, root := range p.res.Roots {
		entries, err := p.fsys.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pth") {
				continue
			}
			file := path.Join(root, e.Name())
			data, err := p.fsys.ReadFile(file)
			if err != nil {
				p.pthTaints = append(p.pthTaints, modgraph.Taint{
					Kind:     modgraph.TaintUnreadable,
					Detail:   "a .pth file could not be read, so what it adds to sys.path is unknown",
					Path:     file,
					Blocking: true,
					Global:   true,
				})
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !strings.HasPrefix(line, "import ") && !strings.HasPrefix(line, "import\t") {
					// A path, relative to the site-packages directory.
					dir := line
					if !strings.HasPrefix(dir, "/") {
						dir = path.Join(root, dir)
					}
					p.search = append(p.search, path.Clean(dir))
					continue
				}
				code := strings.TrimSpace(strings.TrimPrefix(line, "import"))
				if sr := scanPython([]byte("import " + code)); len(sr.specs) > 0 && !strings.ContainsAny(code, "();=") {
					for _, s := range sr.specs {
						for _, f := range p.resolveAbsolute(s.Name) {
							p.pthRoots = append(p.pthRoots, modgraph.Root{
								Path: f,
								Why:  "imported at interpreter startup by " + file,
								Kind: modgraph.RootPlugin,
							})
						}
					}
					continue
				}
				p.pthTaints = append(p.pthTaints, modgraph.Taint{
					Kind:     modgraph.TaintDynamicImport,
					Detail:   "a .pth file runs code at startup that is not a plain import: " + line,
					Path:     file,
					Blocking: true,
					Global:   true,
				})
			}
		}
	}
	p.search = dedupe(p.search)
}

// Roots turns argv into entry modules.
func (p *python) Roots(extra []string) ([]modgraph.Root, []modgraph.Taint, error) {
	var roots []modgraph.Root
	var taints []modgraph.Taint

	entry, entryTaints := p.entryRoots()
	roots = append(roots, entry...)
	taints = append(taints, entryTaints...)

	// Rooted whatever the entrypoint is: Python's analog of the plugin
	// directories elfgraph always roots. The interpreter imports these by
	// name at startup, so nothing in the image ever refers to them.
	for _, dir := range p.search {
		for _, name := range []string{"sitecustomize.py", "usercustomize.py"} {
			f := path.Join(dir, name)
			if _, err := p.fsys.Stat(f); err == nil {
				roots = append(roots, modgraph.Root{Path: f, Why: "imported by the interpreter at startup", Kind: modgraph.RootPlugin})
			}
		}
	}
	roots = append(roots, p.pthRoots...)
	taints = append(taints, p.pthTaints...)

	var explicit bool
	for _, e := range extra {
		for _, f := range p.explicitRoot(e) {
			roots = append(roots, modgraph.Root{Path: f, Why: "named by --roots", Kind: modgraph.RootExplicit})
			explicit = true
		}
	}

	// --roots exists for exactly the image the entrypoint taints describe: the
	// real command comes from outside the config. Having asked the user what
	// runs, answering "what runs is unknown" anyway would make the flag
	// unable to change any conclusion, which is the same as not having it. The
	// assertion is recorded rather than dropped, so a reader can see that the
	// closure rests on it -- and it demotes only the two taints about the
	// entrypoint. Nothing the code itself does is affected.
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

	// An empty root set would report an image in which no Python code runs,
	// which is never the honest answer -- it is the answer of a scanner that
	// gave up. Escalate instead, and say so.
	if !hasRunnable(roots) {
		roots = append(roots, p.escalate()...)
	}
	return roots, taints, nil
}

// hasRunnable reports whether anything other than a startup hook was rooted.
// sitecustomize alone is not an entrypoint.
func hasRunnable(roots []modgraph.Root) bool {
	for _, r := range roots {
		if r.Kind != modgraph.RootPlugin {
			return true
		}
	}
	return false
}

// entryRoots reads argv the way the kernel and the shell would.
func (p *python) entryRoots() ([]modgraph.Root, []modgraph.Taint) {
	argv := p.cfg.Argv()
	if len(argv) == 0 {
		return nil, []modgraph.Taint{{
			Kind:     modgraph.TaintNoEntrypoint,
			Detail:   "the image config has neither Entrypoint nor Cmd, so what it runs is unknown",
			Blocking: true,
			Global:   true,
		}}
	}

	argv0 := p.lookupCommand(argv[0])
	if isInterpreter(path.Base(argv[0])) {
		return p.interpreterRoots(argv)
	}

	// A console script -- pip, gunicorn, airflow -- is a generated Python file
	// with a #! line. Rooting it is the difference between analysing the
	// application and giving up on every image that does not exec python
	// directly.
	if argv0 != "" && p.isPythonScript(argv0) {
		p.prependSearch(path.Dir(argv0))
		return []modgraph.Root{{
			Path: argv0,
			Why:  "the entrypoint is a Python script: " + strings.Join(argv, " "),
			Kind: modgraph.RootEntry,
		}}, nil
	}

	return nil, []modgraph.Taint{{
		Kind:     modgraph.TaintForeignEntrypoint,
		Detail:   fmt.Sprintf("the entrypoint %q is not a Python interpreter or script, so what it imports is unknown", strings.Join(argv, " ")),
		Blocking: true,
		Global:   true,
	}}
}

// interpreterRoots reads a python command line: flags, then -m, -c, or a
// script.
func (p *python) interpreterRoots(argv []string) ([]modgraph.Root, []modgraph.Taint) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-m":
			if i+1 >= len(argv) {
				break
			}
			name := argv[i+1]
			files := p.resolveAbsolute(name)
			if len(files) == 0 {
				// The named module is what runs; not finding it means the
				// graph has no honest starting point at all.
				return nil, []modgraph.Taint{{
					Kind:     modgraph.TaintUnresolvedImport,
					Detail:   "the entrypoint runs -m " + name + ", which resolved to no file",
					Spec:     name,
					Blocking: true,
					Global:   true,
				}}
			}
			var roots []modgraph.Root
			for _, f := range files {
				roots = append(roots, modgraph.Root{Path: f, Why: "the entrypoint runs -m " + name, Kind: modgraph.RootEntry})
			}
			// python -m NAME runs NAME/__main__.py for a package.
			for _, f := range p.resolveAbsolute(name + ".__main__") {
				roots = append(roots, modgraph.Root{Path: f, Why: "the entrypoint runs -m " + name, Kind: modgraph.RootEntry})
			}
			return roots, nil

		case a == "-c":
			return nil, []modgraph.Taint{{
				Kind:     modgraph.TaintDynamicImport,
				Detail:   "the entrypoint is python -c, whose code is in the config rather than on disk",
				Blocking: true,
				Global:   true,
			}}

		case a == "-":
			// Reading the program from stdin: there is nothing on disk.
			return nil, []modgraph.Taint{{
				Kind:     modgraph.TaintDynamicImport,
				Detail:   "the entrypoint reads its program from stdin",
				Blocking: true,
				Global:   true,
			}}

		case strings.HasPrefix(a, "-"):
			if takesValue(a) && i+1 < len(argv) {
				i++
			}

		default:
			f := p.resolveScript(a)
			if f != "" {
				// sys.path[0] is the script's own directory, which is how an
				// application imports its sibling modules. Without it every
				// "from app import x" in every application image would be an
				// unresolved import.
				p.prependSearch(path.Dir(f))
			}
			if f == "" {
				return nil, []modgraph.Taint{{
					Kind:     modgraph.TaintUnresolvedImport,
					Detail:   "the entrypoint script " + a + " is not in the image",
					Spec:     a,
					Blocking: true,
					Global:   true,
				}}
			}
			return []modgraph.Root{{Path: f, Why: "the entrypoint script", Kind: modgraph.RootEntry}}, nil
		}
	}

	// Bare "python" with no script: an interactive interpreter. Nothing runs
	// until someone types something, and what they type can import anything.
	return nil, []modgraph.Taint{{
		Kind:     modgraph.TaintNoEntrypoint,
		Detail:   "the entrypoint is an interactive interpreter, which can import anything installed",
		Blocking: true,
		Global:   true,
	}}
}

// prependSearch puts a directory at the head of the modelled sys.path, where
// the interpreter puts the script's own directory. Anything already resolved
// against the shorter path is forgotten, since the answer may now differ.
func (p *python) prependSearch(dir string) {
	if dir == "" || dir == "." {
		return
	}
	p.search = dedupe(append([]string{path.Clean(dir)}, p.search...))
	p.resolved = map[string][]string{}
}

// escalate roots every installed module. It is what the graph does when it
// cannot tell what runs: the answer becomes "everything is reachable", which
// is useless for narrowing and correct for safety.
func (p *python) escalate() []modgraph.Root {
	var roots []modgraph.Root
	for _, pkg := range p.res.Packages {
		for _, f := range pkg.Files {
			if p.IsModule(f) {
				roots = append(roots, modgraph.Root{
					Path: f,
					// Phrased as a noun: the evidence renders this as
					// "<file> is <why>".
					Why:  "an installed module, rooted because this image's own entrypoint could not be resolved",
					Kind: modgraph.RootEscalated,
				})
			}
		}
	}
	return roots
}

// explicitRoot accepts either a path or a module name from --roots.
func (p *python) explicitRoot(v string) []string {
	if strings.Contains(v, "/") {
		if _, err := p.fsys.Stat(v); err == nil {
			return []string{path.Clean("/" + v)}
		}
		return nil
	}
	return p.resolveAbsolute(v)
}

// lookupCommand resolves argv[0] through PATH.
func (p *python) lookupCommand(cmd string) string {
	if strings.Contains(cmd, "/") {
		c := path.Clean("/" + cmd)
		if _, err := p.fsys.Stat(c); err == nil {
			return c
		}
		return ""
	}
	for _, dir := range p.cfg.PathDirs() {
		c := path.Join(dir, cmd)
		if _, err := p.fsys.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// resolveScript turns a script argument into a path, honouring WorkingDir.
func (p *python) resolveScript(arg string) string {
	cands := []string{arg}
	if !strings.HasPrefix(arg, "/") {
		wd := p.cfg.WorkingDir
		if wd == "" {
			wd = "/"
		}
		cands = []string{path.Join(wd, arg), path.Clean("/" + arg)}
	}
	for _, c := range cands {
		if _, err := p.fsys.Stat(c); err == nil {
			return path.Clean(c)
		}
	}
	return ""
}

// isPythonScript reports whether a file's #! line names a Python interpreter.
func (p *python) isPythonScript(file string) bool {
	data, err := p.fsys.ReadFile(file)
	if err != nil || !strings.HasPrefix(string(data), "#!") {
		return false
	}
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	for _, f := range strings.Fields(line) {
		if isInterpreter(path.Base(f)) {
			return true
		}
	}
	return false
}

// isInterpreter matches python, python3, python3.12, pypy3 and friends.
func isInterpreter(base string) bool {
	switch {
	case base == "python" || base == "pypy":
		return true
	case strings.HasPrefix(base, "python") || strings.HasPrefix(base, "pypy"):
		rest := strings.TrimPrefix(strings.TrimPrefix(base, "python"), "pypy")
		return strings.Trim(rest, "0123456789.") == ""
	}
	return false
}

// takesValue reports whether a python flag consumes the next argument.
func takesValue(flag string) bool {
	switch flag {
	case "-W", "-X", "-Q", "--check-hash-based-pycs":
		return true
	}
	return false
}

// Imports scans one file for what it loads.
func (p *python) Imports(file string) ([]modgraph.Spec, []modgraph.Taint, error) {
	switch path.Ext(file) {
	case ".py":
	case ".so", ".pyd", ".dylib":
		// An extension module's imports are in compiled code. What it links
		// against is elfgraph's question, and it is asked there.
		return nil, nil, nil
	case ".pyc":
		// Bytecode reached because no source sits beside it: the image was
		// stripped. Its imports are unreadable here, and everything they would
		// have pulled in is missing from the closure.
		return nil, []modgraph.Taint{{
			Kind:     modgraph.TaintUnreadable,
			Detail:   "reachable module ships as bytecode with no source, so its imports are unknown",
			Path:     file,
			Blocking: true,
			Global:   true,
		}}, nil
	default:
		// A console script has no extension at all. It is Python source when
		// its #! says so, and skipping it would break every image whose
		// entrypoint is an installed command.
		if !p.isPythonScript(file) {
			return nil, nil, nil
		}
	}
	info, err := p.fsys.Stat(file)
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > maxSource {
		return nil, nil, nil
	}
	data, err := p.fsys.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}

	sr := scanPython(data)
	specs := sr.specs
	var taints []modgraph.Taint

	if len(sr.computed) > 0 {
		detail := fmt.Sprintf("imports a module named at runtime (line %d)", sr.computed[0])
		scope, complete := p.dynamicScope(file)
		if complete && len(scope) > 0 {
			detail += ", which could be this distribution or anything it requires"
		}
		taints = append(taints, modgraph.Taint{
			Kind:     modgraph.TaintDynamicImport,
			Detail:   detail,
			Path:     file,
			Scope:    scope,
			Blocking: true,
			// Code no installed distribution owns -- the application's own, or
			// the stdlib's -- is bounded by nothing and could import anything
			// installed. So is a distribution whose own requirements could not
			// be walked.
			Global: !complete,
		})
	}

	if sr.discovery {
		eps := p.entryPointModules()
		for _, m := range eps {
			specs = append(specs, modgraph.Spec{Name: m, Dynamic: true, Optional: true})
		}
		// Resolving beats surrendering: entry_points.txt is on disk, so the
		// set of plugins discovery could return is knowable, and rooting them
		// is a real answer where a global taint is a shrug. The taint is still
		// recorded -- discovery can reach plugins registered other ways -- and
		// only blocks when there was nothing to enumerate.
		taints = append(taints, modgraph.Taint{
			Kind:     modgraph.TaintPluginDiscovery,
			Detail:   fmt.Sprintf("enumerates installed distributions; %d declared entry-point modules were followed", len(eps)),
			Path:     file,
			Scope:    p.owners(file),
			Blocking: len(eps) == 0,
			Global:   len(eps) == 0,
		})
	}
	return specs, taints, nil
}

// owners names the import roots a file belongs to, so a taint can be scoped to
// the distribution that raised it.
//
// A file under no site-packages directory belongs to no distribution -- it is
// application code, or the stdlib -- and a taint it raises is global, because
// code no distribution owns can import anything installed.
func (p *python) owners(file string) []string {
	// Longest match wins: /usr/lib/python3.12 and its site-packages child are
	// both search roots, and the shorter one would name the importing module
	// "site-packages".
	best := ""
	for _, root := range p.res.Roots {
		if strings.HasPrefix(file, root+"/") && len(root) > len(best) {
			best = root
		}
	}
	if best == "" {
		return nil
	}
	top := strings.TrimPrefix(file, best+"/")
	if i := strings.IndexByte(top, '/'); i >= 0 {
		top = top[:i]
	}
	return []string{strings.TrimSuffix(top, ".py")}
}

// dynamicScope is the set of import names a computed import inside file could
// name, and whether that set is known to be complete.
//
// Scoping a dynamic import to the distribution that contains it -- which is
// what owners alone gives, and what this shipped as -- is inert. A taint only
// blocks a conclusion about a distribution in its scope, and the distribution
// running the computed import is reached by definition, since its file had to
// be read for the taint to be found at all. It could never withhold a
// conclusion from anything. The npm plugin had the identical defect and
// node:22-slim demonstrated the cost: tar reported not_in_execute_path behind
// the very require that loads it.
//
// What a computed import can reach is bounded by what the distribution says it
// requires, so the scope is the transitive closure over Requires-Dist. That
// stays narrow for a leaf library and correctly widens to nearly everything for
// an application distribution at the top of the tree.
//
// Completeness is where Python differs from npm. A declared requirement that is
// not installed is not automatically a broken environment: an unselected extra
// and a marker-gated dependency are *supposed* to be absent, which is why
// langdb.Requirement records whether a marker was present. An unconditional
// requirement that is missing, or metadata that would not parse, means the
// closure is not knowable and the caller must taint globally.
func (p *python) dynamicScope(file string) (names []string, complete bool) {
	own := p.owners(file)
	if len(own) == 0 {
		return nil, false
	}
	p.indexDists()
	dist, ok := p.byImport[own[0]]
	if !ok {
		// Under a site-packages directory but owned by no distribution the
		// inventory found: a stray module, or one whose metadata was
		// unreadable. Either way there is no requirement list to bound it.
		return own, false
	}
	return p.requireClosure(dist)
}

// requireClosure walks Requires-Dist transitively from one distribution.
func (p *python) requireClosure(dist langdb.Package) (names []string, complete bool) {
	if hit, ok := p.scopes[dist.Name]; ok {
		return hit.names, hit.complete
	}
	// Memoized before the walk as well as after. Circular requirements are
	// legal and do occur, and this is what stops one from recursing forever.
	p.scopes[dist.Name] = scopeResult{complete: true}

	seen := map[string]bool{}
	complete = true

	queue := []langdb.Package{dist}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		names = append(names, d.ImportNames...)

		if !d.RequiresKnown {
			complete = false
			continue
		}
		for _, req := range d.Requires {
			next, ok := p.byName[req.Name]
			if ok {
				queue = append(queue, next)
				continue
			}
			if !req.Conditional {
				complete = false
			}
		}
	}

	names = dedupe(names)
	sort.Strings(names)
	p.scopes[dist.Name] = scopeResult{names: names, complete: complete}
	return names, complete
}

// indexDists builds the name lookups the closure walks.
func (p *python) indexDists() {
	if p.byName != nil {
		return
	}
	p.byName = make(map[string]langdb.Package, len(p.res.Packages))
	p.byImport = make(map[string]langdb.Package, len(p.res.Packages))
	p.scopes = map[string]scopeResult{}
	for _, pkg := range p.res.Packages {
		if _, ok := p.byName[pkg.Name]; !ok {
			p.byName[pkg.Name] = pkg
		}
		for _, n := range pkg.ImportNames {
			// First writer wins, matching sys.path order after the inventory's
			// sort: two distributions claiming one import name means only the
			// first is importable under it.
			if _, ok := p.byImport[n]; !ok {
				p.byImport[n] = pkg
			}
		}
	}
}

// entryPointModules lists every module named on the left of a colon in an
// installed distribution's entry_points.txt: what plugin discovery can load.
func (p *python) entryPointModules() []string {
	if p.epDone {
		return p.entryPoints
	}
	p.epDone = true

	seen := map[string]bool{}
	for _, pkg := range p.res.Packages {
		if pkg.Dir == "" {
			continue
		}
		data, err := p.fsys.ReadFile(path.Join(pkg.Dir, "entry_points.txt"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
				continue
			}
			_, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			mod := strings.TrimSpace(value)
			if i := strings.IndexByte(mod, ':'); i >= 0 {
				mod = mod[:i]
			}
			if mod = strings.TrimSpace(mod); mod != "" && !seen[mod] {
				seen[mod] = true
				p.entryPoints = append(p.entryPoints, mod)
			}
		}
	}
	sort.Strings(p.entryPoints)
	return p.entryPoints
}

// IsModule reports whether a path is code the interpreter would load.
//
// A .pyc under __pycache__ is deliberately excluded: it is the compiled twin
// of a .py already counted, and counting both would double every module in
// the image. A .pyc *outside* __pycache__ is counted, because a stripped image
// that ships only bytecode still ships the code.
func (p *python) IsModule(f string) bool {
	switch path.Ext(f) {
	case ".py", ".so", ".pyd":
		return true
	case ".pyc":
		return path.Base(path.Dir(f)) != "__pycache__"
	}
	return false
}

// Resolve maps a specifier onto files, following the interpreter's rules.
func (p *python) Resolve(from string, spec modgraph.Spec) ([]string, bool) {
	name := spec.Name
	if strings.HasPrefix(name, ".") {
		return p.resolveRelative(from, name)
	}
	if isBuiltinModule(topName(name)) {
		// Compiled into the interpreter binary: there is no file to find, and
		// reporting one missing would be a taint on correct code.
		return nil, true
	}
	files := p.resolveAbsolute(name)
	return files, len(files) > 0 || p.isNamespace(name)
}

// resolveRelative counts leading dots as package levels up from the importer.
func (p *python) resolveRelative(from, name string) ([]string, bool) {
	level := 0
	for level < len(name) && name[level] == '.' {
		level++
	}
	dir := path.Dir(from)
	// One dot is the importing module's own package; each further dot is one
	// package above it.
	for i := 1; i < level; i++ {
		dir = path.Dir(dir)
	}
	rest := name[level:]
	if rest == "" {
		f := path.Join(dir, "__init__.py")
		if _, err := p.fsys.Stat(f); err == nil {
			return []string{f}, true
		}
		return nil, true
	}
	files := p.probe(dir, strings.Split(rest, "."))
	return files, len(files) > 0
}

// resolveAbsolute searches sys.path in order.
func (p *python) resolveAbsolute(name string) []string {
	if cached, ok := p.resolved[name]; ok {
		return cached
	}
	parts := strings.Split(name, ".")
	var out []string
	for _, dir := range p.search {
		out = append(out, p.probe(dir, parts)...)
	}
	// A namespace package merges across every sys.path entry, so the search
	// does not stop at the first hit. For an ordinary module the extra probes
	// find nothing, and the memo makes the cost one-time.
	out = dedupe(out)
	p.resolved[name] = out
	return out
}

// isNamespace reports whether a specifier names a PEP 420 namespace package: a
// directory with no __init__.py, which imports cleanly and executes no code.
// Resolving to no file is the correct answer for one, and it must not taint.
func (p *python) isNamespace(name string) bool {
	rel := strings.ReplaceAll(name, ".", "/")
	for _, dir := range p.search {
		if info, err := p.fsys.Stat(path.Join(dir, rel)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// probe applies the interpreter's file-name rules under one directory.
func (p *python) probe(base string, parts []string) []string {
	joined := path.Join(append([]string{base}, parts...)...)
	if f := joined + "/__init__.py"; p.isFile(f) {
		return []string{f}
	}
	for _, ext := range []string{".py", ".pyc"} {
		if f := joined + ext; p.isFile(f) {
			return []string{f}
		}
	}
	// Extension modules carry an ABI tag: _yaml.cpython-312-x86_64-linux-gnu.so.
	// The tag varies with interpreter, platform and build, so the directory is
	// listed rather than the name guessed.
	dir, want := path.Dir(joined), path.Base(joined)
	entries, err := p.fsys.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, want+".") {
			continue
		}
		if strings.HasSuffix(n, ".so") || strings.HasSuffix(n, ".pyd") || strings.HasSuffix(n, ".dylib") {
			return []string{path.Join(dir, n)}
		}
	}
	return nil
}

func (p *python) isFile(f string) bool {
	info, err := p.fsys.Stat(f)
	return err == nil && !info.IsDir()
}

// topName is the first dotted component.
func topName(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
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

// builtinModules are compiled into the interpreter binary and ship no file, so
// an import of one resolves to nothing and that is the right answer. Without
// this list every "import sys" would report a module that is not in the image.
//
// The list is CPython's sys.builtin_module_names on a stock build. It does not
// need to be exhaustive across versions: a name missing from it produces a
// scoped unresolved-import taint on a name no distribution owns, which is
// noise rather than a wrong conclusion.
var builtinModules = map[string]bool{
	"_abc": true, "_ast": true, "_codecs": true, "_collections": true,
	"_functools": true, "_imp": true, "_io": true, "_locale": true,
	"_operator": true, "_signal": true, "_sre": true, "_stat": true,
	"_string": true, "_symtable": true, "_thread": true, "_tokenize": true,
	"_tracemalloc": true, "_warnings": true, "_weakref": true,
	"atexit": true, "builtins": true, "errno": true, "faulthandler": true,
	"gc": true, "itertools": true, "marshal": true, "posix": true,
	"pwd": true, "sys": true, "time": true, "xxsubtype": true,
	"nt": true, "winreg": true, "msvcrt": true, "__main__": true,
}

func isBuiltinModule(name string) bool { return builtinModules[name] }
