// Package analyze orchestrates the vexscan pipeline: prepare a target (extract
// an image, open a rootfs, or check out a source tree), ask each ecosystem
// plugin what it finds, resolve advisories for what the plugins inventory, and
// optionally overlay an LLM assessment on the genuinely-affected results.
//
// The division of labour is deliberate. Plugins own the *deterministic*
// question — is this vulnerable code present, and can it run — and nothing
// else. This package owns advisory resolution and the LLM overlay, so no
// plugin can make the model's opinion load-bearing.
package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/ecosystem/golang"
	"github.com/cwayne18/vexscan/internal/ecosystem/maven"
	"github.com/cwayne18/vexscan/internal/ecosystem/npm"
	"github.com/cwayne18/vexscan/internal/ecosystem/ospkg"
	"github.com/cwayne18/vexscan/internal/ecosystem/pypi"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/image"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/rpmsrc"
	"github.com/cwayne18/vexscan/internal/source"
	"github.com/cwayne18/vexscan/internal/target"
	"github.com/cwayne18/vexscan/internal/triage"
)

// The finding vocabulary lives in internal/ecosystem, which is what the plugins
// produce. These aliases keep the existing analyze.Finding / analyze.Status
// spelling working for callers and keep the JSON output byte-identical.
type (
	Finding = ecosystem.Finding
	Status  = ecosystem.Status
)

const (
	StatusNotPresent   = ecosystem.StatusNotPresent
	StatusNotInPath    = ecosystem.StatusNotInPath
	StatusLinked       = ecosystem.StatusLinked
	StatusReachable    = ecosystem.StatusReachable
	StatusUndetermined = ecosystem.StatusUndetermined
)

// Options configure a run. Set exactly one of Image, RootFS or Repo.
type Options struct {
	Image string
	// RootFS is a filesystem tree already on disk -- an unpacked image, a
	// mounted volume, a machine's own /. It runs the image analyzers against a
	// tree nobody extracted, so it skips the pull but also arrives without an
	// image config: see runTree.
	RootFS string
	Repo   string // git repo (source mode); mutually exclusive with Image
	Ref    string // branch/tag/commit for Repo
	Path   string // module subdirectory within Repo (default ".")

	// RPM are package files to scan without installing them (--rpm): a file, a
	// directory of them, or a URL. Mutually exclusive with the other three.
	//
	// This is the one target with no filesystem behind it, and every
	// difference in the report follows from that: no reachability closure can
	// run, so nothing can be linked and nothing can be ruled out as
	// unreachable. What a header can still answer -- would this package
	// install any code at all -- it does.
	RPM []string

	// rpmPackages is what RPM resolved to. It is unexported and filled in by
	// runTree rather than by the caller, because reading it is I/O and Validate
	// promises to do none: a scan must be able to fail on a bad flag before it
	// fetches anything.
	rpmPackages []ospkg.Supplied

	// Packages are the raw --package selectors: purls, ecosystem:name
	// shorthand, or bare names resolved against whatever inventory contains
	// them. See ecosystem.ParseSubject.
	Packages []string
	// Module is the deprecated --module flag, equivalent to one
	// --package golang:MODULE.
	Module string
	// All requests everything each plugin can inventory, rather than a named
	// list of packages.
	All bool
	// Ecosystems restricts which plugins run (--ecosystem). Empty runs them
	// all. Naming one nothing handles is an error, not an empty result.
	Ecosystems []string
	// Severities restricts the result to findings carrying these severity
	// labels (--severity), already canonicalized through cvss.Parse by the
	// caller. Empty keeps everything.
	//
	// Unlike Ecosystems this changes what is reported rather than what runs:
	// every plugin still inventories and every advisory is still resolved,
	// because a finding's severity is only knowable once its advisory is in
	// hand. What it does buy is that the LLM overlay is never asked about a row
	// nobody is going to read.
	Severities []string

	CVEs    []string // optional filter; empty means "every advisory that applies"
	Version string   // optional override of the detected module version (image mode)
	OS      string
	Arch    string

	// Roots are extra entrypoints for the reachability closures -- the OS
	// plugin's shared libraries and the language plugins' import graphs -- for
	// an image whose real command comes from outside its config.
	Roots []string
	// DlopenPolicy decides whether a reachable dlopen blocks conclusions.
	DlopenPolicy elfgraph.DlopenPolicy
	// DynamicPolicy decides whether a reachable import of a computed name
	// blocks conclusions. It is the import graph's DlopenPolicy.
	DynamicPolicy modgraph.DynamicPolicy
	// OSVEcosystem overrides the OSV ecosystem derived from the image's
	// os-release, for the distributions os-release does not determine. It is
	// not the same knob as Ecosystems, which chooses which plugins run.
	OSVEcosystem string

	// VEXHubs are VEX Hub repositories to check findings against (--vexhub),
	// in priority order: the first hub with a statement about a finding wins,
	// so an internal hub listed ahead of a vendor's overrides it.
	//
	// A statement never changes a finding's status. It records that someone has
	// already published an answer, which the report uses to decide what a
	// reader still has to look at.
	VEXHubs []string

	// Triage is the EPSS/KEV loader for --triage, or nil to skip it entirely.
	// It is the loader rather than a bool so a test can point it at its own
	// feeds, and so the caller owns the cache location.
	//
	// Like VEXHubs it never changes a finding's status. Whether a vulnerability
	// is being exploited elsewhere says nothing about whether the code is
	// present here, which is the only question this tool answers; what it
	// changes is which of the answers a reader looks at first.
	Triage *triage.Loader

	// GoVersion optionally pins the Go toolchain for repo-mode analysis
	// (e.g. "1.24.0"). Mainly useful with --module stdlib, whose findings depend
	// on the toolchain version.
	GoVersion string

	UseLLM bool
	// LLMEndpoint, LLMModel and LLMCommand say who to ask. Each falls back to
	// VEXSCAN_LLM_ENDPOINT / _MODEL / _COMMAND when empty, and exactly one of
	// endpoint and command must end up set: see llm.Config. The credential is
	// read from the environment only, never from here, so it cannot reach a
	// command line.
	LLMEndpoint string
	LLMModel    string
	LLMCommand  string

	// MineAdvisories lets the model read each advisory's prose for symbol,
	// soname and filename leads, which plugins then validate against the image.
	// Requires UseLLM.
	MineAdvisories bool
	// TrustImportAbsence lets the OS plugin conclude not_in_execute_path when
	// nothing the closure reaches imports the vulnerable symbol. Off by default:
	// the vulnerable function is usually called from inside the same library,
	// where no dynamic import records it.
	TrustImportAbsence bool

	// Logf receives progress messages (may be nil).
	Logf func(format string, args ...any)
}

// SchemaVersion is the version of the JSON Result shape.
//
// 1 was gomod-vex: Go only, one module per run. 2 adds the ecosystem-neutral
// finding identity, the per-ecosystem outcome list, and OS package findings.
// Every version-1 field is still present and still means what it meant.
const SchemaVersion = 2

// Result is the full analysis output.
type Result struct {
	SchemaVersion int       `json:"schema_version"`
	Target        string    `json:"target"` // image ref, rootfs directory, or repo
	Mode          string    `json:"mode"`   // "image" | "rootfs" | "repo"
	Module        string    `json:"module"`
	Findings      []Finding `json:"findings"`

	// Ecosystems records how each plugin fared. It exists so a failure is
	// never indistinguishable from a clean result: a plugin that found a
	// package database and could not read it reports the error here and
	// contributes no findings at all.
	Ecosystems []ecosystem.EcosystemResult `json:"ecosystems,omitempty"`

	// Unreadable is the part of the target tree the scan could not enter,
	// accumulated across every plugin that walked it. It is nil in repo mode,
	// which analyzes a checkout the current user just created.
	//
	// It is set for the same reason it is recorded at all: a directory nothing
	// looked inside contributes no findings, which is exactly what a directory
	// full of nothing wrong contributes. Only one of those is good news.
	Unreadable *target.Unreadable `json:"unreadable,omitempty"`

	// VEXHubs records what each --vexhub contributed, including one that could
	// not be read. It is not part of Failed(): see vexOverlay for why a hub
	// failure is not the same kind of incompleteness as an ecosystem failure.
	VEXHubs []ecosystem.VEXHubResult `json:"vex_hubs,omitempty"`

	// Withheld is what --severity removed from Findings, and is nil when the
	// flag was not used or hid nothing. See severityFilter: a filtered result
	// and a clean one are indistinguishable without it.
	Withheld *Withheld `json:"withheld,omitempty"`

	// Triage records what --triage contributed, and is nil when the flag was
	// not used. Like VEXHubs it is not part of Failed(): see triageOverlay.
	Triage *TriageResult `json:"triage,omitempty"`
}

// Failed reports whether the findings are an incomplete account of the target
// -- because an ecosystem could not complete, or because part of the tree could
// not be read.
func (r *Result) Failed() bool {
	for _, e := range r.Ecosystems {
		if e.Error != "" {
			return true
		}
	}
	return r.Unreadable != nil && r.Unreadable.Any()
}

// Validate reports whether the options describe a coherent scan, touching
// neither the network nor the disk. It lets the caller tell a bad command line
// from a failed scan, and report the former before the pull rather than after.
//
// It cannot catch everything: a bare --package name is resolved against the
// inventory, so whether it names anything is only knowable once the target has
// been read.
func Validate(opts Options) error {
	_, _, err := plan(opts)
	return err
}

// Run dispatches to filesystem analysis -- an image or a rootfs -- or to
// source-repo analysis.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	// The Go standard library is "stdlib" in OSV and govulncheck; accept "std"
	// as a convenience alias.
	opts.Module = golang.NormalizeModule(opts.Module)

	if err := opts.checkTarget(); err != nil {
		return nil, err
	}
	if opts.Repo != "" {
		return runRepo(ctx, opts)
	}
	return runTree(ctx, opts)
}

// checkTarget reports whether exactly one target was named.
func (o Options) checkTarget() error {
	var named []string
	for _, t := range []struct {
		flag string
		set  bool
	}{
		{"--image", o.Image != ""}, {"--rootfs", o.RootFS != ""},
		{"--repo", o.Repo != ""}, {"--rpm", len(o.RPM) > 0},
	} {
		if t.set {
			named = append(named, t.flag)
		}
	}
	switch len(named) {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("one of --image, --rootfs, --repo or --rpm is required")
	default:
		return fmt.Errorf("set only one of %s", strings.Join(named, ", "))
	}
}

// registryFor builds the plugin set for a run.
func registryFor(opts Options) *ecosystem.Registry {
	return ecosystem.NewRegistry(
		golang.New(golang.Options{
			VersionOverride: opts.Version,
			GoVersion:       opts.GoVersion,
			Image:           opts.Image,
			Logf:            opts.Logf,
		}),
		ospkg.New(ospkg.Options{
			Roots:              opts.Roots,
			DlopenPolicy:       opts.DlopenPolicy,
			Ecosystem:          opts.OSVEcosystem,
			Packages:           opts.rpmPackages,
			Mine:               opts.MineAdvisories && opts.UseLLM,
			TrustImportAbsence: opts.TrustImportAbsence,
			Logf:               opts.Logf,
		}),
		pypi.New(pypi.Options{
			Roots:              opts.Roots,
			DynamicPolicy:      opts.DynamicPolicy,
			Mine:               opts.MineAdvisories && opts.UseLLM,
			TrustImportAbsence: opts.TrustImportAbsence,
			Logf:               opts.Logf,
		}),
		npm.New(npm.Options{
			Roots:              opts.Roots,
			DynamicPolicy:      opts.DynamicPolicy,
			Mine:               opts.MineAdvisories && opts.UseLLM,
			TrustImportAbsence: opts.TrustImportAbsence,
			Logf:               opts.Logf,
		}),
		// No Roots and no DynamicPolicy: there is no Java reference graph here
		// to root or to taint, so the only question this plugin answers below
		// the artifact is whether the class is in the archive at all.
		maven.New(maven.Options{
			Mine: opts.MineAdvisories && opts.UseLLM,
			Logf: opts.Logf,
		}),
	)
}

// plan resolves the command line into the plugins that will run and the
// subjects they will be asked about.
//
// Both halves can fail, and both failures matter for the same reason: an
// ecosystem selector or a package selector that matches nothing produces an
// empty report, and an empty report is indistinguishable from a clean one.
func plan(opts Options) ([]ecosystem.Plugin, []ecosystem.Subject, error) {
	plugins, err := registryFor(opts).Select(opts.Ecosystems)
	if err != nil {
		return nil, nil, err
	}

	subjects, err := ecosystem.Subjects(plugins, opts.Packages)
	if err != nil {
		return nil, nil, err
	}
	if opts.Module != "" {
		// The deprecated --module is exactly --package golang:MODULE. Spelling
		// it out that way here is what keeps it working forever without a
		// second code path to keep in step.
		subjects = append(subjects, ecosystem.Subject{
			Ecosystem: "golang",
			Name:      golang.NormalizeModule(opts.Module),
			Raw:       "--module " + opts.Module,
		})
	}

	switch {
	case opts.All:
		// A bare subject matches everything in every selected plugin. It
		// replaces rather than joins the named ones, so --all always means the
		// same thing regardless of what else is on the command line.
		subjects = []ecosystem.Subject{{Raw: "--all"}}
	case len(subjects) > 0:
	case len(opts.CVEs) > 0:
		// Ids with nothing named to check them against: search the whole
		// target for where they land.
		subjects = []ecosystem.Subject{{Raw: "--cves"}}
	default:
		return nil, nil, fmt.Errorf("nothing to check: name a package with --package, give ids with --cves, or pass --all")
	}
	return plugins, subjects, nil
}

// targeted reports whether the user named what to look at, as opposed to
// asking for an enumeration. See ecosystem.WorkItem.Targeted.
func targeted(subjects []ecosystem.Subject) bool {
	for _, s := range subjects {
		if s.MatchesAll() {
			return false
		}
	}
	return true
}

// mode names which kind of filesystem target this run is scanning.
func (o Options) mode() string {
	switch {
	case len(o.RPM) > 0:
		return "rpm"
	case o.RootFS != "":
		return "rootfs"
	default:
		return "image"
	}
}

// openTree produces the tree the image analyzers run against, and a cleanup to
// call when the scan is done.
//
// The two branches differ in what that cleanup does, and getting it wrong is
// the one way this goes badly wrong: an extraction directory this created is
// this function's to delete, and a rootfs directory the user named is not.
//
// It takes *Options because image mode defaults the platform and reports what
// it chose.
func openTree(ctx context.Context, opts *Options) (*target.Image, func(), error) {
	if len(opts.RPM) > 0 {
		return openRPMTree(opts)
	}

	if opts.RootFS != "" {
		img, err := openRootFS(opts.RootFS)
		if err != nil {
			return nil, nil, err
		}
		opts.Logf("Scanning rootfs %s...", img.Ref)
		return img, func() {}, nil
	}

	if opts.OS == "" {
		opts.OS = "linux"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	dest, err := os.MkdirTemp("", "vexscan-fs-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(dest) }

	opts.Logf("Extracting %s (%s/%s)...", opts.Image, opts.OS, opts.Arch)
	ex := image.NewExtractor()
	ex.OS, ex.Arch = opts.OS, opts.Arch
	img, err := ex.Extract(ctx, opts.Image, dest)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("extract image: %w", err)
	}
	return img, cleanup, nil
}

// openRPMTree gives --rpm a tree to be scanned against: an empty one.
//
// A real empty directory rather than a nil filesystem, and the difference is
// not cosmetic. Every walk, every Unreadable check and every plugin's "does
// this apply" question runs over it unchanged, and each of them gets the
// truthful answer -- there is no filesystem here, because these packages were
// never installed. A nil RootFS would make the same statement by panicking.
func openRPMTree(opts *Options) (*target.Image, func(), error) {
	dest, err := os.MkdirTemp("", "vexscan-rpm-")
	if err != nil {
		return nil, nil, err
	}
	return &target.Image{
		Ref: strings.Join(opts.RPM, ", "),
		FS:  target.NewDirFS(dest),
	}, func() { os.RemoveAll(dest) }, nil
}

// openRootFS points a target at a directory the user already has.
//
// The result carries no ImageConfig, because a directory does not have one.
// That is a real loss rather than a detail: the entrypoint is what the
// reachability closures are rooted on, so without it the language plugins taint
// their conclusions and the ELF closure falls back to rooting every program it
// finds. Nothing here papers over that -- inventing a plausible entrypoint
// would turn "we could not tell" into a confident wrong answer.
//
// The directory is not required to look like a root filesystem. A tree with
// nothing but an application in it is a legitimate thing to scan, and the
// plugins already report finding no package database.
func openRootFS(dir string) (*target.Image, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("rootfs %s: %w", dir, err)
	}
	// Stat, not Lstat: a rootfs reached through a symlink is fine. What is not
	// fine is a path that is not there, or is a file -- both of which would
	// otherwise scan cleanly, since every walk of a non-directory finds nothing
	// and every plugin would report that it does not apply.
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("rootfs %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("rootfs %s is not a directory", abs)
	}
	return &target.Image{Ref: abs, FS: target.NewDirFS(abs)}, nil
}

// runTree hands a filesystem tree to every image analyzer. The tree is either a
// container image this pulls and extracts, or a rootfs the user already has.
//
// Both go through the same analyzers because none of them reads anything an
// image has and a directory does not: no plugin looks at Ref, OS or Arch, and
// the only real difference -- that a rootfs declares no entrypoint -- is a case
// the reachability closures already handle, by tainting what they cannot root.
// The taint is the honest answer, and --roots is how a user who knows what runs
// in the tree removes it.
func runTree(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf

	// Before plan(), because the plugin set is built holding the inventory:
	// registryFor hands these to the OS plugin at construction time. And in
	// here rather than in Validate, which promises to touch neither disk nor
	// network.
	rpms, err := readRPMs(ctx, &opts)
	if err != nil {
		return nil, err
	}

	// Plan the scan and build the LLM client before the extraction: a bad
	// selector or a rejected token should fail in the first second, not after a
	// multi-gigabyte pull.
	plugins, subjects, err := plan(opts)
	if err != nil {
		return nil, err
	}
	llmClient, err := newLLM(opts)
	if err != nil {
		return nil, err
	}

	img, cleanup, err := openTree(ctx, &opts)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	analyzers := ecosystem.ImageAnalyzers(plugins)
	result := &Result{SchemaVersion: SchemaVersion, Target: img.Ref, Mode: opts.mode(), Module: opts.Module}

	run := &imageRun{
		subjects: subjects,
		targeted: targeted(subjects),
		resolver: newResolver(),
		mine:     newMiner(opts, llmClient),
		cves:     opts.CVEs,
		logf:     logf,
	}

	// One ecosystem failing does not stop the others, but it is never silent:
	// the failure is logged, recorded in the result, and -- when it leaves the
	// run with nothing at all to report -- returned as an error, so that an
	// unreadable package database can never be mistaken for a clean image.
	applied, failed := 0, 0
	for _, a := range analyzers {
		er, findings := run.analyze(ctx, a, img)
		if er == nil {
			continue // did not apply
		}
		applied++
		if er.Error != "" {
			failed++
			logf("  ! %s: %s", a.ID(), er.Error)
		}
		result.Ecosystems = append(result.Ecosystems, *er)
		result.Findings = append(result.Findings, findings...)
	}
	if applied == 0 {
		return nil, fmt.Errorf("no ecosystem could analyze %s", img.Ref)
	}
	if failed == applied {
		return nil, fmt.Errorf("every ecosystem failed on %s; see the log above", img.Ref)
	}
	result.Findings = append(result.Findings, unmapped(opts.CVEs, result.Findings)...)

	// After the plugins, not before: this is the accumulation of every walk
	// they did, so it is only complete once they are done.
	if u := img.FS.Unreadable(); u.Any() {
		result.Unreadable = &u
		logf("  ! %d path(s) in %s could not be read; the scan does not account for them", u.Count, img.Ref)
		for _, p := range u.Paths {
			logf("    ! %s", p)
		}
	}
	result.Unreadable = noteRPMFailures(result.Unreadable, rpms, logf)

	severityOverlay(result.Findings, run.resolver.severities())
	// Filtering here, rather than in the renderer, is what keeps every count
	// downstream honest: the LLM is never billed for a row nobody will read,
	// and a hub's Matched is statements about findings that are actually in the
	// report rather than ones that had already been dropped.
	result.Findings, result.Withheld = severityFilter(result.Findings, opts.Severities)
	// The image is only a product for a scan that was given one: --rootfs
	// analyzes a tree whose provenance nobody recorded, and inventing a purl
	// from a directory name would look up an artifact that does not exist.
	productOverlay(result.Findings, opts.Image)
	sets := run.resolver.cveSets()
	upstreamOverlay(result.Findings, sets.Upstream)
	result.VEXHubs = vexOverlay(ctx, opts.VEXHubs, result.Findings, run.resolver.aliases(), logf)
	result.Triage = triageOverlay(ctx, opts.Triage, result.Findings, sets.All, logf)
	llmOverlay(ctx, llmClient, result.Findings, "", logf)
	sortFindings(result.Findings)
	return result, nil
}

// readRPMs resolves --rpm into the inventory the OS plugin will scan, and
// records it on opts for registryFor to pick up.
//
// It returns the whole result rather than just the packages because what would
// not parse matters as much as what did: see noteRPMFailures.
func readRPMs(ctx context.Context, opts *Options) (*rpmsrc.Result, error) {
	if len(opts.RPM) == 0 {
		return nil, nil
	}
	res, err := rpmsrc.Read(ctx, opts.RPM, opts.Logf)
	if err != nil {
		return nil, err
	}
	opts.rpmPackages = make([]ospkg.Supplied, 0, len(res.Packages))
	for _, p := range res.Packages {
		opts.rpmPackages = append(opts.rpmPackages, ospkg.Supplied{Package: p.Package, Meta: p.Meta})
	}
	for _, n := range res.Skipped {
		opts.Logf("  not scanned: %s (%s)", n.Src, n.Reason)
	}
	return res, nil
}

// noteRPMFailures records the package files that would not parse.
//
// They go into Unreadable because that is already what the whole tool means by
// "this report is not a complete account of what you pointed it at": it drives
// the log line, the report footer and the exit code, and every one of those is
// the right response here. Unreadable's own rule is that the loss surfaces at
// the reader that wanted it and can name what it lost -- so each one is named,
// with the reason, rather than counted.
//
// It folds into the set it is given and returns it, rather than writing to a
// report, because --format inventory needs the same accounting and has no
// report to write to.
func noteRPMFailures(u *target.Unreadable, rpms *rpmsrc.Result, logf func(string, ...any)) *target.Unreadable {
	if rpms == nil || len(rpms.Failed) == 0 {
		return u
	}
	if u == nil {
		u = &target.Unreadable{}
	}
	logf("  ! %d rpm package file(s) could not be read; the scan does not account for them", len(rpms.Failed))
	for _, n := range rpms.Failed {
		logf("    ! %s: %s", n.Src, n.Reason)
		u.Count++
		if len(u.Paths) < maxRPMFailureSample {
			u.Paths = append(u.Paths, fmt.Sprintf("%s: %s", n.Src, n.Reason))
		}
	}
	return u
}

// maxRPMFailureSample bounds the named sample in the JSON, for the same reason
// target caps its own: a directory whose every file is an HTML error page
// would otherwise put a few thousand near-identical lines in the report. The
// count stays exact.
const maxRPMFailureSample = 10

// imageRun is the state every plugin in one image scan shares: what was asked
// for, and the advisory cache that keeps two plugins from querying OSV twice
// for the same coordinates.
type imageRun struct {
	subjects []ecosystem.Subject
	targeted bool
	resolver *advisoryResolver
	mine     *miner
	cves     []string
	logf     func(string, ...any)
}

// analyze runs one plugin's three phases, returning nil when the plugin does
// not apply to the image at all.
func (r *imageRun) analyze(ctx context.Context, a ecosystem.ImageAnalyzer, img *target.Image) (*ecosystem.EcosystemResult, []Finding) {
	subjects, logf := r.subjects, r.logf
	er := &ecosystem.EcosystemResult{ID: a.ID()}

	ok, err := a.DetectImage(ctx, img)
	if err != nil {
		// A detection that failed is not a detection that said no. Recording
		// it as "this plugin does not apply" would drop the ecosystem from the
		// report entirely.
		er.Error = fmt.Sprintf("detect: %v", err)
		return er, nil
	}
	if !ok {
		return nil, nil
	}

	components, err := a.InventoryImage(ctx, img, subjects)
	if err != nil {
		er.Error = fmt.Sprintf("inventory: %v", err)
		return er, nil
	}
	er.Components = len(components)
	er.Ecosystems = distinctEcosystems(components)

	items := r.resolver.workItems(ctx, components, r.cves, r.targeted, logf)
	if ecosystem.UsesHints(a) {
		r.mine.apply(ctx, a.ID(), items)
	}

	findings, err := a.AnalyzeImage(ctx, img, items)
	if err != nil {
		er.Error = fmt.Sprintf("analyze: %v", err)
		return er, nil
	}
	return er, stamp(a.ID(), findings)
}

// distinctEcosystems reports the concrete OSV ecosystems an inventory produced.
func distinctEcosystems(components []ecosystem.Component) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range components {
		if c.Ecosystem != "" && !seen[c.Ecosystem] {
			seen[c.Ecosystem] = true
			out = append(out, c.Ecosystem)
		}
	}
	sort.Strings(out)
	return out
}

// runRepo checks out a git repository and hands it to every source analyzer.
func runRepo(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf

	plugins, subjects, err := plan(opts)
	if err != nil {
		return nil, err
	}
	llmClient, err := newLLM(opts)
	if err != nil {
		return nil, err
	}

	src, cleanup, err := source.Checkout(ctx, opts.Repo, opts.Ref, opts.Path, logf)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	result := &Result{SchemaVersion: SchemaVersion, Target: opts.Repo, Mode: "repo", Module: opts.Module}

	applied := 0
	for _, a := range ecosystem.SourceAnalyzers(plugins) {
		ok, err := a.DetectSource(ctx, src)
		if err != nil {
			return nil, fmt.Errorf("%s: detect: %w", a.ID(), err)
		}
		if !ok {
			continue
		}
		applied++

		findings, err := a.AnalyzeSource(ctx, src, subjects, opts.CVEs)
		if err != nil {
			return nil, err
		}
		result.Findings = append(result.Findings, stamp(a.ID(), findings)...)
	}

	// The inventory-driven analyzers run through the same three phases as an
	// image scan, sharing one advisory cache between them.
	run := &sourceRun{
		subjects: subjects,
		targeted: targeted(subjects),
		resolver: newResolver(),
		cves:     opts.CVEs,
		logf:     logf,
	}
	for _, a := range ecosystem.InventorySourceAnalyzers(plugins) {
		findings, ok, err := run.analyze(ctx, a, src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.ID(), err)
		}
		if !ok {
			continue
		}
		applied++
		result.Findings = append(result.Findings, findings...)
	}
	// No analyzer recognizing the tree must not read as a clean scan: an empty
	// findings array is indistinguishable from "checked, nothing wrong".
	if applied == 0 {
		return nil, fmt.Errorf("no ecosystem could analyze %s (looked in %s)", opts.Repo, src.Subdir)
	}
	result.Findings = append(result.Findings, unmapped(opts.CVEs, result.Findings)...)

	severityOverlay(result.Findings, run.resolver.severities())
	// See runTree for why the filter runs before the overlays rather than in
	// the renderer. Repo mode is the path where it bites hardest: govulncheck's
	// OpenVEX carries no severity, so every Go finding here is UNKNOWN and a
	// --severity that does not name UNKNOWN empties the report completely. The
	// renderer has to say so, which is what Withheld is for.
	result.Findings, result.Withheld = severityFilter(result.Findings, opts.Severities)
	// No productOverlay here: repo mode has no image, and the only artifact a
	// checkout is is its own module, which the Go plugin already recorded.
	sets := run.resolver.cveSets()
	upstreamOverlay(result.Findings, sets.Upstream)
	result.VEXHubs = vexOverlay(ctx, opts.VEXHubs, result.Findings, run.resolver.aliases(), logf)
	result.Triage = triageOverlay(ctx, opts.Triage, result.Findings, sets.All, logf)
	llmOverlay(ctx, llmClient, result.Findings, "source tree", logf)
	sortFindings(result.Findings)
	return result, nil
}

// sourceRun is imageRun's counterpart for the checkout analyzers: the same
// shared advisory cache, over a source tree instead of an image.
//
// It has no miner, and that is a decision rather than an omission. A mined hint
// may only support a not_affected-flavored status after the plugin validates it
// against something it can observe, and what repo mode observes is a lock file:
// a list of names and versions with no file list to check a module path
// against. Every hint would therefore be inert, so asking the model for one
// would be a round trip per advisory spent on an answer nothing can use.
type sourceRun struct {
	subjects []ecosystem.Subject
	targeted bool
	resolver *advisoryResolver
	cves     []string
	logf     func(string, ...any)
}

// analyze runs one plugin's three phases. The bool reports whether the plugin
// applied to the checkout at all.
//
// Unlike imageRun.analyze this returns errors rather than recording them,
// matching the rest of repo mode: an image scan has many ecosystems and can
// afford to lose one, while a checkout usually has exactly the ecosystem the
// user came for, and swallowing its failure would leave nothing to report.
func (r *sourceRun) analyze(ctx context.Context, a ecosystem.InventorySourceAnalyzer, src *target.Source) ([]Finding, bool, error) {
	ok, err := a.DetectSource(ctx, src)
	if err != nil {
		return nil, false, fmt.Errorf("detect: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	components, err := a.InventorySource(ctx, src, r.subjects)
	if err != nil {
		return nil, false, fmt.Errorf("inventory: %w", err)
	}

	items := r.resolver.workItems(ctx, components, r.cves, r.targeted, r.logf)
	findings, err := a.AnalyzeSource(ctx, src, items)
	if err != nil {
		return nil, false, fmt.Errorf("analyze: %w", err)
	}
	return stamp(a.ID(), findings), true, nil
}

// advisoryResolver turns an inventory into per-component advisory sets.
//
// It lives here rather than in the plugins so that no plugin decides which
// advisories exist for the code it just examined — the presence test and the
// vulnerability list come from independent parties.
type advisoryResolver struct {
	client *osv.Client
	cache  map[string]map[string]*osv.Advisory // component key -> advisories
}

func newResolver() *advisoryResolver {
	return &advisoryResolver{
		client: osv.NewClient(),
		cache:  map[string]map[string]*osv.Advisory{},
	}
}

// workItems pairs each component with its advisories and the requested ids.
func (r *advisoryResolver) workItems(ctx context.Context, components []ecosystem.Component, requested []string, targeted bool, logf func(string, ...any)) []ecosystem.WorkItem {
	r.prefetch(ctx, components, logf)

	out := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		out = append(out, ecosystem.WorkItem{
			Component:  c,
			Advisories: r.advisories(ctx, c, logf),
			Requested:  requested,
			Targeted:   targeted,
		})
	}
	return out
}

// prefetch resolves every uncached component in one batched round trip.
//
// A whole-image inventory is hundreds of packages, and each of those is one or
// two OSV names; a query apiece is several minutes of sequential HTTP for a
// scan that should take seconds. Batching is therefore a prerequisite for OS
// package support rather than a tuning knob.
//
// Failure is not fatal and not silent: the batch is abandoned with a message
// and each component falls back to its own query, so one unlucky request
// cannot zero out the advisory set for an entire image — which would render as
// a clean report.
func (r *advisoryResolver) prefetch(ctx context.Context, components []ecosystem.Component, logf func(string, ...any)) {
	// span records where one component's refs sit in the flattened request, so
	// the answers can be folded back together afterwards.
	type span struct {
		key        string
		start, end int
	}

	var (
		refs  []osv.Ref
		spans []span
		queue = map[string]bool{}
	)
	for _, c := range components {
		key := c.Key()
		if _, done := r.cache[key]; done || queue[key] || c.Ecosystem == "" {
			continue
		}
		names := queryNames(c)
		if len(names) == 0 {
			continue
		}
		queue[key] = true
		spans = append(spans, span{key, len(refs), len(refs) + len(names)})
		for _, n := range names {
			refs = append(refs, osv.Ref{Ecosystem: c.Ecosystem, Release: c.Release, Name: n, Version: c.Version})
		}
	}
	// One ref is the same round trip either way, and going through the batch
	// endpoint for it would change the request every existing Go-mode scan
	// makes for no gain.
	if len(refs) < 2 {
		return
	}

	logf("Resolving advisories for %d components (%d OSV queries)...", len(spans), len(refs))
	got, err := r.client.QueryBatch(ctx, refs)
	if err != nil {
		logf("  ! OSV batch query failed (%v); falling back to one query per component", err)
		return
	}
	for _, s := range spans {
		r.cache[s.key] = merge(got[s.start:s.end])
	}
}

// advisories resolves one component, caching by key so several binaries linking
// the same module version cost a single query.
//
// A lookup failure yields an empty advisory set rather than an error, which is
// what makes an explicitly requested id still report as undetermined instead of
// aborting the whole run.
func (r *advisoryResolver) advisories(ctx context.Context, c ecosystem.Component, logf func(string, ...any)) map[string]*osv.Advisory {
	if adv, ok := r.cache[c.Key()]; ok {
		return adv
	}
	adv := map[string]*osv.Advisory{}
	if c.Ecosystem == "" {
		// An empty ecosystem is not a query OSV can answer, and a component
		// that silently resolves to zero advisories reads as clean. Say so.
		logf("  ! component %s@%s declares no ecosystem; skipping advisory lookup", c.Name, c.Version)
		r.cache[c.Key()] = adv
		return adv
	}

	var results []map[string]*osv.Advisory
	for _, name := range queryNames(c) {
		ref := osv.Ref{Ecosystem: c.Ecosystem, Release: c.Release, Name: name, Version: c.Version}
		got, err := r.client.Query(ctx, ref)
		if err != nil {
			logf("  ! OSV query failed for %s: %v", ref, err)
			continue
		}
		results = append(results, got)
	}
	adv = merge(results)
	r.cache[c.Key()] = adv
	return adv
}

// severity is the display rating for one advisory, and the vector it came from.
type severity struct {
	label  string
	vector string
}

// severities flattens everything the resolver fetched into a lookup from
// advisory id to its rating.
//
// This costs no network traffic at all. Every advisory a finding could be about
// was already fetched, decoded and cached to decide whether the finding existed;
// this reads the fields that were sitting in those same records unused.
//
// Each advisory is indexed under its own id and under every alias, because a
// finding names the advisory by whichever id its plugin was working from --
// ospkg reports DEBIAN-CVE-2022-27943 while a caller may have asked about
// CVE-2022-27943, and workItems already treats the two as interchangeable.
func (r *advisoryResolver) severities() map[string]severity {
	out := map[string]severity{}
	for _, set := range r.cache {
		for _, adv := range set {
			if adv == nil {
				continue
			}
			s := severity{label: adv.Severity(), vector: adv.CVSSVector}
			for _, key := range append([]string{adv.ID}, adv.Aliases...) {
				if key == "" {
					continue
				}
				// A key can arrive from more than one component's query. Keep
				// the more severe reading rather than letting map iteration
				// order decide, so a repeated scan cannot report two different
				// severities for the same advisory.
				if prev, ok := out[key]; ok && cvss.Rank(prev.label) <= cvss.Rank(s.label) {
					continue
				}
				out[key] = s
			}
		}
	}
	return out
}

// aliases maps every id an advisory is known by onto that advisory's whole set
// of ids.
//
// It exists for the VEX overlay. A finding names its advisory by whichever id
// its plugin was working from -- the Go plugin reports GO-2025-3547 -- while a
// hub files under whichever its own scanner used, which for every hub seen so
// far is the CVE. Neither side is wrong and neither carries the other's
// spelling, so matching them means going through the record that lists both,
// which the resolver has already fetched.
func (r *advisoryResolver) aliases() map[string][]string {
	out := map[string][]string{}
	for _, set := range r.cache {
		for _, adv := range set {
			if adv == nil {
				continue
			}
			ids := append([]string{adv.ID}, adv.Aliases...)
			for _, key := range ids {
				if key != "" {
					out[key] = ids
				}
			}
		}
	}
	return out
}

// idSets is what the CVE-joining consumers need out of the advisory cache.
//
// It is separate from aliases() because the two relations are not the same
// claim, and confusing them has consequences in opposite directions. See
// cveSets.
type idSets struct {
	// All maps every id an advisory is known by onto every id it relates to at
	// all: its own, its aliases, and the CVEs it says it addresses.
	All map[string][]string
	// Upstream maps a bundling advisory -- by its own id and by each CVE it
	// fixes -- onto just the CVEs it addresses, so the report can name them
	// without re-deriving the difference. Advisories about a single
	// vulnerability are absent, not present with a one-element list.
	Upstream map[string][]string
}

// cveSets is the advisory cache viewed as "what CVEs is this finding about".
//
// aliases() answers a narrower question -- what else is this same vulnerability
// called -- and VEX matching must keep using it: a hub statement about one CVE
// must not suppress a finding about the eight that SUSE-SU-2026:0312-1 bundles.
// Over-suppression is the one failure this tool may not have.
//
// Prioritisation and --cves need the wider set and are safe with it, because
// both take a maximum over the set rather than a single value: a bundle is as
// urgent as the most-exploited thing its patch fixes, and a user filtering for
// a CVE wants the advisory that addresses it. On SUSE and Red Hat the wider set
// is the only one that resolves anything at all -- SUSE-SU-2026:0312-1 and
// RHSA-2024:2447 carry no aliases and no CVE in their own ids.
//
// Like aliases(), this costs no network traffic: every record was already
// fetched to decide whether the finding existed.
func (r *advisoryResolver) cveSets() idSets {
	out := idSets{All: map[string][]string{}, Upstream: map[string][]string{}}
	for _, set := range r.cache {
		for _, adv := range set {
			if adv == nil {
				continue
			}
			ids := append([]string{adv.ID}, adv.Aliases...)
			ids = append(ids, adv.Upstream...)
			for _, key := range ids {
				if key != "" {
					out.All[key] = ids
				}
			}
			// Keyed by the advisory's own id, for an ordinary scan where the
			// row is the bundle; and by each CVE it fixes, for --cves where
			// the row is one member and the fixed version it reports came out
			// of a patch covering all of them. Saying so is the difference
			// between "this upgrade fixes your CVE" and "this upgrade fixes
			// your CVE and seven others you did not ask about".
			if len(adv.Upstream) > 0 {
				for _, key := range append([]string{adv.ID}, adv.Upstream...) {
					if key != "" {
						out.Upstream[key] = adv.Upstream
					}
				}
			}
		}
	}
	return out
}

// upstreamOverlay records, on each finding, the CVEs its advisory addresses.
//
// It runs beside severityOverlay for the same reason severityOverlay exists at
// all: a plugin is handed a presence question and never sees the advisory, so
// anything read off the record has to be attached where the records live.
//
// Only a genuine bundle is annotated. A Debian record addresses the one CVE its
// own id already spells -- DEBIAN-CVE-2023-45853 addresses CVE-2023-45853 --
// and repeating it would put an "addresses:" line under every Debian row
// telling the reader what the row says.
func upstreamOverlay(findings []Finding, ups map[string][]string) {
	for i := range findings {
		f := &findings[i]
		for _, key := range []string{f.ID, f.CVE, f.GoID} {
			if key == "" {
				continue
			}
			u, ok := ups[key]
			if !ok {
				continue
			}
			// findingCVEs with no id sets is exactly "what this row's own ids
			// already name", which is the thing an addresses: line must add to.
			if len(u) == 1 && slices.Contains(findingCVEs(*f, nil), u[0]) {
				break
			}
			f.Upstream = u
			break
		}
	}
}

// severityOverlay labels each finding with its advisory's severity, in place.
//
// It runs in the orchestrator beside llmOverlay, and for the same reason: a
// plugin cannot forget to do something it does not do. Plugins never see an
// advisory's metadata -- they are handed a presence question and answer it --
// so severity has to be attached where the advisories live.
//
// A finding whose advisory is not in the map keeps an empty Severity. That is
// deliberately distinct from UNKNOWN, which means a record was read and
// published no rating: the renderer needs to be able to tell "nobody rated
// this" from "we never looked".
func severityOverlay(findings []Finding, sev map[string]severity) {
	for i := range findings {
		f := &findings[i]
		for _, key := range []string{f.CVE, f.ID, f.GoID} {
			if key == "" {
				continue
			}
			if s, ok := sev[key]; ok {
				f.Severity = s.label
				f.CVSS = s.vector
				break
			}
		}
	}
}

// queryNames is the component's OSV names, primary first, deduplicated.
func queryNames(c ecosystem.Component) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range append([]string{c.Name}, c.AltNames...) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// merge folds the per-name advisory sets into one.
//
// First name wins on a conflict. The records are the same either way -- the
// only ref-dependent field is the Go import path list, and Go components have
// exactly one name -- so this only settles which copy is kept.
func merge(sets []map[string]*osv.Advisory) map[string]*osv.Advisory {
	out := map[string]*osv.Advisory{}
	for _, set := range sets {
		for id, adv := range set {
			if _, ok := out[id]; !ok {
				out[id] = adv
			}
		}
	}
	return out
}

// unmapped accounts for the requested ids that no ecosystem said anything
// about.
//
// Every id the user asks for has to appear in the output. When a package was
// named, the plugin owning it reports the id undetermined and this finds
// nothing left to do. When nothing was named -- `--cves CVE-... ` against a
// whole image -- the plugins deliberately stay quiet about the hundreds of
// components an id does not apply to, and the only place that can tell the id
// landed nowhere at all is here, after every ecosystem has reported.
//
// The alternative is silence, and a missing id reads as a clean one.
func unmapped(requested []string, findings []Finding) []Finding {
	if len(requested) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[f.CVE] = true
	}

	var out []Finding
	for _, id := range requested {
		if seen[id] {
			continue
		}
		seen[id] = true // a duplicate --cves entry is one finding, not two
		out = append(out, Finding{
			ID:     id,
			CVE:    id,
			Status: ecosystem.StatusUndetermined,
			Reason: "no_component_matched",
		})
	}
	return out
}

// stamp records which plugin produced each finding, and mirrors the Go-only
// identity fields onto their ecosystem-neutral names.
//
// The orchestrator does this rather than the plugins, so that Ecosystem is a
// fact about what ran instead of a claim a plugin makes about itself, and so
// that the two spellings of a finding's identity cannot drift: one plugin
// forgetting to fill in Package would publish a finding about nothing.
func stamp(id string, findings []Finding) []Finding {
	for i := range findings {
		f := &findings[i]
		f.Ecosystem = id
		f.ID = f.CVE
		f.Package = f.Module
		f.Location = f.Binary
	}
	return findings
}

// newLLM builds the assessment client, or returns nil when --llm is off.
func newLLM(opts Options) (*llm.Client, error) {
	if !opts.UseLLM {
		return nil, nil
	}
	c, err := llm.NewClient(llm.ConfigFrom(opts.LLMEndpoint, opts.LLMModel, opts.LLMCommand))
	if err != nil {
		// Not wrapped with a prefix: the no-provider error is a formatted
		// paragraph of shell to copy, and "llm client: " in front of its first
		// line would break the block it is trying to show.
		return nil, err
	}
	opts.Logf("LLM overlay: asking %s", c.Describe())
	return c, nil
}

// llmOverlay attaches a model assessment to each genuinely-affected finding,
// in place.
//
// It runs after every plugin has finished, which is what makes the LLM an
// overlay in fact and not just in intent: no status in the report can depend on
// it, and turning --llm off changes only whether an "llm" object is attached.
//
// location names what was analyzed for findings that have no binary of their
// own, because repo mode assesses a source tree rather than an artifact.
// A failed assessment is logged and skipped: losing an advisory opinion must
// never lose the deterministic finding underneath it.
func llmOverlay(ctx context.Context, client *llm.Client, findings []Finding, location string, logf func(string, ...any)) {
	if client == nil {
		return
	}
	for i := range findings {
		f := &findings[i]
		if !f.Affected() {
			continue
		}
		binary := f.Binary
		if binary == "" {
			binary = location
		}
		v, err := client.Assess(ctx, llm.Request{
			Ecosystem: f.Ecosystem,
			CVE:       f.CVE,
			Module:    f.Module,
			Version:   f.Version,
			Packages:  f.Packages,
			Binary:    binary,
			Reachable: f.Reachability,
		})
		if err != nil {
			logf("  ! LLM assess failed for %s: %v", f.CVE, err)
			continue
		}
		f.LLM = v
	}
}

// sortFindings orders findings by location then advisory id. Repo-mode findings
// have no binary, so they sort by id alone, as they always have.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Binary != b.Binary {
			return a.Binary < b.Binary
		}
		// OS findings have no binary of their own, so without the module (the
		// package name, for those) every ecosystem's findings would interleave
		// in advisory order.
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return a.CVE < b.CVE
	})
}
