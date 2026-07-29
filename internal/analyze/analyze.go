// Package analyze orchestrates the vexscan pipeline: prepare a target
// (extract an image, or check out a source tree), ask each ecosystem plugin
// what it finds, resolve advisories for what the plugins inventory, and
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
	"sort"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/ecosystem/golang"
	"github.com/cwayne18/vexscan/internal/image"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/source"
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

// Options configure a run. Set exactly one of Image or Repo.
type Options struct {
	Image   string
	Repo    string // git repo (source mode); mutually exclusive with Image
	Ref     string // branch/tag/commit for Repo
	Path    string // module subdirectory within Repo (default ".")
	Module  string
	CVEs    []string // optional filter; empty means "all advisories for the module version"
	Version string   // optional override of the detected module version (image mode)
	OS      string
	Arch    string

	// GoVersion optionally pins the Go toolchain for repo-mode analysis
	// (e.g. "1.24.0"). Mainly useful with --module stdlib, whose findings depend
	// on the toolchain version.
	GoVersion string

	UseLLM   bool
	LLMModel string
	Token    string

	// Logf receives progress messages (may be nil).
	Logf func(format string, args ...any)
}

// Result is the full analysis output.
type Result struct {
	Target   string    `json:"target"` // image ref or repo
	Mode     string    `json:"mode"`   // "image" | "repo"
	Module   string    `json:"module"`
	Findings []Finding `json:"findings"`
}

// Run dispatches to image or source-repo analysis.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	// The Go standard library is "stdlib" in OSV and govulncheck; accept "std"
	// as a convenience alias.
	opts.Module = golang.NormalizeModule(opts.Module)

	if opts.Image != "" && opts.Repo != "" {
		return nil, fmt.Errorf("set only one of --image or --repo")
	}
	if opts.Repo != "" {
		return runRepo(ctx, opts)
	}
	if opts.Image != "" {
		return runImage(ctx, opts)
	}
	return nil, fmt.Errorf("one of --image or --repo is required")
}

// registryFor builds the plugin set for a run. Go is the only ecosystem today;
// the OS, PyPI and npm plugins register here.
func registryFor(opts Options) *ecosystem.Registry {
	return ecosystem.NewRegistry(
		golang.New(golang.Options{
			VersionOverride: opts.Version,
			GoVersion:       opts.GoVersion,
			Logf:            opts.Logf,
		}),
	)
}

// subjectsFor turns the user's selection into plugin subjects. Today that is
// exactly --module; --package and --all arrive with the new CLI surface.
func subjectsFor(opts Options) []ecosystem.Subject {
	return []ecosystem.Subject{{Name: opts.Module, Raw: opts.Module}}
}

// runImage extracts a container image and hands it to every image analyzer.
func runImage(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf
	if opts.OS == "" {
		opts.OS = "linux"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}

	// Build the LLM client before the extraction: a missing or rejected token
	// should fail in the first second, not after a multi-gigabyte pull.
	llmClient, err := newLLM(opts)
	if err != nil {
		return nil, err
	}

	dest, err := os.MkdirTemp("", "vexscan-fs-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dest)

	logf("Extracting %s (%s/%s)...", opts.Image, opts.OS, opts.Arch)
	ex := image.NewExtractor()
	ex.OS, ex.Arch = opts.OS, opts.Arch
	img, err := ex.Extract(ctx, opts.Image, dest)
	if err != nil {
		return nil, fmt.Errorf("extract image: %w", err)
	}

	analyzers := ecosystem.ImageAnalyzers(registryFor(opts).All())
	subjects := subjectsFor(opts)
	resolver := newResolver()
	result := &Result{Target: opts.Image, Mode: "image", Module: opts.Module}

	applied := 0
	for _, a := range analyzers {
		ok, err := a.DetectImage(ctx, img)
		if err != nil {
			return nil, fmt.Errorf("%s: detect: %w", a.ID(), err)
		}
		if !ok {
			continue
		}
		applied++

		components, err := a.InventoryImage(ctx, img, subjects)
		if err != nil {
			return nil, fmt.Errorf("%s: inventory: %w", a.ID(), err)
		}

		findings, err := a.AnalyzeImage(ctx, img, resolver.workItems(ctx, components, opts.CVEs, logf))
		if err != nil {
			return nil, fmt.Errorf("%s: analyze: %w", a.ID(), err)
		}
		result.Findings = append(result.Findings, findings...)
	}
	if applied == 0 {
		return nil, fmt.Errorf("no ecosystem could analyze %s", opts.Image)
	}

	llmOverlay(ctx, llmClient, result.Findings, "", logf)
	sortFindings(result.Findings)
	return result, nil
}

// runRepo checks out a git repository and hands it to every source analyzer.
func runRepo(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf

	llmClient, err := newLLM(opts)
	if err != nil {
		return nil, err
	}

	src, cleanup, err := source.Checkout(ctx, opts.Repo, opts.Ref, opts.Path, logf)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	analyzers := ecosystem.SourceAnalyzers(registryFor(opts).All())
	subjects := subjectsFor(opts)
	result := &Result{Target: opts.Repo, Mode: "repo", Module: opts.Module}

	applied := 0
	for _, a := range analyzers {
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
		result.Findings = append(result.Findings, findings...)
	}
	// No analyzer recognizing the tree must not read as a clean scan: an empty
	// findings array is indistinguishable from "checked, nothing wrong".
	if applied == 0 {
		return nil, fmt.Errorf("no ecosystem could analyze %s (looked in %s)", opts.Repo, src.Subdir)
	}

	llmOverlay(ctx, llmClient, result.Findings, "source tree", logf)
	sortFindings(result.Findings)
	return result, nil
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
func (r *advisoryResolver) workItems(ctx context.Context, components []ecosystem.Component, requested []string, logf func(string, ...any)) []ecosystem.WorkItem {
	r.prefetch(ctx, components, logf)

	out := make([]ecosystem.WorkItem, 0, len(components))
	for _, c := range components {
		out = append(out, ecosystem.WorkItem{
			Component:  c,
			Advisories: r.advisories(ctx, c, logf),
			Requested:  requested,
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
			refs = append(refs, osv.Ref{Ecosystem: c.Ecosystem, Name: n, Version: c.Version})
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
		ref := osv.Ref{Ecosystem: c.Ecosystem, Name: name, Version: c.Version}
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

// newLLM builds the assessment client, or returns nil when --llm is off.
func newLLM(opts Options) (*llm.Client, error) {
	if !opts.UseLLM {
		return nil, nil
	}
	c, err := llm.NewClient(opts.LLMModel, opts.Token)
	if err != nil {
		return nil, fmt.Errorf("llm client: %w", err)
	}
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
		return a.CVE < b.CVE
	})
}
