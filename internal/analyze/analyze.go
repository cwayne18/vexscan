// Package analyze orchestrates the vexscan pipeline: extract an image, find
// its Go binaries, resolve vulnerable packages from OSV, and decide for each
// requested CVE whether the vulnerable code is present / reachable, optionally
// consulting an LLM for the genuinely-linked survivors.
package analyze

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/image"
	"github.com/cwayne18/vexscan/internal/llm"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/source"
	"github.com/cwayne18/vexscan/internal/target"
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
	if opts.Module == "std" {
		opts.Module = binscan.StdlibModule
	}
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

// runImage extracts a container image and inspects its Go binaries.
func runImage(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if opts.OS == "" {
		opts.OS = "linux"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
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

	logf("Scanning for Go binaries...")
	bins := binscan.FindGoBinaries(img.FS.Root())
	logf("Found %d Go binaries.", len(bins))

	osvClient := osv.NewClient()
	osvCache := map[string]map[string]*osv.Advisory{} // version -> advisory map

	var llmClient *llm.Client
	if opts.UseLLM {
		llmClient, err = llm.NewClient(opts.LLMModel, opts.Token)
		if err != nil {
			return nil, fmt.Errorf("llm client: %w", err)
		}
	}

	result := &Result{Target: opts.Image, Mode: "image", Module: opts.Module}

	for _, bin := range bins {
		version := opts.Version
		if version == "" {
			version = bin.ModuleVersion(opts.Module)
		}
		if version == "" {
			continue // module not linked into this binary and no override given
		}
		rel := target.Rel(img.FS.Root(), bin.Path)

		advMap, ok := osvCache[version]
		if !ok {
			advMap, err = osvClient.Query(ctx, opts.Module, version)
			if err != nil {
				logf("  ! OSV query failed for %s@%s: %v", opts.Module, version, err)
				advMap = map[string]*osv.Advisory{}
			}
			osvCache[version] = advMap
		}

		syms, err := binscan.LoadSymbols(bin.Path)
		if err != nil {
			logf("  ! cannot read %s: %v", rel, err)
			continue
		}
		stripped := binscan.IsStripped(bin.Path)

		// govulncheck is computed lazily (only for non-stripped binaries with a
		// linked package candidate).
		var gvIDs map[string]struct{}
		gvDone := false
		govuln := func() map[string]struct{} {
			if !gvDone {
				gvIDs = binscan.GovulncheckNotAffected(ctx, bin.Path)
				gvDone = true
			}
			return gvIDs
		}

		for _, req := range resolveRequests(opts.CVEs, advMap) {
			f := evaluate(ctx, evalCtx{
				binaryRel: rel,
				module:    opts.Module,
				version:   version,
				stripped:  stripped,
				syms:      syms,
				govuln:    govuln,
				llmClient: llmClient,
				logf:      logf,
			}, req.id, req.adv)
			result.Findings = append(result.Findings, f)
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Binary != b.Binary {
			return a.Binary < b.Binary
		}
		return a.CVE < b.CVE
	})
	return result, nil
}

// runRepo clones a git repository and runs govulncheck in source mode, whose
// call-graph reachability is authoritative for a source tree.
func runRepo(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf

	var llmClient *llm.Client
	if opts.UseLLM {
		var err error
		llmClient, err = llm.NewClient(opts.LLMModel, opts.Token)
		if err != nil {
			return nil, fmt.Errorf("llm client: %w", err)
		}
	}

	stmts, err := source.CloneAndScan(ctx, opts.Repo, opts.Ref, opts.Path, opts.GoVersion, logf)
	if err != nil {
		return nil, err
	}

	result := &Result{Target: opts.Repo, Mode: "repo", Module: opts.Module}

	// Index statements for the target module by every id they are known by.
	byID := map[string]source.Statement{}
	moduleSeen := false
	var moduleVersion string
	for _, st := range stmts {
		if st.Module != opts.Module {
			continue
		}
		moduleSeen = true
		if moduleVersion == "" {
			moduleVersion = st.Version
		}
		for _, id := range st.IDs() {
			byID[id] = st
		}
	}

	makeFinding := func(id string, st source.Statement, matched bool) Finding {
		f := Finding{
			Module:  opts.Module,
			Version: moduleVersion,
			CVE:     id,
			Method:  "govulncheck-source",
		}
		if !matched {
			// No govulncheck statement for this id at the scanned version.
			if moduleSeen {
				f.Version = moduleVersion
				f.Status = StatusNotPresent
				f.Justification = "vulnerable_code_not_present"
				f.Reason = "not flagged by govulncheck source analysis"
			} else {
				f.Status = StatusUndetermined
				f.Reason = "module_not_in_dependency_graph"
			}
			return f
		}
		f.GoID = st.GoID
		f.Version = st.Version
		switch {
		case st.Status == "affected":
			f.Status = StatusReachable
			if llmClient != nil {
				v, lerr := llmClient.Assess(ctx, llm.Request{
					CVE:       id,
					Module:    opts.Module,
					Version:   st.Version,
					Binary:    "source tree",
					Reachable: "reachable (govulncheck source mode: the vulnerable symbol is called)",
				})
				if lerr != nil {
					logf("  ! LLM assess failed for %s: %v", id, lerr)
				} else {
					f.LLM = v
				}
			}
		case st.Justification == "vulnerable_code_not_in_execute_path":
			f.Status = StatusNotInPath
			f.Justification = st.Justification
		default: // vulnerable_code_not_present or any other not_affected
			f.Status = StatusNotPresent
			if st.Justification != "" {
				f.Justification = st.Justification
			} else {
				f.Justification = "vulnerable_code_not_present"
			}
		}
		return f
	}

	if len(opts.CVEs) > 0 {
		for _, id := range opts.CVEs {
			st, ok := byID[id]
			result.Findings = append(result.Findings, makeFinding(id, st, ok))
		}
	} else {
		// Report every distinct advisory govulncheck found for the module.
		seen := map[string]bool{}
		for _, st := range stmts {
			if st.Module != opts.Module || seen[st.GoID] {
				continue
			}
			seen[st.GoID] = true
			id := primaryID(st)
			result.Findings = append(result.Findings, makeFinding(id, st, true))
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].CVE < result.Findings[j].CVE
	})
	return result, nil
}

// primaryID prefers a CVE alias for display, falling back to the GO id.
func primaryID(st source.Statement) string {
	for _, a := range st.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return st.GoID
}

type request struct {
	id  string
	adv *osv.Advisory
}

// resolveRequests turns the CVE filter (or "all") into concrete advisory
// lookups. In filter mode every requested id is returned, with a nil advisory
// when OSV has no mapping (recorded as undetermined). In "all" mode every
// distinct advisory is returned keyed by its canonical GO id.
func resolveRequests(cves []string, advMap map[string]*osv.Advisory) []request {
	if len(cves) > 0 {
		out := make([]request, 0, len(cves))
		for _, id := range cves {
			out = append(out, request{id: id, adv: advMap[id]})
		}
		return out
	}
	seen := map[string]bool{}
	var out []request
	for _, adv := range advMap {
		if seen[adv.GoID] {
			continue
		}
		seen[adv.GoID] = true
		out = append(out, request{id: adv.GoID, adv: adv})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

type evalCtx struct {
	binaryRel string
	module    string
	version   string
	stripped  bool
	syms      *binscan.Symbols
	govuln    func() map[string]struct{}
	llmClient *llm.Client
	logf      func(string, ...any)
}

func evaluate(ctx context.Context, ec evalCtx, id string, adv *osv.Advisory) Finding {
	f := Finding{
		Binary:   ec.binaryRel,
		Module:   ec.module,
		Version:  ec.version,
		CVE:      id,
		Stripped: ec.stripped,
	}
	if adv == nil {
		f.Status = StatusUndetermined
		f.Reason = "no_osv_package_mapping"
		return f
	}
	f.GoID = adv.GoID

	var pkgs []string
	var linked bool
	if len(adv.Pkgs) > 0 {
		pkgs = append(pkgs, adv.Pkgs...)
		sort.Strings(pkgs)
		f.Granularity = "package"
		for _, p := range pkgs {
			if ec.syms.PackagePresent(p) {
				linked = true
				break
			}
		}
	} else {
		pkgs = []string{ec.module}
		f.Granularity = "module"
		linked = ec.syms.ModulePresent(ec.module)
	}
	f.Packages = pkgs

	switch {
	case !linked:
		f.Status = StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		if f.Granularity == "module" {
			f.Method = "pclntab-module"
		} else {
			f.Method = "pclntab"
		}
	case f.Granularity == "package" && !ec.stripped && inNotAffected(ec.govuln(), id, adv.GoID):
		f.Status = StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = "govulncheck"
	default:
		f.Status = StatusLinked
		if ec.llmClient != nil {
			v, err := ec.llmClient.Assess(ctx, llm.Request{
				CVE:       id,
				Module:    ec.module,
				Version:   ec.version,
				Packages:  pkgs,
				Binary:    ec.binaryRel,
				Reachable: reachability(ec.stripped),
			})
			if err != nil {
				ec.logf("  ! LLM assess failed for %s: %v", id, err)
			} else {
				f.LLM = v
			}
		}
	}
	return f
}

func reachability(stripped bool) string {
	if stripped {
		return "linked"
	}
	return "linked (symbols retained; reachability not asserted)"
}

func inNotAffected(set map[string]struct{}, ids ...string) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}
