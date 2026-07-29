package golang

import (
	"context"
	"sort"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/osv"
)

type request struct {
	id  string
	adv *osv.Advisory
}

// resolveRequests turns the requested-id list (or "all") into concrete advisory
// lookups. In filter mode every requested id is returned, with a nil advisory
// when OSV has no mapping — such an id must still produce a finding, recorded
// undetermined, or a --cves scan would silently drop the ids it could not map
// and the omission would read as "not affected". In "all" mode every distinct
// advisory is returned keyed by its canonical GO id.
func resolveRequests(ids []string, advMap map[string]*osv.Advisory) []request {
	if len(ids) > 0 {
		out := make([]request, 0, len(ids))
		for _, id := range ids {
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

// evalCtx is everything evaluate needs about one binary.
type evalCtx struct {
	binaryRel string
	module    string
	version   string
	stripped  bool
	syms      *binscan.Symbols
	// govuln returns the ids govulncheck binary mode marked not_affected. It is
	// a function so the subprocess is only paid for when a verdict depends on it.
	govuln func() map[string]struct{}
	logf   func(string, ...any)
}

// evaluate classifies one advisory against one binary.
//
// It applies only deterministic signals and never consults the LLM: the
// orchestrator adds that overlay afterwards, using Reachability, so a run
// without --llm and a run with it agree on every status.
func evaluate(_ context.Context, ec evalCtx, id string, adv *osv.Advisory) ecosystem.Finding {
	f := ecosystem.Finding{
		Binary:   ec.binaryRel,
		Module:   ec.module,
		Version:  ec.version,
		CVE:      id,
		Stripped: ec.stripped,
	}
	if adv == nil {
		f.Status = ecosystem.StatusUndetermined
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
		f.Status = ecosystem.StatusNotPresent
		f.Justification = "vulnerable_code_not_present"
		if f.Granularity == "module" {
			f.Method = "pclntab-module"
		} else {
			f.Method = "pclntab"
		}
	case f.Granularity == "package" && !ec.stripped && inNotAffected(ec.govuln(), id, adv.GoID):
		f.Status = ecosystem.StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = "govulncheck"
	default:
		f.Status = ecosystem.StatusLinked
		f.Reachability = reachability(ec.stripped)
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
