package golang

import (
	"context"
	"sort"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/osv"
)

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
	f.GoID = adv.ID

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
	case f.Granularity == "package" && !ec.stripped && inNotAffected(ec.govuln(), id, adv.ID):
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
