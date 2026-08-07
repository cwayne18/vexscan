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
	purl      string
	// product is the purl of the binary's own main module -- the artifact a VEX
	// hub files statements about this binary's dependencies under. Empty for a
	// binary built outside a module, which simply means no hub lookup.
	product  string
	stripped bool
	syms     *binscan.Symbols
	// govuln returns the ids govulncheck binary mode marked not_affected. It is
	// a function so the subprocess is only paid for when a verdict depends on it.
	govuln func() map[string]struct{}
	// govulnAvailable is whether the govulncheck binary was found on PATH. When
	// it is not, a linked package-granularity finding on a non-stripped binary
	// could not be tested for reachability, and evaluate records that on the
	// finding so a skipped test is distinguishable from one that ruled nothing
	// out.
	govulnAvailable bool
	logf            func(string, ...any)
}

// OriginGovulncheckUnavailable marks a linked finding whose reachability could
// not be tested because the govulncheck binary was not on PATH. It aliases the
// canonical constant in the ecosystem package, where the report reads it.
const OriginGovulncheckUnavailable = ecosystem.OriginGovulncheckUnavailable

// evaluate classifies one advisory against one binary.
//
// It applies only deterministic signals and never consults the LLM: the
// orchestrator adds that overlay afterwards, using Reachability, so a run
// without --llm and a run with it agree on every status.
func evaluate(_ context.Context, ec evalCtx, id string, adv *osv.Advisory) ecosystem.Finding {
	stripped := ec.stripped
	f := ecosystem.Finding{
		Binary:   ec.binaryRel,
		Module:   ec.module,
		Version:  ec.version,
		PURL:     ec.purl,
		Product:  ec.product,
		CVE:      id,
		Stripped: &stripped,
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
	case f.Granularity == "package" && !ec.stripped && ec.govulnAvailable && inNotAffected(ec.govuln(), id, adv.ID):
		f.Status = ecosystem.StatusNotInPath
		f.Justification = "vulnerable_code_not_in_execute_path"
		f.Method = "govulncheck"
	default:
		f.Status = ecosystem.StatusLinked
		f.Reachability = reachability(ec.stripped)
		// A linked, package-granularity finding on a non-stripped binary is
		// exactly the shape govulncheck could have narrowed to
		// not_in_execute_path. When the binary is missing there is no verdict
		// to consult, and the finding stays linked for want of the test rather
		// than because the test ran and found the code reachable. Record that
		// on the finding so the report can warn, and so the JSON does not read
		// as a reachability test that had nothing to rule out.
		if f.Granularity == "package" && !ec.stripped && !ec.govulnAvailable {
			f.Reachability = "linked (govulncheck not found; reachability not tested)"
			f.Evidence = append(f.Evidence, ecosystem.Evidence{
				Origin: OriginGovulncheckUnavailable,
				Detail: "govulncheck is not on PATH, so binary-mode reachability was not tested; " +
					"install govulncheck to let this finding be ruled not_in_execute_path when its code is unreachable",
			})
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
