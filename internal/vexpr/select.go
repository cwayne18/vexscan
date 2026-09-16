package vexpr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// Claim is one thing this scan wants a hub to record, in the terms both
// serialisations share.
//
// It exists so that deciding what to say happens once. A claim carries a
// vulnerability, the artifact and the component inside it, a verdict and the
// reasoning -- which is the entire content of a VEX statement, and is identical
// whether it ends up as an OpenVEX statement or as an entry in a CSAF
// product_status. Nothing about either format's spelling reaches this far.
type Claim struct {
	// Vuln is the id the claim is filed under, preferring a CVE.
	Vuln string
	// Aliases are the other ids the same vulnerability is known by, so a lookup
	// keyed on any of them still lands.
	Aliases []string
	// Product is the artifact purl -- a scanned image, a Go main module.
	Product string
	// Subcomponent is the dependency inside it the vulnerability is filed
	// against, which is what a vexscan finding actually is.
	Subcomponent string

	Status        string
	Justification string
	// Impact is the sentence explaining, to whoever reviews the pull request,
	// how vexscan reached the verdict.
	Impact    string
	Timestamp string
	// covered is set when a published statement already answers this finding
	// (the scan matched it against a --vexhub, so Finding.VEX is not nil). Such
	// a claim is kept rather than dropped: it is not written into the product's
	// own document -- adding what a hub is missing does not overrule a vendor
	// who has already spoken -- but it is still folded into any aggregate that
	// lags the per-product tree, which is the merged report a CI run reads.
	covered bool
}

// ProductProposal is every claim proposed for one product's document.
type ProductProposal struct {
	// Product is the artifact purl the claims are filed under.
	Product string
	// Claims are the not_affected claims, one per ruled-out finding, sorted so
	// a repeated run produces a byte-identical document.
	Claims []Claim
}

// unanswered is the proposal restricted to the claims no published statement
// already answers -- what belongs in the product's own document. An aggregate
// takes the whole proposal instead, and dedupes against its own contents.
func (p ProductProposal) unanswered() ProductProposal {
	out := ProductProposal{Product: p.Product}
	for _, c := range p.Claims {
		if !c.covered {
			out.Claims = append(out.Claims, c)
		}
	}
	return out
}

// selectProposals turns the ruled-out findings in one or more results into
// per-product proposals.
//
// It takes a slice because a fleet scan is one contribution, not forty. Each
// image is its own product and gets its own document, so grouping by product
// separates them again -- but doing the selection once means the hub is read
// once and any aggregate is merged once, rather than a hundred-megabyte merged
// report being parsed and re-rendered for every image in the list.
//
// A finding qualifies when the scan ruled it out -- not_present or
// not_in_execute_path, the two RULED OUT statuses the report groups. A finding
// the hub already answers (f.VEX != nil) is kept but marked covered: it is not
// written into the product's own document -- this flow adds what a hub is
// missing, it does not overrule a vendor who has already spoken -- but it is
// still offered to any aggregate that lags the per-product tree, so a merged
// report can be brought up to date. Dropping it here instead is what left
// --vex-merge-into reporting "no changes" while the aggregate stayed behind.
//
// A finding with no product, no component purl, or no vulnerability id cannot be
// written as a matchable statement, so it is dropped rather than emitted as one
// that would never be found again. The dropped count is returned so the caller
// can say so instead of silently proposing fewer than the report ruled out.
func selectProposals(results []*analyze.Result, timestamp string) (proposals []ProductProposal, skipped int) {
	byProduct := map[string][]Claim{}
	seen := map[string]bool{}
	for _, res := range results {
		if res == nil {
			continue
		}
		for _, f := range res.Findings {
			if !ruledOut(f) {
				continue
			}
			c, ok := claimFor(f, timestamp)
			if !ok {
				skipped++
				continue
			}
			// The hub has already spoken to this finding when --vexhub matched
			// it. Kept, not dropped, so an aggregate can still be caught up.
			c.covered = f.VEX != nil
			// Dedupe within a single run: two binaries can rule out the same CVE
			// in the same product, and so can two scans of the same image. The
			// document should carry it once.
			dk := dedupeKey(c.Product, c.Vuln, c.Subcomponent)
			if seen[dk] {
				continue
			}
			seen[dk] = true
			byProduct[f.Product] = append(byProduct[f.Product], c)
		}
	}

	for product, claims := range byProduct {
		sort.Slice(claims, func(i, j int) bool {
			if a, b := claims[i].Vuln, claims[j].Vuln; a != b {
				return a < b
			}
			return claims[i].Subcomponent < claims[j].Subcomponent
		})
		proposals = append(proposals, ProductProposal{Product: product, Claims: claims})
	}
	sort.Slice(proposals, func(i, j int) bool { return proposals[i].Product < proposals[j].Product })
	return proposals, skipped
}

// ruledOut reports whether a finding is one the scan ruled out -- the same two
// statuses report.go groups under RULED OUT.
func ruledOut(f analyze.Finding) bool {
	return f.Status == analyze.StatusNotPresent || f.Status == analyze.StatusNotInPath
}

// claimFor builds the claim a ruled-out finding becomes, or reports ok=false
// when the finding lacks what a matchable statement needs.
func claimFor(f analyze.Finding, timestamp string) (Claim, bool) {
	if f.Product == "" || f.PURL == "" {
		return Claim{}, false
	}
	name, aliases := vulnIDs(f)
	if name == "" {
		return Claim{}, false
	}
	return Claim{
		Vuln:          name,
		Aliases:       aliases,
		Product:       f.Product,
		Subcomponent:  f.PURL,
		Status:        StatusNotAffected,
		Justification: justification(f),
		Impact:        impact(f),
		Timestamp:     timestamp,
	}, true
}

// vulnIDs is the id a statement is filed under and the aliases it is also known
// by. A CVE is preferred as the name because it is the id every consumer keys
// on; the finding's other ids follow as aliases so a lookup on any of them
// still lands.
func vulnIDs(f analyze.Finding) (name string, aliases []string) {
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !containsStr(ids, id) {
			ids = append(ids, id)
		}
	}
	add(f.CVE)
	add(f.ID)
	add(f.GoID)
	for _, u := range f.Upstream {
		add(u)
	}
	if len(ids) == 0 {
		return "", nil
	}
	// Prefer a bare CVE for the name, keeping the rest as aliases.
	name = ids[0]
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			name = id
			break
		}
	}
	for _, id := range ids {
		if id != name {
			aliases = append(aliases, id)
		}
	}
	return name, aliases
}

// justification is the justification label for a ruled-out finding.
//
// Every plugin already records a valid OpenVEX justification on the findings it
// rules out (component_not_present, vulnerable_code_not_present,
// vulnerable_code_not_in_execute_path), so the finding's own field is used as
// written -- and CSAF's flag labels are the same five strings, so the value
// needs no translation on the way to either format. The status-derived fallback
// only fires for a finding that somehow carries none, and picks the weakest
// defensible label for its verdict.
func justification(f analyze.Finding) string {
	if f.Justification != "" {
		return f.Justification
	}
	switch f.Status {
	case analyze.StatusNotInPath:
		return "vulnerable_code_not_in_execute_path"
	default:
		return "vulnerable_code_not_present"
	}
}

// impact is the human sentence that explains, to whoever reviews the PR, how
// vexscan reached the verdict for this finding.
func impact(f analyze.Finding) string {
	var b strings.Builder
	b.WriteString("Ruled out by vexscan")
	if f.Method != "" {
		fmt.Fprintf(&b, " (%s)", f.Method)
	}
	for _, e := range f.Evidence {
		if e.Detail != "" {
			fmt.Fprintf(&b, ": %s", e.Detail)
			break
		}
	}
	return b.String()
}

func dedupeKey(product, vuln, sub string) string {
	return product + "\x00" + strings.ToLower(vuln) + "\x00" + sub
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
