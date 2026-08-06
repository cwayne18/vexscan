package vexpr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// ProductProposal is every statement proposed for one product's document.
type ProductProposal struct {
	// Product is the artifact purl the statements are filed under.
	Product string
	// Statements are the not_affected claims, one per ruled-out finding, sorted
	// so a repeated run produces a byte-identical document.
	Statements []Statement
}

// selectProposals turns the ruled-out findings in a result into per-product
// proposals.
//
// A finding qualifies when the scan ruled it out -- not_present or
// not_in_execute_path, the two RULED OUT statuses the report groups -- and the
// hub does not already answer it. A finding the hub already carries a statement
// for (f.VEX != nil) is left alone whatever that statement says: this flow adds
// what a hub is missing, it does not overrule a vendor who has already spoken.
//
// A finding with no product, no component purl, or no vulnerability id cannot be
// written as a matchable statement, so it is dropped rather than emitted as one
// that would never be found again. The dropped count is returned so the caller
// can say so instead of silently proposing fewer than the report ruled out.
func selectProposals(res *analyze.Result, timestamp string) (proposals []ProductProposal, skipped int) {
	byProduct := map[string][]Statement{}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		if !ruledOut(f) {
			continue
		}
		if f.VEX != nil {
			// The hub has already spoken to this finding; --vexhub matched it.
			continue
		}
		st, ok := statementFor(f, timestamp)
		if !ok {
			skipped++
			continue
		}
		// Dedupe within a single scan: two binaries can rule out the same CVE in
		// the same product, and the document should carry it once.
		dk := dedupeKey(f.Product, st.Vulnerability.Name, subcomponentID(st))
		if seen[dk] {
			continue
		}
		seen[dk] = true
		byProduct[f.Product] = append(byProduct[f.Product], st)
	}

	for product, sts := range byProduct {
		sort.Slice(sts, func(i, j int) bool {
			if a, b := sts[i].Vulnerability.Name, sts[j].Vulnerability.Name; a != b {
				return a < b
			}
			return subcomponentID(sts[i]) < subcomponentID(sts[j])
		})
		proposals = append(proposals, ProductProposal{Product: product, Statements: sts})
	}
	sort.Slice(proposals, func(i, j int) bool { return proposals[i].Product < proposals[j].Product })
	return proposals, skipped
}

// ruledOut reports whether a finding is one the scan ruled out -- the same two
// statuses report.go groups under RULED OUT.
func ruledOut(f analyze.Finding) bool {
	return f.Status == analyze.StatusNotPresent || f.Status == analyze.StatusNotInPath
}

// statementFor builds the OpenVEX statement a ruled-out finding becomes, or
// reports ok=false when the finding lacks what a matchable statement needs.
func statementFor(f analyze.Finding, timestamp string) (Statement, bool) {
	if f.Product == "" || f.PURL == "" {
		return Statement{}, false
	}
	name, aliases := vulnIDs(f)
	if name == "" {
		return Statement{}, false
	}
	st := Statement{
		Vulnerability: Vulnerability{Name: name, Aliases: aliases},
		Products: []Product{{
			ID:            f.Product,
			Subcomponents: []Subcomponent{{ID: f.PURL}},
		}},
		Status:          StatusNotAffected,
		Justification:   justification(f),
		ImpactStatement: impact(f),
		Timestamp:       timestamp,
	}
	return st, true
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

// justification is the OpenVEX justification for a ruled-out finding.
//
// Every plugin already records a valid OpenVEX justification on the findings it
// rules out (component_not_present, vulnerable_code_not_present,
// vulnerable_code_not_in_execute_path), so the finding's own field is used as
// written. The status-derived fallback only fires for a finding that somehow
// carries none, and picks the weakest defensible label for its verdict.
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

func subcomponentID(s Statement) string {
	if len(s.Products) == 0 || len(s.Products[0].Subcomponents) == 0 {
		return ""
	}
	return s.Products[0].Subcomponents[0].ID
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
