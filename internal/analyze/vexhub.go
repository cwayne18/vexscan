package analyze

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/vex"
)

// productOverlay fills in the artifact each finding was found in, for every
// plugin that did not already know a narrower one.
//
// It runs in the orchestrator for the same reason stamp and severityOverlay do:
// the image is a fact about the scan, not about any plugin, and a plugin that
// forgot to record it would silently lose every vendor statement about its
// findings. The Go plugin overrides this with the binary's own main module,
// which is the artifact a hub actually files Go statements under.
func productOverlay(findings []Finding, imageRef string) {
	product := vex.ImageProduct(imageRef)
	if product == "" {
		return
	}
	for i := range findings {
		if findings[i].Product == "" {
			findings[i].Product = product
		}
	}
}

// vexOverlay annotates findings with published vendor statements, in place.
//
// It never touches Status. A finding's verdict is what local evidence
// concluded, and it stays that whether or not a hub was consulted, so a scan
// with --vexhub and one without agree on every status and differ only in how
// the report groups them. What a statement changes is the reader's attention:
// see report.go, where an exculpatory one lifts a row out of AFFECTED.
//
// A hub that cannot be read is recorded and warned about, but does not fail the
// run -- deliberately, and unlike an ecosystem that could not be inventoried.
// An unreadable package database makes the report claim a clean image it never
// examined; an unreachable hub only leaves rows in AFFECTED that a vendor had
// already answered. The first under-reports, which is the way this tool must
// never be wrong. The second over-reports, which is merely tiring. It is still
// warned about, because a hub that silently contributed nothing looks exactly
// like a hub with nothing to say.
func vexOverlay(ctx context.Context, hubURLs []string, findings []Finding, aliases map[string][]string, logf func(string, ...any)) []ecosystem.VEXHubResult {
	if len(hubURLs) == 0 {
		return nil
	}
	products := distinctProducts(findings)

	out := make([]ecosystem.VEXHubResult, 0, len(hubURLs))
	for _, u := range hubURLs {
		res := ecosystem.VEXHubResult{URL: u}
		hub, err := vex.Open(ctx, u)
		if err != nil {
			res.Error = err.Error()
			logf("  ! VEX hub %s could not be read: %v", u, err)
			logf("    (findings a vendor has already answered will still be reported as affected)")
			out = append(out, res)
			continue
		}
		res.Products = hub.Size()
		logf("VEX hub %s: %d products indexed", u, hub.Size())

		for _, product := range products {
			doc, ok, err := hub.Lookup(ctx, product)
			if err != nil {
				// One unreadable document is not the hub failing: every other
				// product it covers is still usable.
				logf("  ! VEX hub %s: %v", u, err)
				continue
			}
			if !ok {
				continue
			}
			if res.Author == "" {
				res.Author = doc.Author
			}
			res.Matched += annotate(findings, doc, product, u, aliases)
		}
		if res.Matched > 0 {
			logf("VEX hub %s: %d finding(s) already covered by a published statement", u, res.Matched)
		}
		out = append(out, res)
	}
	return out
}

// annotate attaches this document's statements to every finding under one
// product, and reports how many it spoke to.
//
// A finding already annotated is left alone, so the first --vexhub named is the
// authoritative one -- an internal hub can be listed ahead of a vendor's to
// override it without editing anything.
func annotate(findings []Finding, doc *vex.Doc, product, hubURL string, aliases map[string][]string) int {
	var n int
	for i := range findings {
		f := &findings[i]
		if f.VEX != nil || f.Product != product {
			continue
		}
		st, note := vex.Match(doc, product, findingIDs(*f, aliases), f.PURL)
		if st == nil {
			continue
		}
		f.VEX = &ecosystem.VEXStatement{
			Status:          st.Status,
			Justification:   st.Justification,
			ImpactStatement: st.ImpactStatement,
			ActionStatement: st.ActionStatement,
			Author:          doc.Author,
			Timestamp:       st.Timestamp,
			Product:         product,
			Hub:             hubURL,
			Match:           note,
		}
		f.Evidence = append(f.Evidence, ecosystem.Evidence{
			Origin: "vendor-vex",
			Detail: vexDetail(f.VEX),
			// Never blocking. A vendor claim is a second opinion, not a taint:
			// it cannot stop the local analysis from reaching its own verdict,
			// in either direction.
		})
		n++
	}
	return n
}

// vexDetail is the one-line summary of a statement recorded as evidence.
func vexDetail(v *ecosystem.VEXStatement) string {
	var b strings.Builder
	author := v.Author
	if author == "" {
		author = v.Hub
	}
	fmt.Fprintf(&b, "%s published %s for %s", author, v.Status, v.Product)
	if v.Justification != "" {
		fmt.Fprintf(&b, " (%s)", v.Justification)
	}
	if v.Match != "" {
		// The match was deliberately loose about how the component is spelled,
		// so the disagreement it tolerated belongs in the record.
		fmt.Fprintf(&b, "; %s", v.Match)
	}
	return b.String()
}

// findingIDs is every name this finding's advisory goes by, since a hub files
// under whichever one its own source used.
//
// The finding's own three id fields are rarely enough. A Go finding is reported
// as GO-2025-3547 and every hub seen so far files under CVE-2024-7598, with no
// GO id on the statement to bridge them -- so the OSV record's alias list,
// which the resolver already fetched to attach severities, is what actually
// makes the two sides meet.
func findingIDs(f Finding, aliases map[string][]string) []string {
	ids := make([]string, 0, 4)
	add := func(id string) {
		if id != "" && !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for _, id := range []string{f.ID, f.CVE, f.GoID} {
		add(id)
		for _, alias := range aliases[id] {
			add(alias)
		}
	}
	return ids
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// distinctProducts is the artifacts to look up, sorted so a repeated scan makes
// the same requests in the same order.
//
// One lookup per product, not per finding: an image with three hundred OS
// findings is one document, and a hub should not be asked three hundred times
// for it.
func distinctProducts(findings []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if f.Product == "" || seen[f.Product] {
			continue
		}
		seen[f.Product] = true
		out = append(out, f.Product)
	}
	sort.Strings(out)
	return out
}
