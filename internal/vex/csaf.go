package vex

import (
	"fmt"

	"github.com/cwayne18/vexscan/internal/csaf"
)

// parseCSAF flattens a CSAF-VEX document into the same Doc the OpenVEX reader
// produces, so everything past the parse -- Match, the overlay in
// internal/analyze, the report -- stays unaware of which format the hub
// published.
//
// The flattening is where the formats' one real difference gets paid for.
// OpenVEX writes the purl in place; CSAF names an opaque product id and defines
// it in the product tree, so every id in a product_status must be resolved
// before it means anything. An id the tree never defined, or one whose product
// carries no purl, is dropped rather than carried as a statement about a
// product nothing can be matched against -- the same reason the OpenVEX reader
// drops a statement naming no product.
//
// Neither status nor justification is translated, because neither needs to be:
// the two formats spell all four statuses and all five justification labels
// identically.
func parseCSAF(b []byte) (*Doc, error) {
	cd, err := csaf.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("vex: %w", err)
	}
	idx := cd.Resolve()

	doc := &Doc{
		Author:    cd.Document.Publisher.Name,
		Timestamp: cd.Document.Tracking.CurrentReleaseDate,
	}
	if doc.Author == "" {
		// A document with no publisher name still came from somewhere, and the
		// tracking id is the only other thing identifying it. Better in the
		// --details attribution line than a blank, which reads as a bug.
		doc.Author = cd.Document.Tracking.ID
	}

	for _, v := range cd.Vulnerabilities {
		names := v.Names()
		if len(names) == 0 {
			continue
		}
		timestamp := v.ReleaseDate
		if timestamp == "" {
			timestamp = doc.Timestamp
		}
		for _, list := range v.ProductStatus.Statuses() {
			doc.Statements = append(doc.Statements, csafStatements(idx, v, list, names, timestamp)...)
		}
	}
	return doc, nil
}

// csafReason is the prose explaining one product's verdict. It is the grouping
// key below, because in CSAF these live on flags and threats scoped to a set of
// product ids rather than on the verdict itself.
type csafReason struct{ justification, impact, action string }

// csafStatements turns one product_status list into statements.
//
// Products are grouped by the reason given for them rather than emitted one
// statement per product. A real document routinely gives one justification for
// two hundred products -- SUSE's do -- and one statement per product would turn
// that into two hundred near-identical entries for Match to walk. Grouping
// keeps the document small while preserving exactly which reason applies to
// which product, which a single flattened statement would lose.
func csafStatements(idx *csaf.Index, v csaf.Vulnerability, list csaf.StatusList, names []string, timestamp string) []Statement {
	var order []csafReason
	byReason := map[csafReason][]Product{}

	for _, pid := range list.ProductIDs {
		ref, ok := idx.Resolve(pid)
		if !ok {
			continue
		}
		purl := ref.Product.PURL()
		if purl == "" {
			// Nothing here to match a finding against. A CSAF product
			// identified only by a CPE is not a defect -- it is how an
			// OS-level advisory is written, and internal/distrofeed reads
			// exactly those -- but a hub lookup joins on purls, so for this
			// reader there is no product.
			continue
		}
		r := csafReason{
			justification: v.FlagFor(pid),
			impact:        v.ImpactFor(pid),
			action:        v.ActionFor(pid),
		}
		if _, seen := byReason[r]; !seen {
			order = append(order, r)
		}
		prod := Product{ID: purl}
		if ref.Subcomponent != nil {
			if sub := ref.Subcomponent.PURL(); sub != "" {
				prod.Subcomponents = []string{sub}
			}
		}
		byReason[r] = append(byReason[r], prod)
	}

	out := make([]Statement, 0, len(order))
	for _, r := range order {
		out = append(out, Statement{
			Vulnerability:   names[0],
			Aliases:         names[1:],
			Products:        byReason[r],
			Status:          list.Status,
			Justification:   r.justification,
			ImpactStatement: r.impact,
			ActionStatement: r.action,
			Timestamp:       timestamp,
		})
	}
	return out
}
