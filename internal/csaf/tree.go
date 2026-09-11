package csaf

import "strings"

// maxRelationshipDepth bounds how far Resolve will chase a relationship whose
// container is itself a relationship.
//
// Nesting is legal and shallow in practice -- a package inside an image inside
// a bundle is already unusual -- but a document is free to point two
// relationships at each other, and the cost of a cycle here is a scan that
// never finishes rather than a wrong answer. The bound makes that impossible
// without threading a visited set through every lookup.
const maxRelationshipDepth = 8

// Ref is what one product id turns out to name.
//
// Product is the artifact a statement is filed against. Subcomponent is the
// dependency inside it the statement is scoped to, and is nil for an id naming
// the artifact as a whole -- which is the stronger claim, and the same
// distinction OpenVEX draws between a product with subcomponents and one
// without.
type Ref struct {
	Product      FullProduct
	Subcomponent *FullProduct
}

// Index is a resolved product tree: every product id the document defines, and
// what each one stands for.
type Index struct {
	products map[string]FullProduct
	rels     map[string]relPair
	// order is every product id in definition order, so a caller that walks the
	// index produces the same output on every run.
	order []string
}

// relPair is the two ids a relationship joins.
type relPair struct{ component, container string }

// Resolve walks a document's product tree and indexes it.
//
// Definitions are collected from all three places CSAF allows them --
// full_product_names, the leaves of branches, and each relationship's own
// full_product_name -- because real documents use all three, and a reader that
// handles only one sees a product_status full of ids it cannot explain. SUSE
// nests everything in branches; a hand-written VEX tends to use
// full_product_names; relationships are the only way to express a component
// inside an artifact, which is the claim vexscan matches on.
func (d *Document) Resolve() *Index {
	idx := &Index{
		products: map[string]FullProduct{},
		rels:     map[string]relPair{},
	}
	for _, p := range d.ProductTree.FullProductNames {
		idx.define(p)
	}
	idx.walk(d.ProductTree.Branches)
	for _, r := range d.ProductTree.Relationships {
		id := r.FullProductName.ProductID
		if id == "" || r.ProductReference == "" || r.RelatesToProductReference == "" {
			continue
		}
		idx.define(r.FullProductName)
		idx.rels[id] = relPair{component: r.ProductReference, container: r.RelatesToProductReference}
	}
	return idx
}

// define records one product id, keeping the first definition when a document
// gives two.
//
// CSAF requires product ids to be unique, so a document that repeats one is
// malformed. Honouring the first is the reading that does not let a later entry
// quietly redefine what an earlier statement referred to.
func (idx *Index) define(p FullProduct) {
	if p.ProductID == "" {
		return
	}
	if _, seen := idx.products[p.ProductID]; seen {
		return
	}
	idx.products[p.ProductID] = p
	idx.order = append(idx.order, p.ProductID)
}

// walk collects every product defined in a branch subtree.
func (idx *Index) walk(branches []Branch) {
	for _, b := range branches {
		if b.Product != nil {
			idx.define(*b.Product)
		}
		if len(b.Branches) > 0 {
			idx.walk(b.Branches)
		}
	}
}

// Lookup returns the definition of one product id.
func (idx *Index) Lookup(productID string) (FullProduct, bool) {
	p, ok := idx.products[productID]
	return p, ok
}

// IDs is every product id the tree defines, in definition order.
func (idx *Index) IDs() []string { return idx.order }

// Resolve turns a product id into the artifact it names and, when the id names
// a composition, the component inside it.
//
// A relationship's container may itself be a relationship id -- a package
// inside an image inside a bundle -- so the container is followed down to the
// artifact at the bottom while the component stays the immediate one. An id the
// tree never defined is ok=false: a product_status may only reference ids the
// tree declares, and inventing a meaning for one it does not would be guessing
// at what the document meant to say.
func (idx *Index) Resolve(productID string) (Ref, bool) {
	rel, isRel := idx.rels[productID]
	if !isRel {
		p, ok := idx.products[productID]
		if !ok {
			return Ref{}, false
		}
		return Ref{Product: p}, true
	}

	component, ok := idx.products[rel.component]
	if !ok {
		return Ref{}, false
	}
	container := rel.container
	for depth := 0; ; depth++ {
		if depth >= maxRelationshipDepth {
			return Ref{}, false
		}
		next, nested := idx.rels[container]
		if !nested {
			break
		}
		container = next.container
	}
	artifact, ok := idx.products[container]
	if !ok {
		return Ref{}, false
	}
	return Ref{Product: artifact, Subcomponent: &component}, true
}

// CPEs maps each CPE the tree carries to the product ids that declare it.
//
// It exists for a feed that joins on CPE rather than on purl: SUSE keys its
// products by the operating system CPE an image reports in its os-release, and
// a purl never enters that match at all.
func (idx *Index) CPEs() map[string][]string {
	out := map[string][]string{}
	for _, id := range idx.order {
		if cpe := idx.products[id].CPE(); cpe != "" {
			out[cpe] = append(out[cpe], id)
		}
	}
	return out
}

// FindByPURL returns the product id declaring this purl.
//
// The comparison is exact, unlike the one that matches a finding against a
// statement. This is used by a writer to find an id the document already
// allocated, where two spellings of one purl must stay two ids rather than
// collapse; the deliberately loose comparison lives in internal/vex, where the
// tolerance it applies can be recorded on the finding.
func (idx *Index) FindByPURL(purl string) (string, bool) {
	if purl = strings.TrimSpace(purl); purl == "" {
		return "", false
	}
	for _, id := range idx.order {
		if idx.products[id].PURL() == purl {
			return id, true
		}
	}
	return "", false
}

// FindRelationship returns the product id the tree already allocated for a
// component inside a container, so a writer adding a statement reuses the pair
// the document defined rather than declaring a second id for it.
func (idx *Index) FindRelationship(component, container string) (string, bool) {
	for _, id := range idx.order {
		if rel, ok := idx.rels[id]; ok && rel.component == component && rel.container == container {
			return id, true
		}
	}
	return "", false
}
