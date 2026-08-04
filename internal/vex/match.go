package vex

import (
	"fmt"
	"net/url"
	"strings"
)

// Match finds the statement in d that speaks to a finding: one naming any of
// ids as its vulnerability, under the given product, covering subPURL.
//
// It returns the statement and a note describing every spelling disagreement it
// had to tolerate to get there, or (nil, "") if nothing matched. The note is
// not an aside -- it is the audit trail for a deliberately loose comparison,
// and belongs in the evidence the caller records.
func Match(d *Doc, product string, ids []string, subPURL string) (*Statement, string) {
	if d == nil {
		return nil, ""
	}
	want := canonicalProduct(product)

	var best *Statement
	var bestNote string
	var bestScoped bool
	for i := range d.Statements {
		s := &d.Statements[i]
		if !s.namesVulnerability(ids) {
			continue
		}
		for _, p := range s.Products {
			if canonicalProduct(p.ID) != want {
				continue
			}
			scoped, note, ok := covers(p, subPURL)
			if !ok {
				continue
			}
			if best == nil || better(scoped, s, bestScoped, best) {
				best, bestNote, bestScoped = s, note, scoped
			}
		}
	}
	return best, bestNote
}

// covers reports whether a product entry speaks to this subcomponent, and
// whether it does so by naming it (scoped) or by covering the whole product.
func covers(p Product, subPURL string) (scoped bool, note string, ok bool) {
	// A product entry with no subcomponents is a claim about the artifact as a
	// whole, so it covers anything found inside it.
	if len(p.Subcomponents) == 0 {
		return false, "", true
	}
	have, haveOK := parseKey(subPURL)
	if !haveOK {
		return false, "", false
	}
	for _, sc := range p.Subcomponents {
		want, wantOK := parseKey(sc)
		if !wantOK || want != have {
			continue
		}
		return true, disagreement(sc, subPURL), true
	}
	return false, "", false
}

// better reports whether a newly matched statement should displace the one
// already held, so the result does not depend on the order statements happen to
// appear in the document.
//
// A subcomponent-scoped statement beats a product-wide one: the vendor took the
// trouble to name this dependency. Between two of equal specificity the newer
// timestamp wins, since a hub amends by publishing again.
func better(scoped bool, s *Statement, bestScoped bool, best *Statement) bool {
	if scoped != bestScoped {
		return scoped
	}
	return s.Timestamp > best.Timestamp
}

// key is a purl reduced to what two spellings of the same package must agree
// on.
type key struct{ typ, name string }

// parseKey reduces a purl to its type and name, dropping the version and
// qualifiers, and dropping the namespace only where the namespace is a
// distribution.
//
// The loose comparison is not a shortcut, it is the only rule that fires
// against real data. A hub writes pkg:rpm/suse/libgcrypt20 -- no version, and
// namespaced by vendor. vexscan writes pkg:rpm/sles/libgcrypt20@1.9.4?arch=x86_64
// for the same package, because the namespace comes from the image's os-release
// ID. Comparing full purls would never match anything.
//
// Which part is "the namespace" is the same judgement Finding.Component makes:
// for deb/rpm/apk it is the distro and carries nothing, but for golang the
// leading path is most of the module name and for npm it is the scope. Dropping
// it there would reduce pkg:golang/github.com/nwaples/rardecode/v2 to "v2" and
// match half the ecosystem.
func parseKey(purl string) (key, bool) {
	body, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return key{}, false
	}
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	typ, rest, found := strings.Cut(body, "/")
	if !found {
		return key{}, false
	}
	typ = strings.ToLower(typ)
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	if osPURLTypes[typ] {
		if i := strings.LastIndex(rest, "/"); i >= 0 {
			rest = rest[i+1:]
		}
	}
	if dec, err := url.PathUnescape(rest); err == nil {
		rest = dec
	}
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return key{}, false
	}
	return key{typ: typ, name: rest}, true
}

// osPURLTypes are the purl types whose namespace is a distribution rather than
// part of the package's name. Kept here rather than imported so this package
// stays a self-contained reader of the format.
var osPURLTypes = map[string]bool{"deb": true, "rpm": true, "apk": true}

// disagreement describes how far apart two purls for the same package are, or
// returns "" when they agree exactly.
func disagreement(statement, finding string) string {
	if statement == finding {
		return ""
	}
	return fmt.Sprintf("statement names %s; component is %s", statement, finding)
}
