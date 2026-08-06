package vexpr

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// docFileName is the file every product's document is stored under, per the VEX
// Repository layout internal/vex documents.
const docFileName = "scan.openvex.json"

// productLocation is the path inside the hub a product's document lives at,
// relative to the repository root.
//
//	pkg:golang/github.com/Altinity/clickhouse-backup/v2
//	  -> pkg/golang/github.com/Altinity/clickhouse-backup/v2/scan.openvex.json
//	pkg:oci/hardened-kubernetes?repository_url=index.docker.io/rancher/hardened-kubernetes
//	  -> pkg/oci/index.docker.io/rancher/hardened-kubernetes/scan.openvex.json
//
// The two product types vexscan ever produces are golang (a Go main module, via
// vex.GoProduct) and oci (a scanned image, via vex.ImageProduct); anything else
// is a caller error rather than a case to guess a path for. The oci path is the
// repository_url qualifier, decoded, not the bare purl name -- that is how the
// hub's own index writes it.
func productLocation(purl string) (string, error) {
	typ, body, ok := splitPurl(purl)
	if !ok {
		return "", fmt.Errorf("vexpr: %q: not a package URL", purl)
	}
	switch typ {
	case "golang":
		name, _ := splitQualifiers(body)
		name = strings.Trim(name, "/")
		if name == "" {
			return "", fmt.Errorf("vexpr: %q: no module path", purl)
		}
		return hubPath("golang", name, purl)
	case "oci":
		repo := repositoryURL(body)
		if repo == "" {
			return "", fmt.Errorf("vexpr: %q: no repository_url qualifier", purl)
		}
		return hubPath("oci", repo, purl)
	default:
		return "", fmt.Errorf("vexpr: %q: unsupported product type %q", purl, typ)
	}
}

// hubRoot is the directory inside the hub every product document lives under.
const hubRoot = "pkg"

// hubPath is where a product of the given type and name is filed, refusing any
// name that would put the document somewhere else in the repository.
//
// The check is not fussiness about malformed input. A golang product's name is
// the main module path, and vexscan reads that out of the build info of a
// binary inside the image being scanned -- whoever built that image chose the
// string. An oci product's name comes from the image reference the same way.
// Both are attacker-controlled on an untrusted target, and both arrive here on
// their way to becoming a file path in somebody else's repository. path.Join
// resolves "../.." rather than objecting to it, so a name that climbs out is
// refused before the join instead of silently cleaned into an escape.
func hubPath(typ, name, purl string) (string, error) {
	if err := checkProductName(name, purl); err != nil {
		return "", err
	}
	loc := path.Join(hubRoot, typ, name) + "/" + docFileName
	// Belt to checkProductName's braces. Whatever the name turned out to be,
	// the result has to land under pkg/ -- if it does not, the checks above
	// have a hole, and the consequence worth preventing is the write, not the
	// hole. A refusal here is a bug report; a file outside pkg/ is a commit in
	// someone else's repository.
	if !strings.HasPrefix(loc, hubRoot+"/") {
		return "", fmt.Errorf("vexpr: %q: resolves to %q, outside %s/", purl, loc, hubRoot)
	}
	return loc, nil
}

// checkProductName rejects a product name that cannot become a path inside the
// hub: one that climbs out of it, that is absolute, that has an empty segment,
// or that carries a character no module path or registry name has.
func checkProductName(name, purl string) error {
	if name == "" {
		return fmt.Errorf("vexpr: %q: no product name to file under", purl)
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("vexpr: %q: absolute product name %q", purl, name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return fmt.Errorf("vexpr: %q: product name contains %q", purl, r)
		}
	}
	// "." and ".." are rejected outright rather than resolved, even where they
	// would resolve to somewhere harmless inside pkg/: two spellings of one
	// product would otherwise share a document while getting two index keys.
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "":
			return fmt.Errorf("vexpr: %q: product name has an empty path segment", purl)
		case ".", "..":
			return fmt.Errorf("vexpr: %q: product name climbs out of %s/ at %q", purl, hubRoot, seg)
		}
	}
	return nil
}

// checkHubLocation vets a document path the hub's own index.json supplied.
//
// It is looser than hubPath on purpose: the index is the hub's statement about
// its own layout, and a hub is entitled to store documents somewhere other than
// pkg/. What it is not entitled to do is name a path outside the repository, so
// only traversal and absolute paths are refused.
func checkHubLocation(loc string) error {
	if loc == "" {
		return fmt.Errorf("vexpr: index.json has an empty location")
	}
	if strings.HasPrefix(loc, "/") {
		return fmt.Errorf("vexpr: index.json location %q is absolute", loc)
	}
	for _, seg := range strings.Split(loc, "/") {
		if seg == ".." {
			return fmt.Errorf("vexpr: index.json location %q climbs out of the repository", loc)
		}
	}
	return nil
}

// indexKey is the spelling a product must have in index.json, which is not
// always the spelling vexscan holds it as.
//
// A golang product is written verbatim. An oci product has the slashes in its
// repository_url qualifier percent-encoded, exactly as vex.canonicalProduct
// expects to have to decode them back: the index writes
// repository_url=index.docker.io%2Francher%2Fhardened-kubernetes while the @id
// inside the document it points at is left plain.
func indexKey(purl string) (string, error) {
	typ, body, ok := splitPurl(purl)
	if !ok {
		return "", fmt.Errorf("vexpr: %q: not a package URL", purl)
	}
	switch typ {
	case "golang":
		return purl, nil
	case "oci":
		name, _ := splitQualifiers(body)
		repo := repositoryURL(body)
		if repo == "" {
			return "", fmt.Errorf("vexpr: %q: no repository_url qualifier", purl)
		}
		return fmt.Sprintf("pkg:oci/%s?repository_url=%s", name, url.PathEscape(repo)), nil
	default:
		return "", fmt.Errorf("vexpr: %q: unsupported product type %q", purl, typ)
	}
}

// splitPurl separates a package URL into its type and the remainder after
// "pkg:<type>/".
func splitPurl(purl string) (typ, body string, ok bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return "", "", false
	}
	typ, body, found := strings.Cut(rest, "/")
	if !found || typ == "" {
		return "", "", false
	}
	return strings.ToLower(typ), body, true
}

// splitQualifiers splits the part after the type into the name (path) and the
// raw qualifier string, dropping any #subpath.
func splitQualifiers(body string) (name, qualifiers string) {
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	name, qualifiers, _ = strings.Cut(body, "?")
	return name, qualifiers
}

// repositoryURL returns the decoded repository_url qualifier value, or "" when
// the purl carries none.
func repositoryURL(body string) string {
	_, qualifiers := splitQualifiers(body)
	for _, q := range strings.Split(qualifiers, "&") {
		k, v, found := strings.Cut(q, "=")
		if !found || !strings.EqualFold(k, "repository_url") {
			continue
		}
		if dec, err := url.PathUnescape(v); err == nil {
			v = dec
		}
		return strings.Trim(v, "/")
	}
	return ""
}
