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
		return path.Join("pkg", "golang", name) + "/" + docFileName, nil
	case "oci":
		repo := repositoryURL(body)
		if repo == "" {
			return "", fmt.Errorf("vexpr: %q: no repository_url qualifier", purl)
		}
		return path.Join("pkg", "oci", repo) + "/" + docFileName, nil
	default:
		return "", fmt.Errorf("vexpr: %q: unsupported product type %q", purl, typ)
	}
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
