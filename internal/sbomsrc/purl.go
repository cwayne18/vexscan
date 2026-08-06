package sbomsrc

import (
	"fmt"
	"net/url"
	"strings"
)

// Package URLs are the only field in an SBOM that every producer fills in the
// same way, which is why almost everything here is derived from one and almost
// nothing from the rest of the entry. A component's "name" and "version" are
// whatever the producer felt like writing; its purl has a specification.
//
// "The same way" still has limits, and the two producers measured disagree
// inside the qualifiers -- see distro().

// purl is a parsed package URL: scheme, type, namespace, name, version and
// qualifiers. The subpath is parsed off and discarded, because nothing here
// scans a path inside a package.
type purl struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

// String rebuilds enough of the purl to identify the component in a message.
// Not a canonical re-encoding -- the original is kept for that.
func (p purl) String() string {
	s := "pkg:" + p.Type + "/"
	if p.Namespace != "" {
		s += p.Namespace + "/"
	}
	s += p.Name
	if p.Version != "" {
		s += "@" + p.Version
	}
	return s
}

// parsePURL parses a package URL.
//
// Structural only: the type-specific casing and separator rules (npm lowercases,
// PyPI collapses punctuation, Maven joins with a colon) are applied where the
// component is built, so this stays a parser and the naming rules stay next to
// the ecosystem that owns them.
func parsePURL(s string) (purl, error) {
	rest := strings.TrimSpace(s)
	if len(rest) < 4 || !strings.EqualFold(rest[:4], "pkg:") {
		return purl{}, fmt.Errorf("not a package URL")
	}
	// Some producers write the authority form "pkg://type/...". The
	// specification says to ignore the slashes rather than reject the string.
	rest = strings.TrimLeft(rest[4:], "/")

	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i] // subpath
	}
	var quals map[string]string
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		quals = parseQualifiers(rest[i+1:])
		rest = rest[:i]
	}

	// The version is taken from the last '@', but only when it comes after the
	// last '/'. An unencoded npm scope puts an '@' at the front -- and
	// "pkg:npm/@babel/core" has no version at all, so splitting on the '@'
	// blindly would name the package "npm" at version "babel/core".
	var version string
	if at := strings.LastIndexByte(rest, '@'); at > strings.LastIndexByte(rest, '/') {
		version, rest = rest[at+1:], rest[:at]
	}

	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return purl{}, fmt.Errorf("no package name")
	}
	p := purl{
		Type:       strings.ToLower(unescape(parts[0])),
		Name:       unescape(parts[len(parts)-1]),
		Version:    unescape(version),
		Qualifiers: quals,
	}
	if mid := parts[1 : len(parts)-1]; len(mid) > 0 {
		segs := make([]string, 0, len(mid))
		for _, seg := range mid {
			if seg != "" {
				segs = append(segs, unescape(seg))
			}
		}
		p.Namespace = strings.Join(segs, "/")
	}
	if p.Type == "" {
		return purl{}, fmt.Errorf("no package type")
	}
	if p.Name == "" {
		return purl{}, fmt.Errorf("no package name")
	}
	return p, nil
}

// parseQualifiers reads the "k=v&k=v" tail. Keys are lowercased per the
// specification; an empty value is dropped, which is what the specification
// says a qualifier with no value means.
func parseQualifiers(s string) map[string]string {
	q := map[string]string{}
	for _, kv := range strings.Split(s, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" {
			continue
		}
		q[strings.ToLower(strings.TrimSpace(k))] = unescape(v)
	}
	if len(q) == 0 {
		return nil
	}
	return q
}

// unescape percent-decodes one purl segment, or returns it unchanged.
//
// url.PathUnescape rather than QueryUnescape: a '+' in a version string is a
// plus sign -- Debian writes "12.4+deb12u15" -- and QueryUnescape would turn it
// into a space and silently produce a version that matches no advisory range.
//
// A segment that will not decode is kept verbatim. It is already the case that
// the name may be wrong; dropping it as well would turn a mangled component
// into an absent one.
func unescape(s string) string {
	out, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return out
}
