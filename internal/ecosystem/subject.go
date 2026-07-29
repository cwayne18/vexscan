package ecosystem

import (
	"fmt"
	"sort"
	"strings"
)

// formatAliases map the package-format names people actually type onto the
// plugin that handles them.
//
// "deb" and "apk" are not OSV ecosystems -- OSV names distributions, not
// formats -- so `--package deb:openssl` cannot be matched by MatchEcosystem.
// It is still the obvious thing to type, and the OS plugin is the only thing
// that could answer it, so it is normalized here rather than rejected.
var formatAliases = map[string]string{
	"apk":  "os",
	"deb":  "os",
	"dpkg": "os",
	"rpm":  "os",
	"go":   "golang",
}

// ParseSubject turns one --package value into a Subject.
//
// Three spellings are accepted, in the order they are tried:
//
//	pkg:golang/golang.org%2Fx%2Fnet@v0.17.0   a package URL
//	deb:openssl, golang:golang.org/x/net      ecosystem:name shorthand
//	openssl                                   a bare name, resolved by inventory
//
// A bare name is deliberately not tied to an ecosystem: it is answered by
// whichever plugin's inventory turns out to contain it, which is what makes
// `--package openssl` work without the user knowing whether the image is
// Debian or Alpine.
func ParseSubject(raw string) (Subject, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Subject{}, fmt.Errorf("empty package selector")
	}
	if strings.HasPrefix(s, "pkg:") {
		return Subject{PURL: s, Raw: raw}, nil
	}

	// Only a prefix with no slash in it is an ecosystem: a bare module path
	// never contains a colon, but a name that does -- a Windows-style path, a
	// URL -- would have its slashes before the colon.
	i := strings.Index(s, ":")
	if i <= 0 || strings.ContainsAny(s[:i], "/@") {
		return Subject{Name: s, Raw: raw}, nil
	}

	eco, name := s[:i], strings.TrimSpace(s[i+1:])
	if name == "" {
		return Subject{}, fmt.Errorf("%q names an ecosystem but no package", raw)
	}
	if alias, ok := formatAliases[strings.ToLower(eco)]; ok {
		eco = alias
	}
	return Subject{Ecosystem: eco, Name: name, Raw: raw}, nil
}

// Subjects parses every --package value and checks each one against plugins,
// so that a selector nothing can answer is reported rather than scanned past.
//
// The check matters more than it looks. A subject aimed at an ecosystem no
// selected plugin handles -- a typo, or `--package golang:x --ecosystem os` --
// produces an empty inventory, and an empty inventory renders as a clean
// report. That is the one result this tool must never manufacture from a
// mistake in the command line.
func Subjects(plugins []Plugin, raws []string) ([]Subject, error) {
	var out []Subject
	for _, raw := range raws {
		s, err := ParseSubject(raw)
		if err != nil {
			return nil, err
		}
		if s.Ecosystem != "" && !anyMatches(plugins, s.Ecosystem) {
			return nil, fmt.Errorf("%q names ecosystem %q, which no selected plugin handles (selected: %s)",
				s.Raw, s.Ecosystem, strings.Join(pluginIDs(plugins), ", "))
		}
		out = append(out, s)
	}
	return out, nil
}

func anyMatches(plugins []Plugin, selector string) bool {
	for _, p := range plugins {
		if MatchEcosystem(p, selector) {
			return true
		}
	}
	return false
}

func pluginIDs(plugins []Plugin) []string {
	ids := make([]string, 0, len(plugins))
	for _, p := range plugins {
		ids = append(ids, p.ID())
	}
	sort.Strings(ids)
	return ids
}
