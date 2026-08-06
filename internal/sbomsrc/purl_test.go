package sbomsrc

import "testing"

func TestParsePURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want purl
	}{
		{
			"a debian binary package",
			"pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
			purl{Type: "deb", Namespace: "debian", Name: "libssl3", Version: "3.0.11-1~deb12u2",
				Qualifiers: map[string]string{"arch": "amd64", "distro": "debian-12", "upstream": "openssl"}},
		},
		{
			// The namespace is several segments and the name is the last one.
			"a go module path",
			"pkg:golang/github.com/gorilla/mux@v1.8.0",
			purl{Type: "golang", Namespace: "github.com/gorilla", Name: "mux", Version: "v1.8.0"},
		},
		{
			"a go module with no namespace",
			"pkg:golang/stdlib@go1.21.5",
			purl{Type: "golang", Name: "stdlib", Version: "go1.21.5"},
		},
		{
			"an npm scope, encoded as the specification asks",
			"pkg:npm/%40babel/core@7.24.0",
			purl{Type: "npm", Namespace: "@babel", Name: "core", Version: "7.24.0"},
		},
		{
			// Producers write the scope unencoded too, and the '@' that opens
			// it must not be mistaken for the one that opens a version.
			"an npm scope, written verbatim",
			"pkg:npm/@babel/core@7.24.0",
			purl{Type: "npm", Namespace: "@babel", Name: "core", Version: "7.24.0"},
		},
		{
			// The failure this guards: a last-'@' split with no version present
			// names the package "npm" at version "babel/core".
			"an npm scope with no version at all",
			"pkg:npm/@babel/core",
			purl{Type: "npm", Namespace: "@babel", Name: "core"},
		},
		{
			"a maven coordinate",
			"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			purl{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3", Version: "3.12.0"},
		},
		{
			// Debian versions carry '+', which QueryUnescape would turn into a
			// space and so into a version that matches no advisory range.
			"a percent-encoded plus in a version",
			"pkg:deb/debian/base-files@12.4%2Bdeb12u15?arch=amd64",
			purl{Type: "deb", Namespace: "debian", Name: "base-files", Version: "12.4+deb12u15",
				Qualifiers: map[string]string{"arch": "amd64"}},
		},
		{
			"a subpath is parsed off",
			"pkg:golang/github.com/foo/bar@v1.0.0#internal/x",
			purl{Type: "golang", Namespace: "github.com/foo", Name: "bar", Version: "v1.0.0"},
		},
		{
			"the authority form producers sometimes write",
			"pkg://rpm/rocky/openssl-libs@3.0.7-24.el9",
			purl{Type: "rpm", Namespace: "rocky", Name: "openssl-libs", Version: "3.0.7-24.el9"},
		},
		{
			"the scheme is not case-sensitive and the type is folded",
			"PKG:PyPI/Django@4.2.1",
			purl{Type: "pypi", Name: "Django", Version: "4.2.1"},
		},
		{
			"a valueless qualifier is dropped rather than stored empty",
			"pkg:apk/alpine/musl@1.2.4-r2?arch=&distro=3.19",
			purl{Type: "apk", Namespace: "alpine", Name: "musl", Version: "1.2.4-r2",
				Qualifiers: map[string]string{"distro": "3.19"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePURL(tt.in)
			if err != nil {
				t.Fatalf("parsePURL(%q): %v", tt.in, err)
			}
			if got.Type != tt.want.Type || got.Namespace != tt.want.Namespace ||
				got.Name != tt.want.Name || got.Version != tt.want.Version {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if len(got.Qualifiers) != len(tt.want.Qualifiers) {
				t.Fatalf("qualifiers = %v, want %v", got.Qualifiers, tt.want.Qualifiers)
			}
			for k, v := range tt.want.Qualifiers {
				if got.Qualifiers[k] != v {
					t.Errorf("qualifier %q = %q, want %q", k, got.Qualifiers[k], v)
				}
			}
		})
	}
}

// A string that is not a purl has to say so, because the caller records it as a
// failure and a failure is what makes the run exit non-zero. Silently treating
// one of these as a package would query OSV for a name out of a URL.
func TestParsePURLRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"libssl3",
		"https://example.com/libssl3",
		"pkg:",
		"pkg:deb",  // a type and nothing to name
		"pkg:deb/", // a type and an empty name
		// "pkg:/debian/foo" is not here: the specification says to strip
		// leading slashes, so it parses as the type "debian", which build then
		// declines as an ecosystem this tool has no plugin for. That is the
		// right place to refuse it -- a purl with a type nobody supports is a
		// skip, and a string that is not a purl is a failure.
	} {
		if got, err := parsePURL(in); err == nil {
			t.Errorf("parsePURL(%q) = %+v, want an error", in, got)
		}
	}
}
