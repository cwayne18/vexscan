package ecosystem

import "testing"

// The purls below are the ones the plugins in this tree actually emit; see
// ospkg.purl, npm.purl, golang.purl and pypi.purl.
func TestFindingComponent(t *testing.T) {
	cases := []struct {
		name    string
		purl    string
		pkg     string
		want    string
		comment string
	}{
		{
			name:    "deb binary package differs from the source package",
			purl:    "pkg:deb/debian/libgcc-s1@12.2.0-14+deb12u1?arch=amd64",
			pkg:     "gcc-12",
			want:    "libgcc-s1",
			comment: "the whole point: the source package is not the installed artifact",
		},
		{
			name: "the same source package, a different binary",
			purl: "pkg:deb/debian/gcc-12-base@12.2.0-14+deb12u1?arch=amd64",
			pkg:  "gcc-12",
			want: "gcc-12-base",
		},
		{
			name: "rpm",
			purl: "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?arch=x86_64",
			pkg:  "openssl",
			want: "openssl-libs",
		},
		{
			name: "apk",
			purl: "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64",
			pkg:  "openssl",
			want: "libcrypto3",
		},
		{
			name: "a version containing an epoch colon",
			purl: "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64",
			pkg:  "zlib",
			want: "zlib1g",
		},
		{
			name: "no qualifiers",
			purl: "pkg:deb/debian/libc6@2.36-9",
			pkg:  "glibc",
			want: "libc6",
		},
		{
			name: "no namespace",
			purl: "pkg:deb/libc6@2.36-9",
			pkg:  "glibc",
			want: "libc6",
		},
		{
			name: "no version",
			purl: "pkg:deb/debian/libc6",
			pkg:  "glibc",
			want: "libc6",
		},
		{
			name:    "percent-encoded name",
			purl:    "pkg:deb/debian/lib%2Bplus@1.0",
			pkg:     "plus",
			want:    "lib+plus",
			comment: "decoding must happen after the name is isolated",
		},

		// Everything below is a non-OS ecosystem, where Package is already the
		// installed artifact's name and Component must not second-guess it.
		{
			name:    "npm scoped package falls back to Package",
			purl:    "pkg:npm/@sigstore/core@2.0.0",
			pkg:     "@sigstore/core",
			want:    "@sigstore/core",
			comment: "re-deriving this from the purl could only lose the scope",
		},
		{
			name: "npm unscoped",
			purl: "pkg:npm/lodash@4.17.21",
			pkg:  "lodash",
			want: "lodash",
		},
		{
			name: "go module keeps its full path",
			purl: "pkg:golang/github.com%2Fcwayne18%2Fvexscan@v0.1.2",
			pkg:  "github.com/cwayne18/vexscan",
			want: "github.com/cwayne18/vexscan",
		},
		{
			name: "pypi",
			purl: "pkg:pypi/django@4.2.1",
			pkg:  "django",
			want: "django",
		},
		{
			name: "maven",
			purl: "pkg:maven/org.apache.commons/commons-compress@1.24.0",
			pkg:  "org.apache.commons:commons-compress",
			want: "org.apache.commons:commons-compress",
		},

		// A name that is merely coarse beats no name at all.
		{
			name: "no purl at all",
			purl: "",
			pkg:  "openssl",
			want: "openssl",
		},
		{
			name: "not a purl",
			purl: "openssl-3.0.7",
			pkg:  "openssl",
			want: "openssl",
		},
		{
			name: "purl with no type separator",
			purl: "pkg:deb",
			pkg:  "openssl",
			want: "openssl",
		},
		{
			name: "purl with an empty name",
			purl: "pkg:deb/debian/@1.0",
			pkg:  "openssl",
			want: "openssl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{PURL: tc.purl, Package: tc.pkg}
			if got := f.Component(); got != tc.want {
				t.Errorf("Component() = %q, want %q (purl %q, package %q)%s",
					got, tc.want, tc.purl, tc.pkg, note(tc.comment))
			}
		})
	}
}

func note(s string) string {
	if s == "" {
		return ""
	}
	return "\n  " + s
}

// TestComponentDistinguishesTheGCCTrio is the concrete defect this method was
// added for: three findings for one advisory against one source package, with
// two different verdicts between them, which the report used to render as three
// identical lines.
func TestComponentDistinguishesTheGCCTrio(t *testing.T) {
	trio := []Finding{
		{Package: "gcc-12", PURL: "pkg:deb/debian/gcc-12-base@12.2.0-14+deb12u1?arch=amd64", Status: StatusNotPresent},
		{Package: "gcc-12", PURL: "pkg:deb/debian/libgcc-s1@12.2.0-14+deb12u1?arch=amd64", Status: StatusLinked},
		{Package: "gcc-12", PURL: "pkg:deb/debian/libstdc++6@12.2.0-14+deb12u1?arch=amd64", Status: StatusLinked},
	}
	seen := map[string]bool{}
	for _, f := range trio {
		c := f.Component()
		if seen[c] {
			t.Errorf("two findings both render as %q", c)
		}
		seen[c] = true
	}
	for _, want := range []string{"gcc-12-base", "libgcc-s1", "libstdc++6"} {
		if !seen[want] {
			t.Errorf("%s missing from %v", want, seen)
		}
	}
}
