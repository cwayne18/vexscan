package golang

import (
	"context"
	"debug/buildinfo"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/osv"
)

// Regression tests for percent-encoded namespace separators in golang purls.
//
// purl() used to build "pkg:golang/" + strings.ReplaceAll(module, "/", "%2F"),
// which put "pkg:golang/golang.org%2Fx%2Fcrypto@v0.55.0" into the @id of every
// subcomponent this tool published. Those slashes are structural: they separate
// the namespace segments from the name, and encoding them describes a
// namespace-less package whose name contains slashes -- a different package.
// Trivy emits the literal form and compares purls exactly, so the statements
// never matched and the CVEs they ruled out came back. CVE-2026-56855 and
// CVE-2026-78662 against golang.org/x/crypto/ssh in rke2-runtime are the two
// that were noticed; cwayne18/vexhub#4 hand-patched 46 of them out of the
// published hub.
//
// The rule these pin: in a golang purl nothing is escaped at all. See purl().

// purlCases are the shapes that broke, plus the one that has no namespace to
// get wrong. Versions are included because "+incompatible" is the other
// character a purl builder is tempted to escape and must not: the hub carries
// pkg:golang/github.com/docker/docker@v27.3.1+incompatible, and %2B matches it
// no better than %2F matches a slash.
var purlCases = []struct {
	module, version, want string
}{
	{"golang.org/x/crypto", "v0.55.0", "pkg:golang/golang.org/x/crypto@v0.55.0"},
	{"github.com/docker/docker", "v27.3.1+incompatible", "pkg:golang/github.com/docker/docker@v27.3.1+incompatible"},
	{"go.etcd.io/etcd/client/pkg/v3", "v3.7.0", "pkg:golang/go.etcd.io/etcd/client/pkg/v3@v3.7.0"},
	{"github.com/containerd/containerd/v2", "v2.1.4", "pkg:golang/github.com/containerd/containerd/v2@v2.1.4"},
	// No namespace, so no separator to encode. It is here to prove the fix did
	// not go the other way and start splitting a single-segment path.
	{"stdlib", "1.25.12", "pkg:golang/stdlib@1.25.12"},
}

func assertLiteralPURL(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("purl = %q, want %q", got, want)
	}
	if strings.Contains(got, "%2F") || strings.Contains(got, "%2f") {
		t.Errorf("purl %q percent-encodes a namespace separator", got)
	}
	if strings.Contains(got, "%2B") || strings.Contains(got, "%2b") {
		t.Errorf("purl %q percent-encodes the '+' of a version", got)
	}
}

func TestPURLKeepsNamespaceSlashesLiteral(t *testing.T) {
	for _, tt := range purlCases {
		t.Run(tt.module, func(t *testing.T) {
			assertLiteralPURL(t, purl(tt.module, tt.version), tt.want)
		})
	}
}

// The inventory is where the purl is actually minted -- evaluate only copies
// the component's -- so the grouper is tested on the real path rather than
// purl() being trusted to be the only caller.
func TestInventoryPURLsAreLiteral(t *testing.T) {
	const root = "/tmp/extract"

	deps := make([]*debug.Module, 0, len(purlCases))
	for _, tt := range purlCases {
		if tt.module == "stdlib" {
			continue // supplied by the grouper from the Go version, not by Deps
		}
		deps = append(deps, &debug.Module{Path: tt.module, Version: tt.version})
	}
	bins := []binscan.Binary{{
		Path: root + "/bin/app",
		Info: &buildinfo.BuildInfo{
			Main:      debug.Module{Path: "github.com/example/app", Version: "v1.0.0"},
			GoVersion: "go1.25.12",
			Deps:      deps,
		},
	}}

	comps := New(Options{}).groupAll(root, bins)
	for _, tt := range purlCases {
		if tt.module == "stdlib" {
			continue
		}
		c := mainComponent(comps, tt.module)
		if c == nil {
			t.Errorf("no component for %s", tt.module)
			continue
		}
		assertLiteralPURL(t, c.PURL, tt.want)
	}
	// The main module too: it is the one every subcomponent hangs off.
	if c := mainComponent(comps, "github.com/example/app"); c == nil {
		t.Error("no component for the main module")
	} else {
		assertLiteralPURL(t, c.PURL, "pkg:golang/github.com/example/app@v1.0.0")
	}
}

// The pclntab and pclntab-module paths specifically, because those are the two
// methods the malformed statements in the hub were stamped with -- their
// impact_statement is what identified them. A finding is what becomes a VEX
// subcomponent, so this is the value that has to be right.
func TestPclntabFindingsCarryALiteralPURL(t *testing.T) {
	// A binary that links nothing from x/crypto, so both granularities rule the
	// advisory out rather than reporting it linked.
	syms := symbolsFor(t, "runtime.main\x00fmt.Println")

	const (
		module  = "golang.org/x/crypto"
		version = "v0.55.0"
		want    = "pkg:golang/golang.org/x/crypto@v0.55.0"
	)
	ec := evalCtx{
		binaryRel: "/bin/rke2",
		module:    module,
		version:   version,
		purl:      purl(module, version),
		product:   "pkg:golang/github.com/containerd/containerd/v2",
		syms:      syms,
		logf:      func(string, ...any) {},
	}

	tests := []struct {
		name       string
		adv        *osv.Advisory
		wantMethod string
	}{{
		name:       "package granularity",
		adv:        &osv.Advisory{ID: "GO-2026-4001", Pkgs: []string{"golang.org/x/crypto/ssh"}},
		wantMethod: "pclntab",
	}, {
		name:       "module granularity",
		adv:        &osv.Advisory{ID: "GO-2026-4002"},
		wantMethod: "pclntab-module",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := evaluate(context.Background(), ec, "CVE-2026-56855", tt.adv)
			if f.Method != tt.wantMethod {
				t.Fatalf("method = %q, want %q: this test is aimed at the wrong path", f.Method, tt.wantMethod)
			}
			assertLiteralPURL(t, f.PURL, want)
		})
	}
}

// parsePURL has to keep reading the old spelling: a hub is full of documents
// written before the fix, and failing to parse them would drop statements
// rather than match them.
func TestParsePURLStillReadsTheEncodedForm(t *testing.T) {
	for _, s := range []string{
		"pkg:golang/golang.org%2Fx%2Fcrypto@v0.55.0",
		"pkg:golang/golang.org/x/crypto@v0.55.0",
	} {
		module, version := parsePURL(s)
		if module != "golang.org/x/crypto" || version != "v0.55.0" {
			t.Errorf("parsePURL(%q) = %q@%q, want golang.org/x/crypto@v0.55.0", s, module, version)
		}
	}
}
