package golang

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/osv"
)

// These are characterization tests: they pin the exact classification that
// evaluate produces. They moved here verbatim from internal/analyze when
// evaluate moved behind the ecosystem-plugin interface, and are meant to fail
// loudly if a status, a justification or a method string ever changes, since
// all three end up in a published VEX statement.
//
// The single intended delta from the pre-migration expectations is
// Reachability, which evaluate now records on a linked finding instead of
// consuming it inline to build an LLM prompt. It is not serialized, so no
// output changed.

// Test-local aliases, so the expectations below read exactly as they did in
// internal/analyze.
type Finding = ecosystem.Finding

const (
	StatusNotPresent   = ecosystem.StatusNotPresent
	StatusNotInPath    = ecosystem.StatusNotInPath
	StatusLinked       = ecosystem.StatusLinked
	StatusUndetermined = ecosystem.StatusUndetermined
)

// symbolsFor builds a real *binscan.Symbols over the given fake binary
// contents. The pclntab test is a regex over the raw bytes, so plain text
// standing in for a function-name table is sufficient and keeps the fixture
// readable.
func symbolsFor(t *testing.T, content string) *binscan.Symbols {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fakebin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	syms, err := binscan.LoadSymbols(path)
	if err != nil {
		t.Fatalf("LoadSymbols: %v", err)
	}
	return syms
}

func TestEvaluate(t *testing.T) {
	const (
		module  = "golang.org/x/net"
		version = "v0.17.0"
		binRel  = "/usr/bin/app"
		cve     = "CVE-2023-39325"
		goID    = "GO-2023-2102"

		// The two Reachability strings a linked finding can carry. They are the
		// prose the orchestrator hands the LLM, and are not serialized.
		reachUnstripped = "linked (symbols retained; reachability not asserted)"
		reachStripped   = "linked"
	)

	// A binary that links http2 but not the proxy package.
	linkedBlob := "golang.org/x/net/http2.(*Server).ServeConn\x00runtime.main"
	// A binary that links nothing from the module at all.
	unrelatedBlob := "runtime.main\x00net/http.(*Server).Serve"

	tests := []struct {
		name string

		adv      *osv.Advisory
		blob     string
		stripped bool
		notAff   map[string]struct{}

		want Finding
		// wantGovulnCalled pins the laziness of the govulncheck call: it is
		// expensive (a subprocess per binary) and must only run for a linked,
		// package-granularity, non-stripped candidate.
		wantGovulnCalled bool
	}{
		{
			name: "no OSV mapping is undetermined",
			adv:  nil,
			blob: linkedBlob,
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve,
				Status: StatusUndetermined,
				Reason: "no_osv_package_mapping",
			},
		},
		{
			name: "package granularity, not linked",
			adv:  &osv.Advisory{ID: goID, Pkgs: []string{"golang.org/x/net/http2"}},
			blob: unrelatedBlob,
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:      []string{"golang.org/x/net/http2"},
				Granularity:   "package",
				Status:        StatusNotPresent,
				Justification: "vulnerable_code_not_present",
				Method:        "pclntab",
			},
		},
		{
			name: "package granularity, linked, govulncheck says unreachable",
			adv:  &osv.Advisory{ID: goID, Pkgs: []string{"golang.org/x/net/http2"}},
			blob: linkedBlob,
			// govulncheck reports the CVE id here.
			notAff: map[string]struct{}{cve: {}},
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:      []string{"golang.org/x/net/http2"},
				Granularity:   "package",
				Status:        StatusNotInPath,
				Justification: "vulnerable_code_not_in_execute_path",
				Method:        "govulncheck",
			},
			wantGovulnCalled: true,
		},
		{
			name: "govulncheck match on the GO id, not the CVE id",
			adv:  &osv.Advisory{ID: goID, Pkgs: []string{"golang.org/x/net/http2"}},
			blob: linkedBlob,
			// Only the GO- id is present; inNotAffected checks both.
			notAff: map[string]struct{}{goID: {}},
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:      []string{"golang.org/x/net/http2"},
				Granularity:   "package",
				Status:        StatusNotInPath,
				Justification: "vulnerable_code_not_in_execute_path",
				Method:        "govulncheck",
			},
			wantGovulnCalled: true,
		},
		{
			name:   "package granularity, linked, govulncheck silent",
			adv:    &osv.Advisory{ID: goID, Pkgs: []string{"golang.org/x/net/http2"}},
			blob:   linkedBlob,
			notAff: map[string]struct{}{},
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:     []string{"golang.org/x/net/http2"},
				Granularity:  "package",
				Status:       StatusLinked,
				Reachability: reachUnstripped,
			},
			wantGovulnCalled: true,
		},
		{
			name:     "stripped binary skips govulncheck entirely",
			adv:      &osv.Advisory{ID: goID, Pkgs: []string{"golang.org/x/net/http2"}},
			blob:     linkedBlob,
			stripped: true,
			// Even though govulncheck would say not_affected, a stripped binary
			// must not consult it: binary mode over-reports without symbols.
			notAff: map[string]struct{}{cve: {}},
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:     []string{"golang.org/x/net/http2"},
				Granularity:  "package",
				Stripped:     true,
				Status:       StatusLinked,
				Reachability: reachStripped,
			},
			wantGovulnCalled: false,
		},
		{
			name: "multiple vulnerable packages are sorted, any one linking is enough",
			adv: &osv.Advisory{ID: goID, Pkgs: []string{
				"golang.org/x/net/proxy", "golang.org/x/net/http2",
			}},
			blob:   linkedBlob,
			notAff: map[string]struct{}{},
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:     []string{"golang.org/x/net/http2", "golang.org/x/net/proxy"},
				Granularity:  "package",
				Status:       StatusLinked,
				Reachability: reachUnstripped,
			},
			wantGovulnCalled: true,
		},
		{
			name: "module granularity, not present",
			adv:  &osv.Advisory{ID: goID}, // OSV published no import paths
			blob: unrelatedBlob,
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:      []string{module},
				Granularity:   "module",
				Status:        StatusNotPresent,
				Justification: "vulnerable_code_not_present",
				Method:        "pclntab-module",
			},
		},
		{
			name: "module granularity, present, never consults govulncheck",
			adv:  &osv.Advisory{ID: goID},
			blob: linkedBlob,
			// Module granularity is too coarse to trust govulncheck's
			// package-level verdict, so it is skipped even unstripped.
			notAff: map[string]struct{}{cve: {}},
			want: Finding{
				Binary: binRel, Module: module, Version: version, CVE: cve, GoID: goID,
				Packages:     []string{module},
				Granularity:  "module",
				Status:       StatusLinked,
				Reachability: reachUnstripped,
			},
			wantGovulnCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			govulnCalled := false
			ec := evalCtx{
				binaryRel: binRel,
				module:    module,
				version:   version,
				stripped:  tt.stripped,
				syms:      symbolsFor(t, tt.blob),
				govuln: func() map[string]struct{} {
					govulnCalled = true
					if tt.notAff == nil {
						return map[string]struct{}{}
					}
					return tt.notAff
				},
				logf: func(string, ...any) {},
			}

			got := evaluate(context.Background(), ec, cve, tt.adv)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("evaluate() mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
			if govulnCalled != tt.wantGovulnCalled {
				t.Errorf("govulncheck called = %v, want %v", govulnCalled, tt.wantGovulnCalled)
			}
		})
	}
}

// TestPackagePresentDoesNotLeakFromParent pins the child/parent package
// distinction that keeps a match on .../ssh from claiming .../ssh/agent is
// linked. This is the property that makes the pclntab test safe to base a
// vulnerable_code_not_present statement on.
func TestPackagePresentDoesNotLeakFromParent(t *testing.T) {
	syms := symbolsFor(t, "golang.org/x/crypto/ssh.NewClient\x00runtime.main")

	if !syms.PackagePresent("golang.org/x/crypto/ssh") {
		t.Error("parent package golang.org/x/crypto/ssh should be present")
	}
	if syms.PackagePresent("golang.org/x/crypto/ssh/agent") {
		t.Error("child package .../ssh/agent must not match on a parent-only binary")
	}
}
