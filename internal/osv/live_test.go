package osv

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestLiveEcosystemStrings checks the mapping table against the real
// api.osv.dev. Set VEXSCAN_LIVE_OSV=1 to run it.
//
// It is opt-in because it needs the network, but it is the only test that can
// catch the failure this table exists to prevent. api.osv.dev validates the
// ecosystem family and rejects a misspelling with HTTP 400, but it does not
// validate the version suffix: "Debian:99" answers 200 with an empty result.
// So a suffix rule that goes stale -- OSV renaming a product, or a new release
// series changing shape -- degrades to "this image has no vulnerabilities"
// with nothing in the logs. Only asking the real API notices.
//
//	VEXSCAN_LIVE_OSV=1 go test ./internal/osv/ -run TestLive -v
func TestLiveEcosystemStrings(t *testing.T) {
	if os.Getenv("VEXSCAN_LIVE_OSV") == "" {
		t.Skip("set VEXSCAN_LIVE_OSV=1 to query api.osv.dev")
	}

	// probe is a package that certainly exists in the distribution and
	// certainly has advisories against it. No version: the question is whether
	// the ecosystem string names a database with records in it, not whether
	// any particular version is affected.
	tests := []struct {
		osrel string
		want  string
		probe string
	}{
		{"ID=debian\nVERSION_ID=\"12\"\n", "Debian:12", "openssl"},
		{"ID=debian\nVERSION_ID=\"13\"\n", "Debian:13", "openssl"},
		{"ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.5 LTS (Jammy Jellyfish)\"\n", "Ubuntu:22.04:LTS", "openssl"},
		{"ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.3 LTS (Noble Numbat)\"\n", "Ubuntu:24.04:LTS", "openssl"},
		{"ID=alpine\nVERSION_ID=3.19.1\n", "Alpine:v3.19", "openssl"},
		{"ID=rhel\nVERSION_ID=\"9.4\"\n", "Red Hat", "openssl"},
		{"ID=rocky\nVERSION_ID=\"9.3\"\n", "Rocky Linux:9", "openssl"},
		{"ID=almalinux\nVERSION_ID=\"9.4\"\n", "AlmaLinux:9", "openssl"},
		{"ID=wolfi\nVERSION_ID=\"20230201\"\n", "Wolfi", "openssl"},
		{"ID=chainguard\nVERSION_ID=\"20230214\"\n", "Chainguard", "openssl"},
		{"ID=minimos\nVERSION_ID=\"20250101\"\n", "MinimOS", "openssl"},
		{"ID=azurelinux\nVERSION_ID=\"3.0\"\n", "Azure Linux:3", "openssl"},
		{"ID=mageia\nVERSION_ID=9\n", "Mageia:9", "openssl"},
		{"ID=alpaquita\nVERSION_ID=23\n", "Alpaquita:23", "openssl"},
		{"ID=openEuler\nVERSION_ID=\"24.03\"\nVERSION=\"24.03 (LTS)\"\n", "openEuler:24.03-LTS", "glibc"},
		// SUSE spells openssl "openssl-1_1" / "openssl-3"; glibc is stable
		// across their product line.
		{"ID=opensuse-leap\nVERSION_ID=\"15.6\"\nPRETTY_NAME=\"openSUSE Leap 15.6\"\n", "openSUSE:Leap 15.6", "glibc"},
		{"ID=sles\nVERSION_ID=\"15.7\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 15 SP7\"\n", "SUSE", "glibc"},
	}

	client := NewClient()
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			rel, err := ParseOSRelease(strings.NewReader(tt.osrel))
			if err != nil {
				t.Fatal(err)
			}
			eco, err := rel.Ecosystem()
			if err != nil {
				t.Fatal(err)
			}
			if eco != tt.want {
				t.Fatalf("Ecosystem() = %q, want %q", eco, tt.want)
			}

			adv, err := client.Query(context.Background(), Ref{Ecosystem: eco, Name: tt.probe})
			if err != nil {
				// A 400 here means OSV does not recognize the ecosystem at all.
				t.Fatalf("querying %s/%s: %v", eco, tt.probe, err)
			}
			if len(adv) == 0 {
				t.Errorf("%s/%s returned no advisories: the version suffix is probably wrong, "+
					"since OSV answers 200 with an empty result for a valid family and a bogus version",
					eco, tt.probe)
			}
		})
	}
}

// TestLiveInvalidEcosystemIsRejected pins the one thing that makes a
// misspelled family name recoverable: OSV rejects it outright rather than
// answering clean. If this ever stops being true, a typo in the table becomes
// as silent as a wrong version suffix.
func TestLiveInvalidEcosystemIsRejected(t *testing.T) {
	if os.Getenv("VEXSCAN_LIVE_OSV") == "" {
		t.Skip("set VEXSCAN_LIVE_OSV=1 to query api.osv.dev")
	}

	_, err := NewClient().Query(context.Background(), Ref{Ecosystem: "Debain:12", Name: "openssl"})
	if err == nil {
		t.Fatal("api.osv.dev accepted a misspelled ecosystem")
	}
	if !strings.Contains(err.Error(), "invalid ecosystem") {
		t.Errorf("unexpected error for a misspelled ecosystem: %v", err)
	}
}

// TestLiveSLESProductNarrowing is the regression test for the SLES 15 SP7 gzip
// case: the bare family has to find the advisory, and the release filter has
// to drop the other products' records without dropping that one.
//
// Both halves are load-bearing and they fail in opposite directions. Without
// the bare family nothing is found at all; without the filter a fully patched
// image reports as vulnerable forever, because SLE 16 fixes gzip at a version
// SLE 15 will never ship.
func TestLiveSLESProductNarrowing(t *testing.T) {
	if os.Getenv("VEXSCAN_LIVE_OSV") == "" {
		t.Skip("set VEXSCAN_LIVE_OSV=1 to query api.osv.dev")
	}

	rel, err := ParseOSRelease(strings.NewReader(
		"ID=sles\nVERSION_ID=\"15.7\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 15 SP7\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	eco, err := rel.Ecosystem()
	if err != nil {
		t.Fatal(err)
	}
	release := rel.ProductRelease()
	if release != "15 SP7" {
		t.Fatalf("ProductRelease() = %q", release)
	}

	client := NewClient()
	ctx := context.Background()

	// The version SP7 shipped before the fix. gzip is in the Basesystem
	// module, so this is the exact lookup that used to be impossible to make.
	const vulnerable = "1.10-150200.10.1"
	adv, err := client.Query(ctx, Ref{Ecosystem: eco, Release: release, Name: "gzip", Version: vulnerable})
	if err != nil {
		t.Fatalf("querying gzip@%s: %v", vulnerable, err)
	}
	if _, ok := adv["SUSE-SU-2026:3269-1"]; !ok {
		got := make([]string, 0, len(adv))
		for id := range adv {
			got = append(got, id)
		}
		sort.Strings(got)
		t.Errorf("SUSE-SU-2026:3269-1 not found for gzip@%s; got %v", vulnerable, got)
	}

	// The version that advisory fixes. Every record still returned by the bare
	// family belongs to another product, so the filter must leave nothing.
	const patched = "1.10-150200.13.1"
	adv, err = client.Query(ctx, Ref{Ecosystem: eco, Release: release, Name: "gzip", Version: patched})
	if err != nil {
		t.Fatalf("querying gzip@%s: %v", patched, err)
	}
	for id := range adv {
		t.Errorf("patched gzip@%s still reports %s; the release filter let another product through", patched, id)
	}
}
