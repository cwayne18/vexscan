package main

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

func TestRenderInventory(t *testing.T) {
	inv := &analyze.InventoryResult{
		Target: "debian:12",
		Mode:   "image",
		OS: &analyze.OSInfo{
			ID: "debian", VersionID: "12",
			PrettyName: "Debian GNU/Linux 12 (bookworm)",
			Ecosystem:  "Debian:12",
		},
		Databases: []pkgdb.Result{{
			Format: pkgdb.FormatDeb,
			DB:     "/var/lib/dpkg/status",
			Packages: []pkgdb.Package{
				{Format: pkgdb.FormatDeb, Name: "libc6", Version: "2.36-9+deb12u14", Arch: "amd64", Source: "glibc"},
				{Format: pkgdb.FormatDeb, Name: "bash", Version: "5.2.15-2+b13", Arch: "amd64", Source: "bash"},
			},
		}},
	}

	got := renderInventory(inv)
	for _, want := range []string{
		"vexscan inventory for debian:12",
		"ecosystem: Debian:12",
		"packages:  2",
		"deb (2 packages, /var/lib/dpkg/status)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}

	// The names OSV will actually be queried by are the point of this view.
	// Debian files glibc advisories against "glibc"; a user checking the
	// output needs to see that the tool knows it.
	if !strings.Contains(got, "glibc, libc6") {
		t.Errorf("libc6 line does not show the source name it will be queried by:\n%s", got)
	}
	// A package whose source matches its name lists one name, not two.
	if strings.Contains(got, "bash, bash") {
		t.Errorf("bash is listed twice:\n%s", got)
	}
}

// TestRenderInventoryShoutsAboutAnUnresolvedEcosystem: with no ecosystem there
// is nothing to query, so a later scan comes back with no findings. That is
// indistinguishable from a clean image unless the inventory says so plainly.
func TestRenderInventoryShoutsAboutAnUnresolvedEcosystem(t *testing.T) {
	got := renderInventory(&analyze.InventoryResult{
		Target: "sles15:latest",
		OS: &analyze.OSInfo{
			ID: "sles", PrettyName: "SUSE Linux Enterprise Server 15 SP5",
			EcosystemError: "osv: this distribution's OSV ecosystem cannot be determined from os-release: name it with --ecosystem",
		},
		Databases: []pkgdb.Result{{Format: pkgdb.FormatRPM, DB: "/var/lib/rpm/rpmdb.sqlite", Packages: []pkgdb.Package{
			{Format: pkgdb.FormatRPM, Name: "glibc", Version: "0:2.31-150300.63.1", Arch: "x86_64", Source: "glibc"},
		}}},
	})
	if !strings.Contains(got, "UNRESOLVED") || !strings.Contains(got, "--ecosystem") {
		t.Errorf("an unresolvable ecosystem is not called out:\n%s", got)
	}
	// The packages are still listed: the inventory is useful without a name.
	if !strings.Contains(got, "glibc") {
		t.Errorf("packages were suppressed:\n%s", got)
	}
}

// TestRenderersSayWhenPartOfTheTreeWasNotRead: an unlistable directory hides an
// unknown number of packages, and both views have to say so above the data, not
// after it. This is mostly a rootfs concern -- extraction creates every
// directory 0755 -- but the renderers do not care which mode produced it.
func TestRenderersSayWhenPartOfTheTreeWasNotRead(t *testing.T) {
	unreadable := &target.Unreadable{Count: 12, Paths: []string{"/opt/vendor", "/srv/data"}}

	inv := renderInventory(&analyze.InventoryResult{
		Target: "/mnt/rootfs", Mode: "rootfs", Unreadable: unreadable,
	})
	res := renderText([]*analyze.Result{
		{
			SchemaVersion: analyze.SchemaVersion, Target: "/mnt/rootfs", Mode: "rootfs",
			Unreadable: unreadable,
		},
	}, renderOpts{})

	for name, got := range map[string]string{"inventory": inv, "report": res} {
		if !strings.Contains(got, "INCOMPLETE") {
			t.Errorf("%s does not flag the gap:\n%s", name, got)
		}
		if !strings.Contains(got, "/opt/vendor") || !strings.Contains(got, "/srv/data") {
			t.Errorf("%s does not name the paths:\n%s", name, got)
		}
		// The sample is capped, so the count and the list disagree. Printing
		// only the list would read as "two directories" when it was twelve.
		if !strings.Contains(got, "and 10 more") {
			t.Errorf("%s hides the paths beyond the sample:\n%s", name, got)
		}
	}
	// A report with no findings and a hole in it is not a clean report.
	if !strings.Contains(res, "This is not a clean result.") {
		t.Errorf("an incomplete empty report reads as clean:\n%s", res)
	}
}

func TestRenderInventoryWithNothingFound(t *testing.T) {
	got := renderInventory(&analyze.InventoryResult{Target: "scratch-app:latest"})
	if !strings.Contains(got, "unknown (no readable /etc/os-release)") {
		t.Errorf("missing os line:\n%s", got)
	}
	if !strings.Contains(got, "No dpkg, apk or rpm database found.") {
		t.Errorf("an image with no package database is not reported plainly:\n%s", got)
	}
}
