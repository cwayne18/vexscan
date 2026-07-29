//go:build norpm

package pkgdb

import (
	"errors"
	"testing"
)

// TestNoRPMBuildStillDetectsAndThenFails is the point of the stub. A build
// without rpm support must not answer "no package database found" for a Red
// Hat image -- that renders as an image with nothing installed and therefore
// nothing vulnerable, a clean bill of health handed out by a build flag.
func TestNoRPMBuildStillDetectsAndThenFails(t *testing.T) {
	fsys := writeTree(t, map[string]string{"/var/lib/rpm/rpmdb.sqlite": "SQLite format 3\x00"})

	db, ok := (&RPM{}).Detect(fsys)
	if !ok || db != "/var/lib/rpm/rpmdb.sqlite" {
		t.Fatalf("Detect() = %q, %v; the stub must still recognize an rpm image", db, ok)
	}

	_, err := (&RPM{}).Read(fsys)
	if !errors.Is(err, ErrRPMUnsupported) {
		t.Fatalf("Read() = %v, want ErrRPMUnsupported", err)
	}

	// And it must propagate: a detected-but-unreadable database fails the
	// whole inventory rather than yielding a partial one.
	if results, err := Read(fsys); err == nil {
		t.Fatalf("Read() reported an inventory without rpm support: %+v", results)
	}
}
