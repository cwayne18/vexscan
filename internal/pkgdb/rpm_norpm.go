//go:build norpm

package pkgdb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// rpmDBs mirrors the real backend's list so Detect still recognizes an rpm
// image and can say so, rather than reporting no package database at all.
var rpmDBs = []string{
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/var/lib/rpm/rpmdb.sqlite",
	"/usr/lib/sysimage/rpm/Packages.db",
	"/var/lib/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/Packages",
	"/var/lib/rpm/Packages",
}

// ErrRPMUnsupported is returned when an rpm database is found by a binary
// built with the "norpm" tag.
var ErrRPMUnsupported = errors.New("this build has no rpm support (built with -tags norpm)")

// RPM is the stub backend. Reading rpm needs github.com/knqyf263/go-rpmdb and
// its sqlite driver, the only third-party dependencies in the tree; the norpm
// tag drops them. It still detects the database and then fails, because
// answering "no packages installed" for a Red Hat image would be a clean bill
// of health handed out by a build flag.
type RPM struct{}

func (*RPM) Format() Format { return FormatRPM }

func (*RPM) Detect(fsys target.RootFS) (string, bool) {
	return firstExisting(fsys, rpmDBs...)
}

func (r *RPM) Read(fsys target.RootFS) ([]Package, error) {
	db, ok := r.Detect(fsys)
	if !ok {
		return nil, fmt.Errorf("no rpm database at any of %s", strings.Join(rpmDBs, ", "))
	}
	return nil, fmt.Errorf("%s: %w", db, ErrRPMUnsupported)
}
