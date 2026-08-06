//go:build !norpm

package pkgdb

import (
	"fmt"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	// go-rpmdb reads the sqlite database through database/sql and calls
	// sql.Open("sqlite", path) without registering a driver -- its own tests
	// blank-import this one to make that work. Omitting it does not fail to
	// compile; it fails at the first query on every RHEL 9+ and Fedora 33+
	// image, which is most rpm images in circulation. glebarez/go-sqlite is
	// the modernc pure-Go driver, so this stays CGO-free and the Dockerfile's
	// CGO_ENABLED=0 cross-compile keeps working.
	_ "github.com/glebarez/go-sqlite"

	"github.com/cwayne18/vexscan/internal/target"
)

// rpmDBs are the database files rpm may keep, newest layout first.
//
// The sysimage paths come first because a modern image often has
// /var/lib/rpm as a symlink to /usr/lib/sysimage/rpm; either order works
// through that link, but naming the real location in evidence is clearer.
// The three filenames are three on-disk formats: sqlite (RHEL 9+, Fedora 33+),
// ndb (SUSE), and Berkeley DB (RHEL 7 and 8, CentOS).
var rpmDBs = []string{
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/var/lib/rpm/rpmdb.sqlite",
	"/usr/lib/sysimage/rpm/Packages.db",
	"/var/lib/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/Packages",
	"/var/lib/rpm/Packages",
}

// RPM reads rpm's database.
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
	// go-rpmdb opens a real file: sqlite and Berkeley DB both mmap and seek,
	// so there is no io.Reader path to hand it.
	host, err := fsys.HostPath(db)
	if err != nil {
		return nil, err
	}

	handle, err := rpmdb.Open(host)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", db, err)
	}
	defer handle.Close()

	infos, err := handle.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", db, err)
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("%s parsed to zero installed packages", db)
	}

	pkgs := make([]Package, 0, len(infos))
	for _, info := range infos {
		if info == nil || info.Name == "" {
			continue
		}
		pkg := Package{
			Format:  FormatRPM,
			Name:    info.Name,
			Version: rpmEVR(info.EpochNum(), info.Version, info.Release),
			Epoch:   info.EpochNum(),
			Arch:    info.Arch,
			Source:  SourceRPMName(info.SourceRpm),
			DB:      db,
		}
		// A package with no file list is normal (metapackages own nothing),
		// but a header that fails to decode is not, and silently dropping its
		// files would make the package look like docs-only.
		files, err := info.InstalledFileNames()
		if err != nil {
			return nil, fmt.Errorf("%s: file list for %s: %w", db, info.Name, err)
		}
		pkg.Files = normalizePaths(files)
		pkgs = append(pkgs, pkg)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s yielded no named packages", db)
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// rpmEVR, SourceRPMName and normalizePaths live in rpmfile.go, which carries no
// build tag: the file reader needs them too, and it has to keep working in the
// norpm build that omits everything above.
