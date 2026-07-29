//go:build !norpm

package pkgdb

import (
	"fmt"
	"sort"
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
			Source:  sourceRPMName(info.SourceRpm),
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

// rpmEVR composes the version string OSV compares against.
//
// The epoch is always included, including when it is zero. That is not what
// rpm -q prints, but it is what the Red Hat, Rocky and AlmaLinux OSV records
// contain -- verified against api.osv.dev:
//
//	RHSA-2024:2447  openssl    fixed 1:3.0.7-27.el9
//	RHSA-2023:6746  nghttp2    fixed 0:1.43.0-5.el9_3.1   <- explicit zero
//	Rocky Linux:9   openssl    fixed 1:3.0.1-43.el9_0
//	AlmaLinux:9     openssl    fixed 1:3.0.1-41.el9_0
//
// Azure Linux is the exception: its records carry no epoch at all ("3.3.0-1").
// Package.Epoch is exposed separately so the OS plugin can drop the prefix for
// that ecosystem rather than have this layer guess which consumer it has.
func rpmEVR(epoch int, version, release string) string {
	evr := version
	if release != "" {
		evr += "-" + release
	}
	return fmt.Sprintf("%d:%s", epoch, evr)
}

// sourceRPMName extracts the source package name from a SOURCERPM value like
// "openssl-3.2.2-16.el10.src.rpm", which is name-version-release.src.rpm. The
// name itself may contain hyphens ("java-21-openjdk"), so the tail is stripped
// by position from the right rather than by splitting from the left.
func sourceRPMName(srpm string) string {
	s := strings.TrimSuffix(strings.TrimSpace(srpm), ".src.rpm")
	s = strings.TrimSuffix(s, ".nosrc.rpm")
	if s == "" || s == srpm {
		// Not the expected shape; a bare name is still usable, anything else
		// is better dropped than passed to OSV as a package name.
		if strings.HasSuffix(srpm, ".rpm") {
			return ""
		}
		return s
	}
	// Strip "-release" then "-version".
	for i := 0; i < 2; i++ {
		dash := strings.LastIndex(s, "-")
		if dash <= 0 {
			return ""
		}
		s = s[:dash]
	}
	return s
}

// normalizePaths makes rpm's file list tree-absolute and ordered. rpm stores
// absolute paths already, but relocatable packages and malformed headers can
// produce relative ones, which would silently fail to match anything.
func normalizePaths(files []string) []string {
	if len(files) == 0 {
		return nil
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !strings.HasPrefix(f, "/") {
			f = "/" + f
		}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
