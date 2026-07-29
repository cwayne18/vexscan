// Package pkgdb reads the installed-package databases of the three OS package
// managers that show up in container images: dpkg, apk and rpm.
//
// It answers two questions the OS ecosystem plugin needs: which packages are
// installed at which versions, and which files each one owns. The second is
// what connects a CVE against "openssl" to the ELF objects that would have to
// be loaded for it to matter.
//
// Nothing here talks to OSV or to the network. Readers parse a filesystem and
// return what they found, or an error -- never a partial answer.
package pkgdb

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// Format identifies a package manager.
type Format string

const (
	FormatDeb Format = "deb"
	FormatAPK Format = "apk"
	FormatRPM Format = "rpm"
)

// Package is one installed package.
type Package struct {
	Format  Format `json:"format"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`

	// Source is the source (dpkg "Source:", apk "o:", rpm SOURCERPM) package
	// this was built from, when the database records one and it differs from
	// Name.
	Source string `json:"source,omitempty"`
	// SourceVersion is the source version when dpkg records one explicitly,
	// which it only does when it differs from Version.
	SourceVersion string `json:"source_version,omitempty"`

	// Files are the tree-absolute paths the package installs, as the database
	// records them: directories included, nothing stat'ed.
	Files []string `json:"files,omitempty"`

	// DB is the tree-absolute path of the database this came from, for
	// evidence and error messages.
	DB string `json:"db,omitempty"`
}

// OSVNames returns the package names to query OSV with, likeliest first.
//
// Which name a distribution files advisories against is not consistent, and
// not even consistent within one package format. Verified against the live
// api.osv.dev, querying with no version so the count is "does this name exist
// in the database at all":
//
//	Debian:12      openssl 255    libssl3       0    <- source
//	Debian:12      glibc   158    libc6         0    <- source
//	Alpine:v3.19   openssl  55    libssl3       0    <- origin
//	Red Hat        openssl 168    openssl-libs 113   <- binary
//	AlmaLinux:9    openssl  10    openssl-libs  15   <- binary
//	Rocky Linux:9  openssl  10    openssl-libs   0   <- source, unlike its
//	                                                    upstream and its peer
//
// So the rule cannot be "deb and apk use the source name, rpm uses the binary
// name": Rocky and AlmaLinux are both RPM rebuilds of Red Hat and disagree.
// Both names are returned instead. A name that matches nothing costs one entry
// in a batch query; choosing the wrong single name reports a vulnerable
// package as clean, which is the one outcome this tool must never produce.
//
// The order is a display and tie-break preference only -- callers query every
// name returned.
func (p Package) OSVNames() []string {
	if p.Source == "" || p.Source == p.Name {
		return []string{p.Name}
	}
	if p.Format == FormatRPM {
		return []string{p.Name, p.Source}
	}
	return []string{p.Source, p.Name}
}

// Reader parses one kind of package database out of a filesystem tree.
type Reader interface {
	// Format names the package manager this reader understands.
	Format() Format
	// Detect reports whether the tree carries this kind of database, and the
	// tree-absolute path of the one it found.
	Detect(fsys target.RootFS) (string, bool)
	// Read parses the database. A database that Detect found but Read cannot
	// parse is an error, never an empty slice.
	Read(fsys target.RootFS) ([]Package, error)
}

// Readers returns every backend, in a stable order.
func Readers() []Reader {
	return []Reader{&Deb{}, &APK{}}
}

// Result is what one reader found.
type Result struct {
	Format   Format    `json:"format"`
	DB       string    `json:"db"`
	Packages []Package `json:"packages"`
}

// Read runs every reader that detects a database in fsys.
//
// A reader whose database is present but unparseable fails the whole call.
// Reporting the packages from the other databases and quietly omitting that
// one would render as "these are all the packages in the image", and every
// package the unread database owns would be attested as not present.
func Read(fsys target.RootFS) ([]Result, error) {
	var (
		out  []Result
		errs []error
	)
	for _, r := range Readers() {
		db, ok := r.Detect(fsys)
		if !ok {
			continue
		}
		pkgs, err := r.Read(fsys)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s database %s: %w", r.Format(), db, err))
			continue
		}
		out = append(out, Result{Format: r.Format(), DB: db, Packages: pkgs})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// sortPackages orders packages by name then architecture, so output is stable
// across runs regardless of the order a database happens to store them in.
func sortPackages(pkgs []Package) {
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Arch < pkgs[j].Arch
	})
}

// firstExisting returns the first of names that is a regular file in fsys.
func firstExisting(fsys target.RootFS, names ...string) (string, bool) {
	for _, name := range names {
		fi, err := fsys.Stat(name)
		if err == nil && fi.Mode().IsRegular() {
			return name, true
		}
	}
	return "", false
}

// splitSource parses dpkg's "Source:" value, which is either a bare package
// name ("acl") or a name with the source version in parentheses when it
// differs from the binary version ("bash (5.2.15-2)").
func splitSource(v string) (name, version string) {
	v = strings.TrimSpace(v)
	open := strings.Index(v, "(")
	if open < 0 {
		return v, ""
	}
	name = strings.TrimSpace(v[:open])
	rest := v[open+1:]
	if close := strings.Index(rest, ")"); close >= 0 {
		version = strings.TrimSpace(rest[:close])
	}
	return name, version
}
