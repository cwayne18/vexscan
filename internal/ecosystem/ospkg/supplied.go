package ospkg

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
)

// Supplied is one package read from somewhere other than an installed tree --
// today, an rpm file that --rpm named.
//
// It pairs the ordinary Package every other reader produces with the header
// metadata that only a package file carries. Meta is what makes a verdict
// possible at all without a filesystem: no ELF in the header means no
// vulnerable code will be installed, which is the same evidence pkgdb-no-code
// rests on when it is read out of an image.
type Supplied struct {
	Package pkgdb.Package
	Meta    pkgdb.Meta
}

// prepareSupplied fills in a prepared from Plugin.Packages instead of from a
// tree.
//
// It is the whole of what --rpm changes inside this plugin. Everything after
// it -- inventory, OSVNames, the batch query, severity, --triage, --vexhub --
// runs against exactly the same types it runs against for an image, because
// the difference between a package that is installed and a package that would
// be installed is not a difference in its coordinates.
func (p *Plugin) prepareSupplied(pr *prepared) error {
	pr.metadataOnly = true
	pr.meta = make(map[string]pkgdb.Meta, len(p.Packages))

	for _, s := range p.Packages {
		pr.meta[metaKey(s.Package)] = s.Meta
	}
	pr.dbs = SuppliedResults(p.Packages)

	eco, distro, err := SuppliedIdentity(p.Packages, p.Ecosystem)
	if err != nil {
		return err
	}
	// Deliberately no ProductRelease narrowing. On SUSE that token is the
	// service pack -- "15 SP6" -- and the DISTRIBUTION header stops at "SUSE
	// Linux Enterprise 15", so narrowing here would filter with a token no
	// affected entry carries and clear findings that are real. Leaving it off
	// matches SLE 15 and SLE 16 records both, which over-reports rather than
	// under-reports, and every one of those findings is undetermined anyway.
	pr.ecosystem, pr.release, pr.distro = eco, "", distro
	return nil
}

// SuppliedResults groups a handed-in inventory the way a database reader
// groups what it read, so --format inventory can print one without a plugin
// and without a tree.
func SuppliedResults(pkgs []Supplied) []pkgdb.Result {
	byFormat := map[pkgdb.Format][]pkgdb.Package{}
	for _, s := range pkgs {
		byFormat[s.Package.Format] = append(byFormat[s.Package.Format], s.Package)
	}
	formats := make([]pkgdb.Format, 0, len(byFormat))
	for f := range byFormat {
		formats = append(formats, f)
	}
	sort.Slice(formats, func(i, j int) bool { return formats[i] < formats[j] })

	out := make([]pkgdb.Result, 0, len(formats))
	for _, f := range formats {
		group := byFormat[f]
		out = append(out, pkgdb.Result{Format: f, DB: commonSource(group), Packages: group})
	}
	return out
}

// SuppliedIdentity decides which OSV ecosystem a handed-in inventory belongs
// to, and which distro id its purls should carry.
//
// --osv-ecosystem always wins, and it is the documented way out of everything
// below. Otherwise the identity comes from the VENDOR and DISTRIBUTION tags in
// the headers, which is the only thing a package file knows about the system
// it was built for -- there is no /etc/os-release to read, because there is no
// system.
//
// The packages must agree. A directory holding both Rocky and SUSE rpms has no
// single right answer, and picking one would file half the inventory under an
// ecosystem whose records will never match it -- a query that answers HTTP 200
// with nothing, indistinguishable from a clean package.
func SuppliedIdentity(pkgs []Supplied, override string) (eco, distro string, err error) {
	ids := map[string]bool{}
	var rels []osv.Release
	var unknown []string
	for _, s := range pkgs {
		rel, ok := releaseFromHeader(s.Package, s.Meta)
		if !ok {
			unknown = append(unknown, describe(s))
			continue
		}
		if !ids[rel.ID] {
			ids[rel.ID] = true
			rels = append(rels, rel)
		}
	}

	if override != "" {
		// The override answers the ecosystem, but the purl namespace still
		// wants a distro id and the headers may well have one. When they
		// disagree among themselves it is left empty rather than guessed:
		// purl is evidence, and an evidence field should not be invented.
		if len(rels) == 1 {
			distro = strings.ToLower(rels[0].ID)
		}
		return override, distro, nil
	}

	switch {
	case len(rels) == 0:
		return "", "", fmt.Errorf("these package files do not say which distribution they are for "+
			"(no usable VENDOR or DISTRIBUTION header in %s), so their advisories cannot be looked up; "+
			"name the ecosystem with --osv-ecosystem", strings.Join(trim(unknown, 3), ", "))
	case len(rels) > 1:
		names := make([]string, 0, len(rels))
		for _, r := range rels {
			names = append(names, r.ID)
		}
		sort.Strings(names)
		return "", "", fmt.Errorf("these package files are for more than one distribution (%s); "+
			"scan them separately, or name one ecosystem with --osv-ecosystem", strings.Join(names, ", "))
	}

	eco, err = rels[0].Ecosystem()
	if err != nil {
		return "", "", fmt.Errorf("%w; name it with --osv-ecosystem", err)
	}
	return eco, strings.ToLower(rels[0].ID), nil
}

// rpmDistros maps what an rpm header says about who built a package onto the
// os-release ID the ecosystem table is keyed by.
//
// The match is a lowercased substring of DISTRIBUTION first and VENDOR second,
// because DISTRIBUTION is the more specific of the two -- "openSUSE Tumbleweed"
// and "openSUSE Leap 15.6" share a vendor and are different ecosystems. The
// order matters for the same reason: the longer key is tested first.
//
// Measured on real packages:
//
//	Rocky 9    VENDOR "Rocky Enterprise Software Foundation"  DISTRIBUTION "Rocky Linux 9"
//	SLE 15.6   VENDOR "SUSE LLC <https://www.suse.com/>"      DISTRIBUTION "SUSE Linux Enterprise 15"
//
// Distributions absent from the table are absent from OSV too (Fedora, Oracle
// Linux, CentOS Stream have no ecosystem there), so guessing a near neighbour
// for them would answer a query that finds nothing and reads as clean. They
// fall through to the --osv-ecosystem error instead.
var rpmDistros = []struct{ match, id string }{
	{"opensuse tumbleweed", "opensuse-tumbleweed"},
	{"opensuse leap", "opensuse-leap"},
	{"opensuse", "opensuse"},
	{"rocky", "rocky"},
	{"almalinux", "almalinux"},
	{"alpaquita", "alpaquita"},
	{"openeuler", "openeuler"},
	{"mageia", "mageia"},
	{"azure linux", "azurelinux"},
	{"common base linux mariner", "mariner"},
	{"red hat", "rhel"},
	// Last, because "SUSE" is a substring of nothing else here but "openSUSE"
	// is a substring of a SUSE vendor string.
	{"suse", "sles"},
}

// elRelease finds the ".el9" a Red Hat-family release tag ends with.
var elRelease = regexp.MustCompile(`\.el(\d+)`)

// trailingVersion finds the version a distribution name ends with, as in
// "Rocky Linux 9" or "openSUSE Leap 15.6".
var trailingVersion = regexp.MustCompile(`(\d+(?:\.\d+)*)\s*$`)

// releaseFromHeader builds the os-release fields Release.Ecosystem reads out
// of what the rpm header carries.
//
// It is a synthesis, not a parse: the header has no ID and no VERSION_ID, so
// both are derived. The version is taken from DISTRIBUTION when it states one
// and from the ".el9" in the release tag when it does not, which is what Red
// Hat packages leave to work with -- they carry a vendor and frequently no
// DISTRIBUTION at all.
func releaseFromHeader(pkg pkgdb.Package, meta pkgdb.Meta) (osv.Release, bool) {
	dist := strings.TrimSpace(meta.Distribution)
	vendor := strings.TrimSpace(meta.Vendor)

	id := ""
	for _, d := range rpmDistros {
		if strings.Contains(strings.ToLower(dist), d.match) || strings.Contains(strings.ToLower(vendor), d.match) {
			id = d.id
			break
		}
	}
	if id == "" {
		return osv.Release{}, false
	}

	rel := osv.Release{ID: id, PrettyName: dist}
	if m := trailingVersion.FindStringSubmatch(dist); m != nil {
		rel.VersionID = m[1]
	} else if m := elRelease.FindStringSubmatch(pkg.Version); m != nil {
		rel.VersionID = m[1]
	}
	rel.Version = rel.VersionID
	return rel, true
}

// metaKey identifies a package within one scan. Name and arch alone are not
// enough: a repository directory holds several builds of the same package, and
// they need not agree about whether they ship code.
func metaKey(pkg pkgdb.Package) string {
	return pkg.Name + "\x00" + pkg.Arch + "\x00" + pkg.Version
}

// commonSource is the shortest location that contains every package, for the
// one inventory log line that names where a Result came from. Per-package
// evidence does not go through here -- Package.DB already holds the exact
// file.
//
// It is string prefix arithmetic rather than path.Dir because these are as
// often URLs as paths, and path.Clean turns "https://m/pub" into "https:/m/pub".
func commonSource(pkgs []pkgdb.Package) string {
	if len(pkgs) == 0 {
		return ""
	}
	common := pkgs[0].DB
	for _, pkg := range pkgs[1:] {
		if pkg.DB == common {
			continue
		}
		n := 0
		for n < len(common) && n < len(pkg.DB) && common[n] == pkg.DB[n] {
			n++
		}
		// Back up to a separator, so two siblings that merely share the start
		// of their names ("xa.rpm", "xb.rpm") report their directory and not a
		// path fragment that does not exist.
		common = common[:n]
		if i := strings.LastIndexByte(common, '/'); i >= 0 {
			common = common[:i+1]
		} else {
			common = ""
		}
	}
	if trimmed := strings.TrimSuffix(common, "/"); trimmed != "" {
		return trimmed
	}
	if common == "/" {
		return "/"
	}
	return fmt.Sprintf("%d package files", len(pkgs))
}

// describe names a package file in an error message, preferring where it came
// from because that is what the user typed.
func describe(s Supplied) string {
	if s.Package.DB != "" {
		return path.Base(s.Package.DB)
	}
	return s.Package.Name
}

func trim(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(items[:n:n], fmt.Sprintf("and %d more", len(items)-n))
}
