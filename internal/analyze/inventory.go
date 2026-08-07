package analyze

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/ecosystem/ospkg"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// InventoryResult is what a tree's package databases say is installed.
//
// This is the raw material the OS ecosystem plugin works from, exposed on its
// own because it is checkable: a user who suspects a finding is wrong can see
// exactly which database row it came from, and the ecosystem string that will
// be used to query OSV before any query is made.
type InventoryResult struct {
	Target    string         `json:"target"`
	Mode      string         `json:"mode"` // "image" | "rootfs" | "rpm" | "sbom"
	OS        *OSInfo        `json:"os,omitempty"`
	Databases []pkgdb.Result `json:"databases"`

	// Unreadable is the part of the tree the walks could not enter. An
	// inventory that skipped a directory is a list of what is installed with
	// an unknown number of omissions, which is not the same document.
	Unreadable *target.Unreadable `json:"unreadable,omitempty"`

	// Languages are the installed distributions of the language ecosystems
	// that ship inside images: Python's site-packages, Node's node_modules.
	// They are kept separate from Databases because they overlap: Debian's
	// python3-yaml deb installs the same files a PyPI inventory reports under
	// "pyyaml", and merging the two would hide that both advisory namespaces
	// apply.
	Languages []langdb.Result `json:"languages,omitempty"`

	// Notes are things the reader of this list has to know that are not
	// omissions: packages that were read but have no column here, and the like.
	// Unreadable is for what could not be read, and conflating the two would
	// make a complete inventory report as incomplete.
	Notes []string `json:"notes,omitempty"`
}

// OSInfo is the distribution identity read from /etc/os-release.
type OSInfo struct {
	ID         string `json:"id,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
	// CPEName is the CPE_NAME field, e.g. "cpe:/o:suse:sles:15:sp5". It is the
	// precise product key a CSAF security feed joins on, where a distro's own
	// name for the release is exact and unambiguous in a way VERSION_ID is not.
	CPEName string `json:"cpe_name,omitempty"`

	// Ecosystem is the OSV ecosystem string, or empty with EcosystemError set.
	Ecosystem      string `json:"ecosystem,omitempty"`
	EcosystemError string `json:"ecosystem_error,omitempty"`
}

// Packages counts the OS packages the inventory found.
func (r *InventoryResult) Packages() int {
	n := 0
	for _, db := range r.Databases {
		n += len(db.Packages)
	}
	return n
}

// LanguagePackages counts the installed language distributions.
//
// It is kept apart from Packages rather than added to it because the two
// overlap -- the same files can be one deb and one PyPI distribution -- so a
// single total would be a number that counts some code twice and means nothing.
func (r *InventoryResult) LanguagePackages() int {
	n := 0
	for _, l := range r.Languages {
		n += len(l.Packages)
	}
	return n
}

// Inventory reads the OS package databases of an image or a rootfs.
//
// It deliberately does not require a subject: "what is in this tree" is a
// question worth answering on its own, and it is the one output that can be
// checked against `dpkg -l` or `rpm -qa` run inside the same tree.
func Inventory(ctx context.Context, opts Options) ([]*InventoryResult, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	// Check --repo first: a user who passed it gets told why it does not
	// apply, rather than being told to pass a flag they deliberately did not.
	if opts.Repo != "" {
		return nil, errors.New("--format inventory reads a filesystem's package databases; it does not apply to --repo")
	}
	if err := opts.checkTarget(); err != nil {
		return nil, err
	}
	logf := opts.Logf

	// --rpm and --sbom have no tree, and opening the empty one would only lead
	// every reader below to correctly report that it found nothing.
	if len(opts.RPM) > 0 {
		res, err := rpmInventory(ctx, opts)
		if err != nil {
			return nil, err
		}
		return []*InventoryResult{res}, nil
	}
	if opts.SBOM != "" {
		res, err := sbomInventory(opts)
		if err != nil {
			return nil, err
		}
		return []*InventoryResult{res}, nil
	}

	processTree := func(opts Options) (*InventoryResult, error) {
		img, cleanup, err := openTree(ctx, &opts)
		if err != nil {
			return nil, err
		}
		defer cleanup()

		res := &InventoryResult{Target: img.Ref, Mode: opts.mode()}
		res.OS = readOSInfo(img.FS, logf)

		dbs, err := pkgdb.Read(img.FS)
		if err != nil {
			// A detected-but-unreadable database is fatal here. Printing the
			// databases that did parse would render as a complete inventory of the
			// image, and every package in the one that failed would look absent.
			return nil, fmt.Errorf("reading package databases: %w", err)
		}
		res.Databases = dbs

		if len(dbs) == 0 {
			logf("  ! no dpkg, apk or rpm database found in %s", img.Ref)
		}
		for _, db := range dbs {
			logf("  %s: %d packages from %s", db.Format, len(db.Packages), db.DB)
		}

		langs, err := langdb.Scan(img.FS)
		if err != nil {
			// Same reasoning as above: a site-packages directory that was found and
			// could not be listed would render as an image with no Python in it.
			return nil, fmt.Errorf("reading language packages: %w", err)
		}
		res.Languages = langs

		for _, l := range langs {
			logf("  %s: %d packages from %d %s", l.Format, len(l.Packages), len(l.Roots), rootWord(l.Format))
			for _, m := range l.Unreadable {
				// Not fatal, but never silent: a distribution whose manifest would
				// not parse is one whose absence must not be asserted later.
				logf("    ! unreadable manifest %s", m)
			}
			for _, m := range l.Unidentified {
				logf("    ! archive declares no coordinates %s", m.Path)
			}
			for _, m := range l.Platform {
				logf("    - runtime jar, not a queryable artifact: %s", m)
			}
		}

		// Last, because it accumulates across both scans above.
		if u := img.FS.Unreadable(); u.Any() {
			res.Unreadable = &u
			logf("  ! %d path(s) could not be read; this inventory does not account for them", u.Count)
			for _, m := range u.Paths {
				logf("    ! %s", m)
			}
		}
		return res, nil
	}

	if opts.mode() != "image" {
		ires, err := processTree(opts)
		if err != nil {
			return nil, err
		}
		return []*InventoryResult{ires}, nil
	}

	var (
		results []*InventoryResult
		errs    error
	)
	targets, err := opts.imageTargets()
	if err != nil {
		return nil, err
	}
	for _, target := range targets {
		clone := opts
		clone.Image = target
		res, err := processTree(clone)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", target, err))
			continue
		}
		results = append(results, res)
	}
	return results, errs
}

// rpmInventory lists what --rpm resolved to, which is the cheapest way to
// check what a scan is about to be run against.
//
// It reports no Languages: an rpm header lists the files the package would
// install and nothing about their contents, so the site-packages and
// node_modules a python3-yaml rpm would create are not knowable from it. An
// empty Languages list here means "not looked for", and saying otherwise by
// running the scanner over an empty directory would mean "looked for and not
// there".
func rpmInventory(ctx context.Context, opts Options) (*InventoryResult, error) {
	logf := opts.Logf
	rpms, err := readRPMs(ctx, &opts, false)
	if err != nil {
		return nil, err
	}

	res := &InventoryResult{
		Target:    strings.Join(opts.RPM, ", "),
		Mode:      opts.mode(),
		Databases: ospkg.SuppliedResults(opts.rpmPackages),
	}

	// An ecosystem that cannot be derived is recorded, not fatal. The whole
	// point of this output is to be able to see what a scan would use before
	// running one, and that includes seeing that it would not have an
	// ecosystem to query with.
	eco, distro, err := ospkg.SuppliedIdentity(opts.rpmPackages, opts.OSVEcosystem)
	res.OS = &OSInfo{ID: distro, Ecosystem: eco}
	if err != nil {
		res.OS.EcosystemError = err.Error()
		logf("  ! %v", err)
	}
	if len(opts.rpmPackages) > 0 {
		res.OS.PrettyName = opts.rpmPackages[0].Meta.Distribution
	}

	for _, db := range res.Databases {
		logf("  %s: %d packages from %s", db.Format, len(db.Packages), db.DB)
	}
	res.Unreadable = noteRPMFailures(res.Unreadable, rpms, logf)
	return res, nil
}

// sbomInventory lists what --sbom resolved the document to.
//
// This is the output worth having before a scan, and more so here than
// anywhere else: the whole risk of scanning a bill of materials is that a
// component was read under a name OSV has no records for, and this is where
// that is visible -- the queried names beside the ones the document wrote.
func sbomInventory(opts Options) (*InventoryResult, error) {
	logf := opts.Logf
	bom, err := readSBOM(&opts)
	if err != nil {
		return nil, err
	}

	res := &InventoryResult{
		Target:    opts.SBOM,
		Mode:      opts.mode(),
		Databases: ospkg.SuppliedResults(opts.sbomOS),
	}

	// An ecosystem that cannot be derived is recorded, not fatal -- the point
	// of this output is to see that a scan would have had nothing to query
	// with, before running one. Skipped when the document named no OS package
	// at all, where "no ecosystem" is not a problem to report.
	if len(opts.sbomOS) > 0 {
		eco, distro, err := ospkg.SuppliedIdentity(opts.sbomOS, opts.OSVEcosystem)
		res.OS = &OSInfo{ID: distro, Ecosystem: eco}
		if err != nil {
			res.OS.EcosystemError = err.Error()
			logf("  ! %v", err)
		}
	}

	for _, l := range []langdb.Result{
		{Format: langdb.FormatPyPI, Packages: opts.sbomPyPI, Roots: []string{opts.SBOM}},
		{Format: langdb.FormatNPM, Packages: opts.sbomNPM, Roots: []string{opts.SBOM}},
		{Format: langdb.FormatMaven, Packages: opts.sbomMaven, Roots: []string{opts.SBOM}},
	} {
		if len(l.Packages) > 0 {
			res.Languages = append(res.Languages, l)
		}
	}

	// Go has no column here, because this output is package databases and
	// installed distributions and a Go module is neither -- image mode reads
	// them out of binaries and does not list them either. Said rather than
	// dropped: a document whose Go modules simply vanished from the inventory
	// would read as a document that had none.
	if len(opts.sbomGo) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%d Go module(s) in this document are not listed above: this output covers package "+
				"databases and installed distributions, and Go's inventory is neither. They are scanned.",
			len(opts.sbomGo)))
	}

	for _, db := range res.Databases {
		logf("  %s: %d packages from %s", db.Format, len(db.Packages), db.DB)
	}
	res.Unreadable = noteSBOMFailures(res.Unreadable, bom, logf)
	return res, nil
}

// rootWord names what a language's roots are, for log lines.
func rootWord(f langdb.Format) string {
	switch f {
	case langdb.FormatNPM:
		return "node_modules trees"
	case langdb.FormatMaven:
		return "archives"
	default:
		return "site-packages directories"
	}
}

// readOSInfo parses /etc/os-release and maps it to an OSV ecosystem.
//
// Neither failure stops an inventory -- listing packages is useful without an
// ecosystem name, and a scratch image with a copied-in dpkg database is a real
// thing. Both are reported, because an unnamed ecosystem means the OS plugin
// will have nothing to query and must say so rather than find nothing.
func readOSInfo(fsys target.RootFS, logf func(string, ...any)) *OSInfo {
	f, err := fsys.Open("/etc/os-release")
	if err != nil {
		// Debian and Alpine both symlink /etc/os-release to this.
		f, err = fsys.Open("/usr/lib/os-release")
	}
	if err != nil {
		logf("  ! no /etc/os-release; the OS ecosystem cannot be identified")
		return nil
	}
	defer f.Close()

	rel, err := osv.ParseOSRelease(f)
	if err != nil {
		logf("  ! %v", err)
		return nil
	}

	info := &OSInfo{ID: rel.ID, VersionID: rel.VersionID, PrettyName: rel.PrettyName, CPEName: rel.CPEName}
	eco, err := rel.Ecosystem()
	if err != nil {
		info.EcosystemError = err.Error()
		logf("  ! %v", err)
		return info
	}
	info.Ecosystem = eco
	return info
}
