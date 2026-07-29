package analyze

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cwayne18/vexscan/internal/image"
	"github.com/cwayne18/vexscan/internal/langdb"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/pkgdb"
	"github.com/cwayne18/vexscan/internal/target"
)

// InventoryResult is what an image's package databases say is installed.
//
// This is the raw material the OS ecosystem plugin works from, exposed on its
// own because it is checkable: a user who suspects a finding is wrong can see
// exactly which database row it came from, and the ecosystem string that will
// be used to query OSV before any query is made.
type InventoryResult struct {
	Target    string         `json:"target"`
	Mode      string         `json:"mode"` // always "image"
	OS        *OSInfo        `json:"os,omitempty"`
	Databases []pkgdb.Result `json:"databases"`

	// Languages are the installed distributions of the language ecosystems
	// that ship inside images: Python's site-packages, Node's node_modules.
	// They are kept separate from Databases because they overlap: Debian's
	// python3-yaml deb installs the same files a PyPI inventory reports under
	// "pyyaml", and merging the two would hide that both advisory namespaces
	// apply.
	Languages []langdb.Result `json:"languages,omitempty"`
}

// OSInfo is the distribution identity read from /etc/os-release.
type OSInfo struct {
	ID         string `json:"id,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`

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

// Inventory extracts an image and reads its OS package databases.
//
// It deliberately does not require a subject: "what is in this image" is a
// question worth answering on its own, and it is the one output that can be
// checked against `dpkg -l` or `rpm -qa` inside the same image.
func Inventory(ctx context.Context, opts Options) (*InventoryResult, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	// Check --repo first: a user who passed it gets told why it does not
	// apply, rather than being told to pass a flag they deliberately did not.
	if opts.Repo != "" {
		return nil, errors.New("--format inventory reads an image's package databases; it does not apply to --repo")
	}
	if opts.Image == "" {
		return nil, errors.New("--format inventory needs --image")
	}
	if opts.OS == "" {
		opts.OS = "linux"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	logf := opts.Logf

	dest, err := os.MkdirTemp("", "vexscan-fs-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dest)

	logf("Extracting %s (%s/%s)...", opts.Image, opts.OS, opts.Arch)
	ex := image.NewExtractor()
	ex.OS, ex.Arch = opts.OS, opts.Arch
	img, err := ex.Extract(ctx, opts.Image, dest)
	if err != nil {
		return nil, fmt.Errorf("extract image: %w", err)
	}

	res := &InventoryResult{Target: opts.Image, Mode: "image"}
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
		logf("  ! no dpkg, apk or rpm database found in %s", opts.Image)
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
	}
	return res, nil
}

// rootWord names what a language's roots are, for log lines.
func rootWord(f langdb.Format) string {
	if f == langdb.FormatNPM {
		return "node_modules trees"
	}
	return "site-packages directories"
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

	info := &OSInfo{ID: rel.ID, VersionID: rel.VersionID, PrettyName: rel.PrettyName}
	eco, err := rel.Ecosystem()
	if err != nil {
		info.EcosystemError = err.Error()
		logf("  ! %v", err)
		return info
	}
	info.Ecosystem = eco
	return info
}
