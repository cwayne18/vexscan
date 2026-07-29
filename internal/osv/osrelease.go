package osv

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Release is the subset of /etc/os-release needed to name an OSV ecosystem.
type Release struct {
	ID              string   // ID=
	IDLike          []string // ID_LIKE=
	Version         string   // VERSION=
	VersionID       string   // VERSION_ID=
	VersionCodename string   // VERSION_CODENAME=
	PrettyName      string   // PRETTY_NAME=
	CPEName         string   // CPE_NAME=
}

// ErrUnknownDistro is returned by Release.Ecosystem when the distribution has
// no entry in the mapping table. It is deliberately an error and never an
// empty string: a missing ecosystem must stop the scan, because an OSV query
// with no ecosystem finds nothing and reads exactly like a clean image.
var ErrUnknownDistro = errors.New("no OSV ecosystem is known for this distribution")

// ErrAmbiguousDistro is returned when OSV does carry the distribution, but the
// ecosystem string depends on something os-release does not record -- SUSE's
// support phase, currently. Like ErrUnknownDistro this stops the scan; the
// caller is expected to offer an explicit override.
var ErrAmbiguousDistro = errors.New("this distribution's OSV ecosystem cannot be determined from os-release")

// ParseOSRelease reads the os-release(5) key=value format.
func ParseOSRelease(r io.Reader) (Release, error) {
	var rel Release
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = unquote(value)
		switch strings.TrimSpace(key) {
		case "ID":
			rel.ID = value
		case "ID_LIKE":
			rel.IDLike = strings.Fields(value)
		case "VERSION":
			rel.Version = value
		case "VERSION_ID":
			rel.VersionID = value
		case "VERSION_CODENAME":
			rel.VersionCodename = value
		case "PRETTY_NAME":
			rel.PrettyName = value
		case "CPE_NAME":
			rel.CPEName = value
		}
	}
	if err := sc.Err(); err != nil {
		return Release{}, fmt.Errorf("osv: reading os-release: %w", err)
	}
	if rel.ID == "" {
		return rel, errors.New("osv: os-release has no ID field")
	}
	return rel, nil
}

// Ecosystem returns the OSV ecosystem string for this release.
//
// The strings below were verified against the live api.osv.dev rather than
// read off the schema, because the API validates them asymmetrically: the
// family name is checked -- a misspelled "Debain:12" is rejected with HTTP 400
// and {"code":3,"message":"invalid ecosystem"} -- but the version suffix is
// not. "Debian:99" answers HTTP 200 with an empty result, indistinguishable
// from a clean image. That asymmetry is why this is a table with tests rather
// than a format string, and why an unrecognized distribution is an error.
//
// The suffix rules are not uniform and none of them are guessable:
//
//	Debian          major only            Debian:12          (bare "Debian" over-matches every release)
//	Ubuntu          ":LTS" only when LTS  Ubuntu:24.04:LTS   ("Ubuntu:24.10" for a non-LTS release)
//	Alpine          "v" prefix, no patch  Alpine:v3.19       ("Alpine:3.19" finds nothing)
//	Azure Linux     major only            Azure Linux:3      ("Azure Linux:3.0" finds nothing)
//	openEuler       "-LTS" when LTS       openEuler:24.03-LTS
//	openSUSE        product name from PRETTY_NAME
//	Red Hat         bare -- see below
//	SLE             not derivable -- see below
func (rel Release) Ecosystem() (string, error) {
	switch id := strings.ToLower(strings.TrimSpace(rel.ID)); id {
	case "debian":
		return rel.versioned("Debian", major)

	case "ubuntu":
		v, err := rel.require(majorMinor)
		if err != nil {
			return "", err
		}
		// OSV carries an ":LTS" suffix for LTS releases and none for interim
		// ones. os-release states which it is in VERSION/PRETTY_NAME.
		if rel.isLTS() {
			return "Ubuntu:" + v + ":LTS", nil
		}
		return "Ubuntu:" + v, nil

	case "alpine":
		v, err := rel.require(majorMinor)
		if err != nil {
			return "", err
		}
		return "Alpine:v" + v, nil

	case "rhel", "redhat":
		// OSV spells RHEL as "Red Hat:<cpe-tail>", e.g.
		// "Red Hat:enterprise_linux:9::appstream". CPE_NAME gives exactly one
		// of those tails -- usually "::baseos" -- while a real image installs
		// packages from several repositories, so keying on it would silently
		// drop every appstream advisory. The bare family name matches records
		// from all RHEL versions and repositories: over-inclusive across minor
		// versions, but over-inclusion only adds candidates for the
		// deterministic tests to rule out, whereas under-inclusion is a silent
		// false negative. CPEName is retained so a later pass can refine this.
		return "Red Hat", nil

	case "rocky":
		return rel.versioned("Rocky Linux", major)
	case "almalinux":
		return rel.versioned("AlmaLinux", major)
	case "mageia":
		return rel.versioned("Mageia", major)
	case "alpaquita":
		return rel.versioned("Alpaquita", major)

	case "mariner", "azurelinux":
		return rel.versioned("Azure Linux", major)

	case "openeuler":
		v, err := rel.require(majorMinor)
		if err != nil {
			return "", err
		}
		if rel.isLTS() {
			return "openEuler:" + v + "-LTS", nil
		}
		return "openEuler:" + v, nil

	case "wolfi":
		return "Wolfi", nil
	case "chainguard":
		return "Chainguard", nil
	case "minimos":
		return "MinimOS", nil

	case "opensuse-tumbleweed":
		return "openSUSE:Tumbleweed", nil

	case "opensuse-leap", "opensuse":
		if eco, ok := suseFromPrettyName(rel.PrettyName); ok {
			return eco, nil
		}
		v, err := rel.require(majorMinor)
		if err != nil {
			return "", err
		}
		return "openSUSE:Leap " + v, nil

	case "sles", "sled", "sles_sap", "sle-micro", "sle_hpc":
		// SUSE keys enterprise products on the marketing name *including the
		// support-phase suffix*: glibc advisories for SLES 15 SP4 are filed
		// under "SUSE:Linux Enterprise Server 15 SP4-LTSS", and the unsuffixed
		// "SUSE:Linux Enterprise Server 15 SP4" returns nothing at all. The
		// suffix follows the product's lifecycle date and subscription, not
		// anything recorded in os-release, so it cannot be derived here.
		//
		// Guessing the base name would answer "no advisories" for every SLE
		// image past general support -- which is most of the images anyone
		// scans. Refusing is the only honest option; --osv-ecosystem lets a
		// user who knows their support phase name it outright.
		return "", fmt.Errorf("osv: %w: %s (%q) -- SUSE keys advisories on the support phase "+
			"(e.g. %q, %q), which os-release does not record; name it with --osv-ecosystem",
			ErrAmbiguousDistro, rel.ID, rel.PrettyName,
			"SUSE:Linux Enterprise Server 15 SP4-LTSS", "SUSE:Linux Enterprise Micro 5.5")

	default:
		return "", fmt.Errorf("osv: %w: ID=%q (known: %s)", ErrUnknownDistro, rel.ID, strings.Join(KnownDistroIDs(), ", "))
	}
}

// KnownDistroIDs lists the os-release ID values Ecosystem can map, for error
// messages.
func KnownDistroIDs() []string {
	ids := []string{
		"almalinux", "alpaquita", "alpine", "azurelinux", "chainguard",
		"debian", "mageia", "mariner", "minimos", "openeuler", "opensuse",
		"opensuse-leap", "opensuse-tumbleweed", "redhat", "rhel", "rocky",
		"sle-micro", "sle_hpc", "sled", "sles", "sles_sap", "ubuntu", "wolfi",
	}
	sort.Strings(ids)
	return ids
}

// Families lists the OSV ecosystem families Ecosystem can produce, without
// their version suffixes. It is what --ecosystem accepts for OS packages, and
// it lives beside the mapping so the two cannot drift apart.
func Families() []string {
	return []string{
		"AlmaLinux", "Alpaquita", "Alpine", "Azure Linux", "Chainguard",
		"Debian", "Mageia", "MinimOS", "Red Hat", "Rocky Linux", "SUSE",
		"Ubuntu", "Wolfi", "openEuler", "openSUSE",
	}
}

// suseFromPrettyName turns "SUSE Linux Enterprise Server 15 SP5" into
// "SUSE:Linux Enterprise Server 15 SP5" and "openSUSE Leap 15.6" into
// "openSUSE:Leap 15.6" -- the vendor prefix becomes the ecosystem family and
// the rest is the product name verbatim.
func suseFromPrettyName(pretty string) (string, bool) {
	pretty = strings.TrimSpace(pretty)
	for _, vendor := range []string{"openSUSE", "SUSE"} {
		rest, ok := strings.CutPrefix(pretty, vendor+" ")
		if !ok {
			continue
		}
		if rest = strings.TrimSpace(rest); rest != "" {
			return vendor + ":" + rest, true
		}
	}
	return "", false
}

func (rel Release) versioned(family string, trim func(string) string) (string, error) {
	v, err := rel.require(trim)
	if err != nil {
		return "", err
	}
	return family + ":" + v, nil
}

// require applies trim to VERSION_ID and refuses an empty result. Rolling and
// unreleased images (Debian sid, for instance) ship no VERSION_ID at all;
// there is no ecosystem string for them, and inventing one from the codename
// would query a release the image is not.
func (rel Release) require(trim func(string) string) (string, error) {
	v := trim(strings.TrimSpace(rel.VersionID))
	if v == "" {
		return "", fmt.Errorf("osv: %s: os-release has no usable VERSION_ID (codename %q)", rel.ID, rel.VersionCodename)
	}
	return v, nil
}

func (rel Release) isLTS() bool {
	return strings.Contains(strings.ToUpper(rel.Version+" "+rel.PrettyName), "LTS")
}

// major returns the first dot-separated component of a version.
func major(v string) string {
	return field(v, 1)
}

// majorMinor returns the first two dot-separated components of a version, so
// Alpine's "3.19.1" becomes "3.19".
func majorMinor(v string) string {
	return field(v, 2)
}

func field(v string, n int) string {
	parts := strings.Split(v, ".")
	if len(parts) > n {
		parts = parts[:n]
	}
	return strings.Join(parts, ".")
}

// unquote strips the shell quoting os-release permits around a value.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) < 2 {
		return v
	}
	q := v[0]
	if (q != '"' && q != '\'') || v[len(v)-1] != q {
		return v
	}
	v = v[1 : len(v)-1]
	if q == '\'' {
		return v
	}

	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			switch v[i+1] {
			case '"', '\\', '$', '`':
				i++
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
