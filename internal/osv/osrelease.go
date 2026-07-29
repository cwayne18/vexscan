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
//	SLE             bare + ProductRelease narrowing -- see below
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
		// Bare, for the same reason Red Hat is bare, but the specifics are
		// worse. A SUSE affected-entry ecosystem is not the product a user
		// thinks they are running: on SLE 15 the base packages are filed
		// against the *module* that ships them, so gzip on SLES 15 SP7 lives
		// under "SUSE:Linux Enterprise Module for Basesystem 15 SP7". Neither
		// "SUSE:Linux Enterprise Server 15 SP7" nor its "-LTSS" spelling
		// carries that record -- both answer HTTP 200 with nothing. Which
		// module ships a given package is nowhere in os-release, so no product
		// string derived here could be right for more than a fraction of an
		// image's packages.
		//
		// The bare family matches every SUSE record whatever its product, so
		// the advisory is found at all; ProductRelease then narrows the answer
		// back to this image's release. Filtering after the query works
		// because the affected entry states its own product, while guessing
		// before the query has nothing to go on.
		return "SUSE", nil

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

// ProductRelease is the release token an affected entry must carry for this
// image, or "" when no narrowing applies.
//
// It exists for the bare-family ecosystems, where a query matches records from
// every product the vendor ships. That over-matching is not benign for SUSE:
// gzip is fixed at 1.10-150200.13.1 on SLE 15 and at 1.13-160000.3.1 on SLE
// 16, so a *fully patched* SLES 15 SP7 image still matches the SLE 16 record,
// and no amount of patching will ever clear it. Version comparison cannot sort
// this out, because the two products' version lines never converge.
//
// The token is the trailing version part of the product name -- "15 SP7" for
// SLES 15 SP7, "5.5" for SLE Micro 5.5 -- which is the one component every
// spelling of a product shares, module and support-phase suffix included.
func (rel Release) ProductRelease() string {
	switch strings.ToLower(strings.TrimSpace(rel.ID)) {
	case "sles", "sled", "sles_sap", "sle-micro", "sle_hpc":
	default:
		return ""
	}
	if tok := releaseToken(rel.PrettyName); tok != "" {
		return tok
	}
	// PRETTY_NAME is absent or unparseable. VERSION_ID is "15.7" for SLES 15
	// SP7 and "5.5" for SLE Micro 5.5 -- the same number, two spellings -- and
	// only the SP-era enterprise products (12 and 15) use the SP form.
	v := strings.TrimSpace(rel.VersionID)
	maj, min, ok := strings.Cut(v, ".")
	if !ok || min == "" {
		return v
	}
	if maj == "12" || maj == "15" {
		return maj + " SP" + min
	}
	return v
}

// releaseToken returns a product name's trailing version part: everything from
// the first digit-leading word onward, so "SUSE Linux Enterprise Server 15 SP7"
// yields "15 SP7".
func releaseToken(pretty string) string {
	fields := strings.Fields(pretty)
	for i, f := range fields {
		if f != "" && f[0] >= '0' && f[0] <= '9' {
			return strings.Join(fields[i:], " ")
		}
	}
	return ""
}

// MatchesProductRelease reports whether an OSV affected-entry ecosystem string
// names a product of the given release.
//
// eco is the full affected-entry spelling ("SUSE:Linux Enterprise Module for
// Basesystem 15 SP7"); release is a ProductRelease token ("15 SP7"). The
// support-phase suffix is dropped before comparing, because it distinguishes
// subscriptions rather than releases: an image running 15 SP4 is described by
// the "15 SP4-LTSS" records whether or not its owner holds that subscription.
func MatchesProductRelease(eco, release string) bool {
	if release == "" {
		return true
	}
	if _, rest, ok := strings.Cut(eco, ":"); ok {
		eco = rest
	}
	eco = strings.TrimSpace(eco)
	for _, phase := range supportPhases {
		if trimmed, ok := strings.CutSuffix(eco, phase); ok {
			eco = trimmed
			break
		}
	}
	return eco == release || strings.HasSuffix(eco, " "+release)
}

// supportPhases are the subscription suffixes SUSE appends to a product name.
var supportPhases = []string{"-LTSS", "-ESPOS", "-TERADATA"}

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
