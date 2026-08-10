package osv

import (
	"strings"

	"golang.org/x/mod/semver"

	"github.com/cwayne18/vexscan/internal/apkver"
	"github.com/cwayne18/vexscan/internal/debver"
	"github.com/cwayne18/vexscan/internal/mavenver"
	"github.com/cwayne18/vexscan/internal/pep440"
	"github.com/cwayne18/vexscan/internal/rpmver"
)

// Choosing a comparator is only ever needed offline. On the API path osv.dev
// decides which versions a range covers and vexscan reads the verdict; here
// there is nobody to ask, so the ordering has to be done against the rules the
// ecosystem actually uses. Getting that wrong in the strict direction drops a
// finding, so an ecosystem this file cannot order says so -- it returns nil --
// and the caller keeps the advisory and reports that it did.

// comparatorFor picks the ordering for a range.
//
// The range type decides first, because that is what it is for: a SEMVER range
// is semver wherever it appears, including in ecosystems whose own versions are
// not semver at all. Only an ECOSYSTEM range defers to the ecosystem.
func comparatorFor(rangeType, ecosystem string) comparator {
	if strings.EqualFold(rangeType, "SEMVER") {
		return semverCompare
	}
	return ecosystemComparator(ecosystem)
}

func ecosystemComparator(ecosystem string) comparator {
	switch family(ecosystem) {
	// dpkg's verrevcmp.
	case "Debian", "Ubuntu":
		return total(debver.Compare)

	// rpm's rpmvercmp. Compare, not CompareInstalledToFix: the fail-closed
	// epoch rule there is for the installed-versus-fix question, and this is
	// the different question of where a version sits in a published range.
	case "AlmaLinux", "Mageia", "openEuler", "openSUSE", "Oracle Linux",
		"Photon OS", "Red Hat", "Rocky Linux", "SUSE":
		return total(rpmver.Compare)

	// apk. Wolfi, Chainguard, MinimOS and Alpaquita are apk distributions and
	// state their fixed versions the same way Alpine does.
	case "Alpaquita", "Alpine", "Chainguard", "MinimOS", "Wolfi":
		return apkCompare

	// Ecosystems whose versions are semver by definition. Their records almost
	// always carry SEMVER ranges and are handled above; this is for the ones
	// that spell the same thing as an ECOSYSTEM range.
	case "crates.io", "GitHub Actions", "Go", "Hex", "npm", "Pub", "SwiftURL":
		return semverCompare

	// PEP 440, which semver would order wrongly rather than not at all: it has
	// no post-release, and no epoch.
	case "PyPI":
		return pep440Compare

	// Maven's ComparableVersion.
	case "Maven":
		return mavenCompare
	}

	// Everything else -- NuGet, RubyGems, Packagist, CRAN, Hackage, Bitnami --
	// has an ordering this repository does not implement. Every ecosystem
	// vexscan has a plugin for is above, so reaching this line means an SBOM or
	// a --osv-ecosystem override named something no scanner here inventories.
	//
	// The gap is also narrower than the list looks, because those databases
	// publish an explicit versions[] enumeration next to the range, and an
	// enumeration needs no comparator: versionAffected checks it first and its
	// answer is exact. What is left over is reported, not swallowed.
	return nil
}

// total wraps a comparator that orders any two strings. dpkg's and rpm's
// algorithms both do, by construction -- they consume arbitrary bytes and never
// fail -- so the only unorderable input is an empty one.
func total(cmp func(a, b string) int) comparator {
	return func(a, b string) (int, bool) {
		if a == "" || b == "" {
			return 0, false
		}
		return cmp(a, b), true
	}
}

func semverCompare(a, b string) (int, bool) {
	ca, cb := canonicalVersion(a), canonicalVersion(b)
	if !semver.IsValid(ca) || !semver.IsValid(cb) {
		return 0, false
	}
	return semver.Compare(ca, cb), true
}

func apkCompare(a, b string) (int, bool) {
	if !apkver.Valid(a) || !apkver.Valid(b) {
		return 0, false
	}
	return apkver.Compare(a, b), true
}

func pep440Compare(a, b string) (int, bool) {
	if !pep440.Valid(a) || !pep440.Valid(b) {
		return 0, false
	}
	return pep440.Compare(a, b), true
}

func mavenCompare(a, b string) (int, bool) {
	if !mavenver.Valid(a) || !mavenver.Valid(b) {
		return 0, false
	}
	return mavenver.Compare(a, b), true
}
