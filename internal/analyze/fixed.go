package analyze

import (
	"strings"

	"golang.org/x/mod/semver"

	"github.com/cwayne18/vexscan/internal/debver"
)

// fixCandidates is every version one advisory says it fixed one package in,
// together with the OSV ecosystem they were read from.
//
// The ecosystem travels with the versions because it is what decides whether
// they can be ordered, and the overlay cannot recover it later: Finding.
// Ecosystem is the plugin id ("os", "golang"), not the OSV ecosystem string
// ("Debian:12", "Go"), and one plugin answers for several of the latter.
type fixCandidates struct {
	ecosystem string
	versions  []string
}

// fixedOverlay labels each finding with the version its advisory's patch lands
// in, in place. It runs beside severityOverlay for the same reason: a plugin
// answers a presence question and never sees the affected ranges the fix lives
// in, so the join has to happen where the advisories are.
//
// The join is on advisory id and then on package name. The package key is the
// finding's Package -- the source name OSV files its affected entry against,
// which is why two binaries built from one source (libgcc-s1, libstdc++6 from
// gcc-12) both resolve to the same fixed source version. A finding whose
// advisory published no fix for its package keeps an empty FixedVersion, which
// the renderer shows as "no fix" rather than a blank.
//
// Where the advisory published several fixes the finding keeps all of them, so
// the report can disclose what was not chosen. See pickFix for the choosing.
func fixedOverlay(findings []Finding, fixed map[string]map[string]fixCandidates) {
	for i := range findings {
		f := &findings[i]
		for _, key := range []string{f.CVE, f.ID, f.GoID} {
			if key == "" {
				continue
			}
			byPkg, ok := fixed[key]
			if !ok {
				continue
			}
			c, ok := byPkg[f.Package]
			if !ok {
				c, ok = byPkg[f.Component()]
			}
			if !ok {
				continue
			}
			f.FixedVersion = pickFix(c.ecosystem, f.Version, c.versions)
			if len(c.versions) > 1 {
				f.FixedVersions = append([]string(nil), c.versions...)
			}
			break
		}
	}
}

// pickFix chooses the upgrade target out of everything one advisory says it
// fixed a package in.
//
// Several fixes is not a versioning quirk, it is what a vendor maintaining more
// than one branch publishes: GO-2022-0623 fixed Vault in 1.5.9, 1.6.5 and
// 1.7.2, and 22 of the 110 records for that module read the same way. They are
// alternatives. The answer for someone on 1.5.4 is 1.5.9 -- the lowest fix that
// is actually an upgrade -- and naming 1.7.2 instead would prescribe two major
// versions of unrelated change to close one advisory.
//
// Where the ecosystem cannot be ordered the last published version is kept,
// which is what this tool did for every ecosystem before it kept the list. That
// is deliberately the conservative direction: an upgrade target that is too
// high is a bigger change than necessary, while one that is too low is a fix
// that does not fix anything and a report that says the problem is closed when
// it is open. The candidates it did not choose are disclosed either way, so the
// overshoot is visible rather than silent.
//
// An installed version at or above every published fix falls back to the
// highest, because there is nothing to pick: the finding exists, so something
// disagrees with the arithmetic -- a backport, a distro rebuild, an epoch -- and
// the newest fix is the least wrong thing to name.
func pickFix(ecosystem, installed string, candidates []string) string {
	switch len(candidates) {
	case 0:
		return ""
	case 1:
		return candidates[0]
	}
	order := fixOrder(ecosystem)
	if order == nil {
		return candidates[len(candidates)-1]
	}

	var usable []string
	for _, c := range candidates {
		if order.valid(c) {
			usable = append(usable, c)
		}
	}
	if len(usable) == 0 {
		return candidates[len(candidates)-1]
	}
	highest := usable[0]
	for _, c := range usable[1:] {
		if order.compare(c, highest) > 0 {
			highest = c
		}
	}
	if installed == "" || !order.valid(installed) {
		return highest
	}

	lowest := ""
	for _, c := range usable {
		if order.compare(c, installed) <= 0 {
			continue
		}
		if lowest == "" || order.compare(c, lowest) < 0 {
			lowest = c
		}
	}
	if lowest == "" {
		return highest
	}
	return lowest
}

// versionOrder is a total order over an ecosystem's version strings, plus the
// test for whether a given string is one it can order at all.
type versionOrder struct {
	valid   func(string) bool
	compare func(a, b string) int
}

// fixOrder returns the ordering for an OSV ecosystem, or nil when this tool has
// no rules that order it.
//
// The omissions are the point, because the cost of the two answers is not
// symmetric: declining to order costs an upgrade target that may be higher than
// needed, while ordering with the wrong rules costs one that is too low, and a
// version that does not contain the fix reported as the version that does.
//
// PyPI is absent for exactly that reason. PEP 440 sorts "1.0rc1" before "1.0"
// and semver sorts it after, so scoring a Python fix with semver would invert
// the pair silently. The RPM distros are absent because rpmvercmp is not dpkg's
// verrevcmp however similar the two look -- it has no epoch-less comparison and
// treats "~" differently. Maven has no total order this tool implements. Alpine
// is close to dpkg but not it. Each of those keeps today's behaviour, which is
// correct in the single-fix case that covers nearly all of them.
func fixOrder(ecosystem string) *versionOrder {
	family, _, _ := strings.Cut(ecosystem, ":")
	switch family {
	case "Debian", "Ubuntu":
		// dpkg's own rules, verified against verrevcmp in internal/debver.
		// Compare is total over arbitrary strings the way dpkg is, so there is
		// nothing it cannot order.
		return &versionOrder{
			valid:   func(string) bool { return true },
			compare: debver.Compare,
		}
	case "Go", "npm":
		// Go module versions are semver by definition and npm requires it of
		// every published package. Both databases write them without the "v",
		// which x/mod/semver needs, and both can still carry something semver
		// rejects -- a Go pseudo-version stub, an npm tag -- so validity is
		// checked rather than assumed.
		return &versionOrder{
			valid:   func(v string) bool { return semver.IsValid(semverish(v)) },
			compare: func(a, b string) int { return semver.Compare(semverish(a), semverish(b)) },
		}
	}
	return nil
}

// semverish prefixes the "v" that x/mod/semver requires and OSV does not write.
func semverish(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
