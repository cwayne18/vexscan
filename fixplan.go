package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/debver"
)

// The fix plan.
//
// --format text answers "what is wrong with this image". --format fixplan
// answers the next question, the one a reader asks once the table is 150 rows
// long: "what do I do about it". It reorganises the same affected findings by
// the action that clears them -- upgrade this package to that version -- so a
// wall of per-CVE rows becomes a short list of upgrades, each annotated with
// how many advisories it clears and the worst severity among them.
//
// It is a view, not a filter. Every affected finding that has no fix is still
// listed at the end, under its own heading, because a remediation plan that
// silently dropped the un-fixable rows would be the most dangerous kind: it
// would read as complete. The population is exactly the one the text summary's
// remediation line counts -- affected, and not already answered by a published
// VEX statement -- so the two never disagree.
func renderFixPlan(results []*analyze.Result, o renderOpts) string {
	var b strings.Builder
	for _, res := range results {
		writeHeader(&b, res, o.pal)

		if len(res.Findings) == 0 {
			writeNoFindings(&b, res)
			continue
		}

		// Same population as writeRemediation: affected, not already vexed. Split
		// by whether a fix exists so the actionable rows lead and the rest are
		// still accounted for.
		var fixable, noFix []analyze.Finding
		var s fixSummary
		for _, f := range res.Findings {
			if !f.Affected() {
				if f.Status != analyze.StatusNotPresent && f.Status != analyze.StatusNotInPath {
					s.undetermined++
				}
				continue
			}
			if alreadyVexed(f) {
				s.vexed++
				continue
			}
			if f.FixedVersion != "" {
				fixable = append(fixable, f)
			} else {
				noFix = append(noFix, f)
			}
		}

		plan := groupUpgrades(fixable, dpkgPlugins(res))
		s.fixable, s.noFix = len(fixable), len(noFix)
		s.upgrades, s.cleared = len(plan), uniqueAdvisories(fixable)

		writeFixSummary(&b, s)
		if s.fixable+s.noFix == 0 {
			continue
		}
		b.WriteString("\n")

		if len(plan) > 0 {
			writeUpgradePlan(&b, plan, o.pal)
		}
		if len(noFix) > 0 {
			writeNoFix(&b, noFix, o.pal)
		}

		// The footer is the fix plan's own, not renderText's. writeFooter repeats
		// the main report's summary and its section index, which here would name
		// AFFECTED and RULED OUT under a document whose only headings are UPGRADE
		// and NO FIX YET -- an index of sections the reader cannot find. The
		// caveats still repeat verbatim, because that promise is about the scan
		// and not about the view.
		if strings.Count(b.String(), "\n") > footerThreshold {
			writeCaveats(&b, res, o.pal)
			writeFixSummary(&b, s)
		}
	}
	return b.String()
}

// fixSummary is the fix plan's count of itself, computed once and printed at
// both ends of the report so the header and the footer cannot disagree.
type fixSummary struct {
	fixable      int // affected findings with a published fix
	noFix        int // affected findings without one
	upgrades     int // rows in the UPGRADE table
	cleared      int // distinct advisories those upgrades clear
	vexed        int // affected, but already answered by a vendor
	undetermined int // neither affected nor ruled out
}

// writeFixSummary prints what the plan covers and, as importantly, what it does
// not.
//
// Every count names its unit. An earlier cut read "clears 86 advisories; 154
// with no fix yet", where the first number is advisories and the second is
// findings -- two units in one sentence, presented as if they were comparable.
// The vexed and undetermined lines are here for the same reason the NO FIX YET
// table is: a remediation view that silently omits rows is the one kind of
// report whose shortness reads as good news.
func writeFixSummary(b *strings.Builder, s fixSummary) {
	total := s.fixable + s.noFix
	switch {
	case total == 0:
		b.WriteString("  no affected findings to fix.\n")
	default:
		fmt.Fprintf(b, "  %d of %d affected findings have a fix.\n", s.fixable, total)
	}
	switch {
	case s.upgrades > 0:
		line := fmt.Sprintf("  upgrading %d %s clears %d %s",
			s.upgrades, plural(s.upgrades, "package", "packages"),
			s.cleared, plural(s.cleared, "advisory", "advisories"))
		if s.noFix > 0 {
			line += fmt.Sprintf("; %d %s no fix yet",
				s.noFix, plural(s.noFix, "finding has", "findings have"))
		}
		b.WriteString(line + ".\n")
	case s.noFix > 0:
		fmt.Fprintf(b, "  no published fixes yet for any of the %d affected findings.\n", s.noFix)
	}
	if s.vexed > 0 {
		fmt.Fprintf(b, "  (%d already answered by a vendor VEX statement, so not planned for.)\n", s.vexed)
	}
	if s.undetermined > 0 {
		fmt.Fprintf(b, "  (%d undetermined finding(s) not shown; run the default report to review them.)\n", s.undetermined)
	}
}

// upgrade is one action: move a package from its installed version to the
// version that clears the vulnerabilities found on it. Several advisories
// usually collapse into one upgrade, which is the whole point of the view.
type upgrade struct {
	ecosystem  string
	pkg        string
	current    string
	fixedIn    string
	advisories map[string]bool
	topRank    int // cvss.Rank of the worst cleared finding; lower is worse
	topLabel   string
	kev        bool
}

// groupUpgrades collapses fixable findings into upgrade actions. For an
// ecosystem whose versions this tool can order -- Debian and Ubuntu, via
// dpkgPlugins -- every advisory on a package folds into a single row whose
// target is the newest fix of them all, because a distro point release is
// cumulative and installing the latest clears every earlier one. That is the
// difference between a plan that says "upgrade libc6 to 2.36-9+deb12u14 to
// clear 29 advisories" and one that lists the same package eight times, once
// per point release.
//
// For any other ecosystem the tool will not guess an order (a semver
// pre-release sorts the opposite way to a Debian revision, so one comparator
// cannot serve both), and findings stay split by their published fixed
// version -- correct, if less collapsed. Two binary packages built from one
// source stay separate rows either way: they are separate things to upgrade.
func groupUpgrades(findings []analyze.Finding, dpkg map[string]bool) []upgrade {
	index := map[string]*upgrade{}
	var order []*upgrade
	for _, f := range findings {
		pkg := f.Component()
		collapse := dpkg[f.Ecosystem]

		// When the versions are orderable, a package folds to one row and its
		// target is chosen below. When they are not, the published fixed
		// version is part of the key, so distinct targets stay distinct rows.
		key := f.Ecosystem + "\x00" + pkg + "\x00" + f.Version
		if !collapse {
			key += "\x00" + f.FixedVersion
		}

		u := index[key]
		if u == nil {
			u = &upgrade{
				ecosystem:  f.Ecosystem,
				pkg:        pkg,
				current:    f.Version,
				fixedIn:    f.FixedVersion,
				advisories: map[string]bool{},
				topRank:    99,
			}
			index[key] = u
			order = append(order, u)
		}
		if collapse && debver.Compare(f.FixedVersion, u.fixedIn) > 0 {
			// Newest fix wins: it supersedes every earlier one on this package.
			u.fixedIn = f.FixedVersion
		}
		u.advisories[shortAdvisory(f)] = true
		if r := cvss.Rank(displaySeverity(f)); r < u.topRank {
			u.topRank = r
			u.topLabel = displaySeverity(f)
		}
		if priorityBand(f) == bandKEV {
			u.kev = true
		}
	}

	plan := make([]upgrade, 0, len(order))
	for _, u := range order {
		plan = append(plan, *u)
	}
	// Worst first: known-exploited, then severity, then the biggest wins (an
	// upgrade that clears six advisories before one that clears one), then a
	// stable name order so the plan is diffable between runs.
	sort.SliceStable(plan, func(i, j int) bool {
		a, c := plan[i], plan[j]
		if a.kev != c.kev {
			return a.kev
		}
		if a.topRank != c.topRank {
			return a.topRank < c.topRank
		}
		if len(a.advisories) != len(c.advisories) {
			return len(a.advisories) > len(c.advisories)
		}
		if a.ecosystem != c.ecosystem {
			return a.ecosystem < c.ecosystem
		}
		return a.pkg < c.pkg
	})
	return plan
}

// dpkgPlugins reports which analyzer ids produced Debian-comparable versions,
// so groupUpgrades knows where it may fold a package to its newest fix. A
// plugin qualifies only when every OSV ecosystem it detected is a Debian or
// Ubuntu one; a mixed or unknown analyzer is left in the safe, un-collapsed
// path rather than compared with a rule that might not fit it.
func dpkgPlugins(res *analyze.Result) map[string]bool {
	out := map[string]bool{}
	for _, e := range res.Ecosystems {
		if len(e.Ecosystems) == 0 {
			continue
		}
		all := true
		for _, name := range e.Ecosystems {
			if !isDebianFamily(name) {
				all = false
				break
			}
		}
		if all {
			out[e.ID] = true
		}
	}
	return out
}

// isDebianFamily reports whether an OSV ecosystem string names a dpkg-based
// distribution, whose versions debver can order.
func isDebianFamily(ecosystem string) bool {
	family := ecosystem
	if i := strings.IndexByte(ecosystem, ':'); i >= 0 {
		family = ecosystem[:i]
	}
	return strings.EqualFold(family, "Debian") || strings.EqualFold(family, "Ubuntu")
}

// writeUpgradePlan prints the actionable table: one row per upgrade, worst
// first. The ECOSYSTEM and KEV columns earn their place the same way the main
// report's columns do -- ECOSYSTEM only when the plan spans more than one, KEV
// only when something in it is actually listed -- so a single-ecosystem image
// with no known-exploited flaws gets neither.
func writeUpgradePlan(b *strings.Builder, plan []upgrade, pal palette) {
	showEco := distinctEcosystems(plan) > 1
	showKEV := false
	for _, u := range plan {
		if u.kev {
			showKEV = true
			break
		}
	}

	header := []string{}
	if showEco {
		header = append(header, "ECOSYSTEM")
	}
	header = append(header, "PACKAGE", "CURRENT", "FIXED IN", "CLEARS", "SEVERITY")
	if showKEV {
		header = append(header, "KEV")
	}

	table := [][]string{header}
	for _, u := range plan {
		cells := []string{}
		if showEco {
			cells = append(cells, u.ecosystem)
		}
		cells = append(cells,
			truncate(u.pkg, colPackage),
			truncate(u.current, colVersion),
			truncate(u.fixedIn, colFixed),
			fmt.Sprintf("%d", len(u.advisories)),
			pal.severity(cvss.Display(u.topLabel)),
		)
		if showKEV {
			kev := ""
			if u.kev {
				kev = "yes"
			}
			cells = append(cells, kev)
		}
		table = append(table, cells)
	}

	fmt.Fprintf(b, "%s - apply these to clear the fixable findings\n",
		pal.heading(fmt.Sprintf("UPGRADE (%d)", len(plan))))
	writeTable(b, table)
	b.WriteString("\n")
}

// writeNoFix lists the affected findings no upgrade can clear, so the plan is
// honest about what it leaves behind. Same columns and sort as the main
// report's AFFECTED table, minus the FIXED IN column that would read "no fix"
// on every row.
func writeNoFix(b *strings.Builder, rows []analyze.Finding, pal palette) {
	sorted := make([]analyze.Finding, len(rows))
	copy(sorted, rows)
	sortForDisplay(sorted)

	showEPSS, showKEV := triageColumns(sorted)
	header := []string{"SEVERITY", "ADVISORY", "PACKAGE", "VERSION"}
	if showEPSS {
		header = append(header, "EPSS")
	}
	if showKEV {
		header = append(header, "KEV")
	}

	table := [][]string{header}
	for _, f := range sorted {
		cells := []string{
			pal.severity(displaySeverity(f)),
			shortAdvisory(f),
			truncate(f.Component(), colPackage),
			truncate(f.Version, colVersion),
		}
		if showEPSS {
			cells = append(cells, displayEPSS(f))
		}
		if showKEV {
			cells = append(cells, displayKEV(f))
		}
		table = append(table, cells)
	}

	fmt.Fprintf(b, "%s - affected, but no patch has shipped\n",
		pal.heading(fmt.Sprintf("NO FIX YET (%d)", len(sorted))))
	writeTable(b, table)
	b.WriteString("\n")
}

// uniqueAdvisories counts distinct advisories across a set of findings, which
// is the honest size of "how many things does this clear": one CVE seen on
// three packages is one advisory, not three.
func uniqueAdvisories(findings []analyze.Finding) int {
	seen := map[string]bool{}
	for _, f := range findings {
		seen[shortAdvisory(f)] = true
	}
	return len(seen)
}

// distinctEcosystems counts how many ecosystems a plan spans, which decides
// whether the ECOSYSTEM column earns its place.
func distinctEcosystems(plan []upgrade) int {
	seen := map[string]bool{}
	for _, u := range plan {
		seen[u.ecosystem] = true
	}
	return len(seen)
}

// plural picks the singular or plural word for a count. English only, and only
// the two forms these summaries need.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
