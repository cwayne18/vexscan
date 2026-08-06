package osv

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// This file corrects one specific defect in the Go vulnerability database.
//
// That database imports advisories from other feeds without curating them, and
// marks those records review_status: UNREVIEWED. When such a record's affected
// versions cannot be expressed as Go module versions -- which is the normal
// case for a v2+ project whose module path carries no /vN suffix, so that its
// only publishable versions are "+incompatible" ones -- it does not drop the
// fix boundaries. It publishes a standard range that is open at the top:
//
//	"ranges": [{"type":"SEMVER","events":[{"introduced":"0"}]}]
//
// and puts the versions it could not translate in a field of its own:
//
//	"ecosystem_specific": {"custom_ranges": [{"type":"ECOSYSTEM","events":[
//	  {"introduced":"2.10.11"},{"fixed":"2.11.13"},
//	  {"introduced":"2.12.0"}, {"fixed":"2.12.9"}]}]}
//
// An open range matches every version forever, so OSV answers "affected" for a
// release that fixed the flaw years ago. On rancher/rancher this is not a
// rounding error: 27 of the 28 advisories OSV returns for the image's own
// module at v2.15.0 are this shape, and every one of them was fixed before it.
//
// The correction reads the record's own custom_ranges. That is not overruling
// the advisory -- the open range is not a claim that every version is affected,
// it is the database saying it could not say -- and the precise answer is
// published in the same record by the same people.
//
// Dropping a finding is the direction this tool must never be wrong in, so the
// correction is deliberately narrow and never silent. Every one of these has to
// hold before a record is set aside:
//
//   - The query was for the Go ecosystem. custom_ranges is that database's
//     field; anywhere else its absence would mean nothing.
//   - The record says review_status: UNREVIEWED. A curated record's ranges are
//     the curated answer and are not second-guessed.
//   - The record's standard ranges for this package have no fixed and no
//     last_affected event: they are the degraded shape. A record with a real
//     upper bound was matched on its merits.
//   - custom_ranges exists for this package and every version in it parses.
//   - The queried version falls outside all of them.
//   - No other record in the same answer corroborates the claim. OSV returns
//     every record matching one package and version together, so if the
//     GHSA this one is aliased to also matched, it is right there in the
//     response -- and it disagrees, so the finding stands. That is what makes
//     this two independent sources rather than one record reinterpreted. A
//     record in the same degraded shape does not count: rancher/rancher really
//     does have pairs like GO-2024-2929 and GO-2024-3220, aliases of each
//     other, both UNREVIEWED, both open at the top. That is one importer
//     twice, not a second opinion.
//
// Anything set aside is reported: see Client.OnCorrection.

// unreviewedStatus is what the Go vulnerability database sets on a record it
// imported from another feed and did not curate.
const unreviewedStatus = "UNREVIEWED"

// Correction is an advisory OSV matched against a version that the advisory's
// own precise ranges exclude.
//
// It exists so the drop can be counted and shown. A scan that quietly returned
// 27 fewer findings than the database offered would be indistinguishable from a
// cleaner image, and that is the one reading this tool must never invite.
type Correction struct {
	// Advisory is the OSV id that was set aside.
	Advisory string
	// Package and Version are what was queried.
	Package string
	Version string
	// Ranges renders the record's own precise affected ranges, so a reader can
	// check the arithmetic that excluded them.
	Ranges string
}

func (c Correction) String() string {
	return fmt.Sprintf("%s does not apply to %s@%s (the record's own ranges are %s)",
		c.Advisory, c.Package, c.Version, c.Ranges)
}

// misranged reports whether v is a degraded Go-database record whose own
// precise ranges exonerate the queried version. others is every other record in
// the same OSV answer.
func misranged(ref Ref, v vuln, others []vuln) (Correction, bool) {
	if ref.Ecosystem != GoEcosystem || ref.Name == "" {
		return Correction{}, false
	}
	if !degraded(ref, v) {
		return Correction{}, false
	}
	version := normalizeVersion(ref)
	if !parsableVersion(version) {
		return Correction{}, false
	}

	// A record may carry several affected entries for one package, and the
	// question is asked of the package as a whole: membership of any custom
	// range means the version is affected.
	var custom []versionRange
	for _, aff := range v.Affected {
		if aff.Package.Name == ref.Name {
			custom = append(custom, aff.EcosystemSpecific.CustomRanges...)
		}
	}
	if len(custom) == 0 {
		return Correction{}, false
	}

	events, ok := rangeEvents(custom)
	if !ok || len(events) == 0 {
		return Correction{}, false
	}
	if affectedByEvents(version, events) {
		return Correction{}, false
	}
	if corroborated(ref, v, others) {
		return Correction{}, false
	}
	return Correction{
		Advisory: v.ID,
		Package:  ref.Name,
		Version:  ref.Version,
		Ranges:   describeEvents(events),
	}, true
}

// degraded reports whether v is an uncurated record whose standard ranges for
// this package say only that the flaw starts somewhere.
//
// That shape asserts nothing about where the flaw ends -- not "it is unfixed",
// which is a claim, but "this database could not put a boundary in Go module
// versions". Which is why such a record can be corrected against its own
// custom_ranges, and equally why it cannot corroborate anyone else's match.
func degraded(ref Ref, v vuln) bool {
	if !strings.EqualFold(strings.TrimSpace(v.DatabaseSpecific.ReviewStatus), unreviewedStatus) {
		return false
	}
	var (
		std   []versionRange
		names bool
	)
	for _, aff := range v.Affected {
		if aff.Package.Name != ref.Name {
			continue
		}
		names = true
		std = append(std, aff.Ranges...)
	}
	return names && !bounded(std)
}

// bounded reports whether any range closes at the top. A fixed or last_affected
// event is the database stating where the flaw stops, which is exactly what the
// degraded shape lacks.
func bounded(ranges []versionRange) bool {
	for _, r := range ranges {
		for _, ev := range r.Events {
			if ev.Fixed != "" || ev.LastAffected != "" {
				return true
			}
		}
	}
	return false
}

// event is one range boundary, flattened out of OSV's per-event object so the
// whole set can be sorted and swept in version order.
type event struct {
	version string
	kind    eventKind
}

type eventKind int

const (
	introduced eventKind = iota
	fixed
	lastAffected
)

// rangeEvents flattens and sorts every event across the given ranges. ok is
// false if any version in them is not comparable, in which case the caller must
// not act: a partial reading of the boundaries could place a version outside a
// range it is really inside.
func rangeEvents(ranges []versionRange) (events []event, ok bool) {
	for _, r := range ranges {
		for _, ev := range r.Events {
			for _, pair := range []struct {
				raw  string
				kind eventKind
			}{
				{ev.Introduced, introduced},
				{ev.Fixed, fixed},
				{ev.LastAffected, lastAffected},
			} {
				if pair.raw == "" {
					continue
				}
				if !parsableVersion(pair.raw) {
					return nil, false
				}
				events = append(events, event{version: pair.raw, kind: pair.kind})
			}
		}
	}
	// OSV does not promise events are listed in order, and the sweep below
	// depends on it. Ties put an introduced before the event that closes it, so
	// a range of a single version is still a range.
	sort.SliceStable(events, func(i, j int) bool {
		if c := compareVersions(events[i].version, events[j].version); c != 0 {
			return c < 0
		}
		return events[i].kind < events[j].kind
	})
	return events, true
}

// affectedByEvents applies OSV's range semantics: sweep the boundaries in
// version order, and whichever one the version last passed decides.
func affectedByEvents(version string, events []event) bool {
	var hit bool
	for _, ev := range events {
		switch ev.kind {
		case introduced:
			if compareVersions(version, ev.version) >= 0 {
				hit = true
			}
		case fixed:
			if compareVersions(version, ev.version) >= 0 {
				hit = false
			}
		case lastAffected:
			if compareVersions(version, ev.version) > 0 {
				hit = false
			}
		}
	}
	return hit
}

// corroborated reports whether any other record in the same answer is about the
// same vulnerability.
//
// OSV matched every returned record against one package and one version, so a
// second record naming this vulnerability is a second source saying the version
// really is affected -- reached through its own ranges, not the degraded ones.
// When that happens the finding stands, whatever custom_ranges says.
//
// Records in the same degraded shape are skipped, because they are not a second
// source. Two Go-database records aliased to each other, both UNREVIEWED and
// both open at the top, are the same importer failing to express the same
// versions twice; letting one vouch for the other would make every such pair
// permanently uncorrectable.
func corroborated(ref Ref, v vuln, others []vuln) bool {
	names := map[string]bool{}
	for _, n := range append([]string{v.ID}, v.Aliases...) {
		if n != "" {
			names[n] = true
		}
	}
	for _, o := range others {
		if o.ID == v.ID || degraded(ref, o) {
			continue
		}
		for _, n := range append([]string{o.ID}, o.Aliases...) {
			if n != "" && names[n] {
				return true
			}
		}
	}
	return false
}

// describeEvents renders the swept boundaries as the intervals they describe,
// e.g. "2.10.11-2.11.13, 2.12.0-2.12.9". An interval left open at the top ends
// in "and later", because that is the claim being made about it.
func describeEvents(events []event) string {
	var (
		parts []string
		open  string
		in    bool
	)
	for _, ev := range events {
		switch ev.kind {
		case introduced:
			if !in {
				open, in = ev.version, true
			}
		case fixed, lastAffected:
			if in {
				parts = append(parts, open+"-"+ev.version)
				in = false
			}
		}
	}
	if in {
		parts = append(parts, open+" and later")
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}

// parsableVersion reports whether a version can be ordered against another.
func parsableVersion(v string) bool { return semver.IsValid(canonicalVersion(v)) }

func compareVersions(a, b string) int {
	return semver.Compare(canonicalVersion(a), canonicalVersion(b))
}

// canonicalVersion puts a version in the shape x/mod/semver wants. The "v" is
// optional in OSV's spelling and mandatory in semver's; "+incompatible" is
// build metadata, which semver ignores in comparisons, so it needs no special
// handling beyond being left alone.
func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}
