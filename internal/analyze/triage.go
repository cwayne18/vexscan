package analyze

import (
	"context"
	"regexp"
	"strings"

	"github.com/cwayne18/vexscan/internal/triage"
)

// bareCVE matches a CVE id and nothing else. Distro databases publish ids like
// DEBIAN-CVE-2026-54369 and Go publishes GO-2025-3547; only the plain form is a
// key into either feed.
var bareCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// TriageResult records what --triage contributed, including what it could not.
//
// It sits beside VEXHubs in Result and, like VEXHubs, is deliberately not part
// of Failed(). An unreachable EPSS mirror does not make the report claim a
// clean image it never examined -- it leaves the findings in the order they
// were already in. That is a different kind of wrong from an ecosystem that
// could not be inventoried, and only one of them may pass silently.
type TriageResult struct {
	// EPSSDate and KEVDate are the feeds' own dates, read out of the payloads.
	// A cached percentile is a claim about a day, and a report read next month
	// must not be able to pretend otherwise.
	EPSSDate string `json:"epss_date,omitempty"`
	KEVDate  string `json:"kev_date,omitempty"`

	// Stale means the network could not be reached and a previously downloaded
	// copy was used.
	EPSSStale bool `json:"epss_stale,omitempty"`
	KEVStale  bool `json:"kev_stale,omitempty"`

	EPSSError string `json:"epss_error,omitempty"`
	KEVError  string `json:"kev_error,omitempty"`

	// Scored is how many findings got a percentile. NoCVE is those whose
	// advisory carries no CVE id at all, and NotInFeed those that had one the
	// feed did not know -- almost always a CVE published in the last day or
	// two. They are counted apart because the report has to explain the two
	// differently, and because neither of them means "low risk".
	Scored         int `json:"scored"`
	NoCVE          int `json:"no_cve,omitempty"`
	NotInFeed      int `json:"not_in_feed,omitempty"`
	KnownExploited int `json:"known_exploited"`
	CatalogSize    int `json:"catalog_size,omitempty"`
}

// Unscored is how many findings have no percentile, for whichever reason.
func (t *TriageResult) Unscored() int { return t.NoCVE + t.NotInFeed }

// Usable reports whether either feed produced anything to sort by. When it is
// false the report keeps its severity ordering and says why.
func (t *TriageResult) Usable() bool {
	return t != nil && (t.EPSSError == "" || t.KEVError == "")
}

// triageOverlay attaches exploitation evidence to every finding, in place.
//
// It runs in the orchestrator beside severityOverlay and llmOverlay, and for
// the same reason: a plugin cannot forget to do something it does not do.
//
// A nil loader means --triage was off, and every Priority stays nil, which is
// what keeps an untriaged report byte-identical to one from before this
// existed.
//
// The join is the interesting part. Both feeds are keyed by CVE and vexscan's
// findings frequently are not: on a Rancher image not one finding of seventy
// carries a CVE in any of its three id fields, and on SUSE not one of forty-six
// does either. findingIDs walks the id sets the resolver already fetched, which
// is what lets GO-2025-3547 be scored as CVE-2024-7598 and SUSE-SU-2026:0312-1
// be scored as the worst of the eight CVEs its patch fixes. Advisories that
// reach no CVE at all are counted and named rather than quietly left at zero.
func triageOverlay(ctx context.Context, loader *triage.Loader, findings []Finding, sets map[string][]string, logf func(string, ...any)) *TriageResult {
	if loader == nil {
		return nil
	}

	// Resolve every finding's CVEs first, so the feed parser can throw away the
	// other 355,000 rows as it streams them.
	cves := make([][]string, len(findings))
	want := map[string]bool{}
	for i, f := range findings {
		cves[i] = findingCVEs(f, sets)
		for _, cve := range cves[i] {
			want[cve] = true
		}
	}
	logf("Triaging %d findings against EPSS and CISA KEV (%d CVE ids)", len(findings), len(want))

	loader.Logf = logf
	data := loader.Load(ctx, want)

	res := &TriageResult{
		EPSSDate:    data.EPSSDate,
		KEVDate:     data.KEVDate,
		EPSSStale:   data.EPSSStale,
		KEVStale:    data.KEVStale,
		EPSSError:   data.EPSSError,
		KEVError:    data.KEVError,
		CatalogSize: len(data.KEV),
	}
	for i := range findings {
		p := data.LookupSet(cves[i])
		findings[i].Priority = &p
		switch {
		case p.Scored:
			res.Scored++
		case len(cves[i]) == 0:
			res.NoCVE++
		default:
			res.NotInFeed++
		}
		if p.KEV != nil {
			res.KnownExploited++
		}
	}
	if res.KnownExploited > 0 {
		logf("Triage: %d finding(s) are in CISA's known-exploited catalog", res.KnownExploited)
	}
	return res
}

// findingCVEs is every bare CVE id a finding can be looked up by, in the order
// the ids were reached, deduplicated. Empty when its advisory has never been
// assigned one.
//
// It is a set rather than a single id because a distro advisory is a bundle:
// SUSE-SU-2026:0312-1 addresses eight CVEs and names none of them in its own
// id. Returning the first would be returning whichever the record happened to
// list first. LookupSet takes the worst of them instead.
//
// Distro prefixes are stripped the way report.go's shortAdvisory strips them
// for display: DEBIAN-CVE-2026-54369 is CVE-2026-54369 wearing a database's
// name.
func findingCVEs(f Finding, sets map[string][]string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(cve string) {
		if !seen[cve] {
			seen[cve] = true
			out = append(out, cve)
		}
	}
	for _, id := range findingIDs(f, sets) {
		switch {
		case bareCVE.MatchString(id):
			add(id)
		default:
			if _, rest, found := strings.Cut(id, "-"); found && bareCVE.MatchString(rest) {
				add(rest)
			}
		}
	}
	return out
}
