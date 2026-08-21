package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// The summary.
//
// --format text is the whole table; --format summary is the number at the top
// of it. It answers the first question a reader of a 150-row scan actually has
// -- how much is here, and how much of it is real -- as a handful of rows: one
// per ecosystem, then a total. The column no version scanner can offer sits
// beside the one that has to be acted on, so RULED OUT (what a version match
// would have raised and the presence test cleared) is read next to AFFECTED.
//
// It is a view over the same findings every other format renders, counted
// rather than listed. The buckets here are the sections in --format text, so a
// summary and a full report of the same scan can never disagree: bucketOf is
// the one place that decides which section a finding belongs to, and both go
// through it.

// statusBucket is which of the report's four sections a finding renders under.
type statusBucket int

const (
	bucketAffected statusBucket = iota
	bucketVexed
	bucketUndetermined
	bucketRuledOut
)

// bucketOf classifies a finding into the section it belongs to. sections() and
// the summary both route through it, so a finding can never be counted in one
// bucket and listed under another.
func bucketOf(f analyze.Finding) statusBucket {
	switch f.Status {
	case analyze.StatusLinked, analyze.StatusReachable:
		if alreadyVexed(f) {
			return bucketVexed
		}
		return bucketAffected
	case analyze.StatusNotPresent, analyze.StatusNotInPath:
		return bucketRuledOut
	default:
		return bucketUndetermined
	}
}

// summaryCounts is the per-ecosystem tally the table prints.
type summaryCounts struct {
	affected     int
	vexed        int
	undetermined int
	ruledOut     int
}

func (c *summaryCounts) add(b statusBucket) {
	switch b {
	case bucketAffected:
		c.affected++
	case bucketVexed:
		c.vexed++
	case bucketUndetermined:
		c.undetermined++
	case bucketRuledOut:
		c.ruledOut++
	}
}

func (c *summaryCounts) addAll(o summaryCounts) {
	c.affected += o.affected
	c.vexed += o.vexed
	c.undetermined += o.undetermined
	c.ruledOut += o.ruledOut
}

// renderSummary renders a scan result as a per-ecosystem count table: the same
// header and caveats every human-readable format carries, then a row of counts
// per ecosystem and a bold total.
func renderSummary(res *analyze.Result, o renderOpts) string {
	var b strings.Builder
	writeHeader(&b, res, o.pal)

	// Same three ways to be empty as every other format, and only one of them
	// is good news. Shared so an empty --format summary cannot read as clean
	// where --format text would call it incomplete.
	if len(res.Findings) == 0 {
		writeNoFindings(&b, res)
		return b.String()
	}

	writeSummaryTable(&b, res, o.pal)
	writeAffectedSeverity(&b, res)

	// Long enough that the header scrolled off: repeat the caveats. Measured on
	// the report, like renderText, so a file, a gist and a paged terminal all
	// get the same bytes.
	if strings.Count(b.String(), "\n") > footerThreshold {
		writeFooter(&b, res, o.pal)
	}
	return b.String()
}

// writeSummaryTable prints one row of counts per ecosystem that ran, then a
// bold total.
//
// A status column that is zero in every ecosystem earns no place, matching the
// findings table: an image with nothing vexed and nothing undetermined shows
// neither column rather than two columns of zeros. AFFECTED and COMPONENTS are
// always shown -- they are the two numbers the reader came for.
func writeSummaryTable(b *strings.Builder, res *analyze.Result, pal palette) {
	perEco := map[string]*summaryCounts{}
	for _, f := range res.Findings {
		c := perEco[f.Ecosystem]
		if c == nil {
			c = &summaryCounts{}
			perEco[f.Ecosystem] = c
		}
		c.add(bucketOf(f))
	}

	type ecoRow struct {
		label      string
		components int
		counts     summaryCounts
	}
	var rows []ecoRow
	var total summaryCounts
	var totalComponents int
	for _, e := range res.Ecosystems {
		if e.Error != "" {
			continue // the INCOMPLETE banner in the header already accounts for it
		}
		c := summaryCounts{}
		if got := perEco[e.ID]; got != nil {
			c = *got
		}
		// A plugin that found no inventory and no findings has nothing to say in
		// a summary -- it is noise here, though the full text report still lists
		// it. A plugin that inventoried components but matched no advisory keeps
		// its row: "50 npm packages, none vulnerable" is a result worth seeing.
		if e.Components == 0 && c == (summaryCounts{}) {
			continue
		}
		rows = append(rows, ecoRow{ecosystemLabel(e), e.Components, c})
		total.addAll(c)
		totalComponents += e.Components
	}

	showVexed := total.vexed > 0
	showUndet := total.undetermined > 0
	showRuled := total.ruledOut > 0

	header := []string{"ECOSYSTEM", "COMPONENTS", "AFFECTED"}
	if showVexed {
		header = append(header, "VEXED")
	}
	if showUndet {
		header = append(header, "UNDETERMINED")
	}
	if showRuled {
		header = append(header, "RULED OUT")
	}

	mkRow := func(label string, components int, c summaryCounts) []string {
		cells := []string{label, strconv.Itoa(components), strconv.Itoa(c.affected)}
		if showVexed {
			cells = append(cells, strconv.Itoa(c.vexed))
		}
		if showUndet {
			cells = append(cells, strconv.Itoa(c.undetermined))
		}
		if showRuled {
			cells = append(cells, strconv.Itoa(c.ruledOut))
		}
		return cells
	}

	table := [][]string{header}
	for _, r := range rows {
		table = append(table, mkRow(r.label, r.components, r.counts))
	}
	// The total earns its row only when it sums more than one ecosystem;
	// with a single row it would just repeat it.
	if len(rows) > 1 {
		totalRow := mkRow("TOTAL", totalComponents, total)
		for i := range totalRow {
			totalRow[i] = pal.bold(totalRow[i])
		}
		table = append(table, totalRow)
	}

	fmt.Fprintf(b, "%s\n", pal.heading("SUMMARY"))
	writeTable(b, table)
}

// writeAffectedSeverity prints the severity spread of the affected rows, the one
// breakdown a reader wants once the table has told them how many there are. It
// is the same population and the same line as the text report's summary, so the
// two never disagree.
func writeAffectedSeverity(b *strings.Builder, res *analyze.Result) {
	counts := map[string]int{}
	for _, f := range res.Findings {
		if bucketOf(f) == bucketAffected {
			counts[displaySeverity(f)]++
		}
	}
	if spread := severitySpread(counts, false); spread != "" {
		fmt.Fprintf(b, "\naffected by severity: %s\n", spread)
	}
}

// ecosystemLabel names an ecosystem for the table: its plugin id, and the
// concrete OSV ecosystem in parentheses when that says something the id does not
// ("os (Debian:12)", but plain "golang").
func ecosystemLabel(e ecosystem.EcosystemResult) string {
	name := strings.Join(e.Ecosystems, ", ")
	if name == "" || strings.EqualFold(name, e.ID) {
		return e.ID
	}
	return fmt.Sprintf("%s (%s)", e.ID, name)
}
