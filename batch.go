package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// Batch scanning.
//
// One image is a report. A fleet is a question the single-image report cannot
// answer: which of these forty images is the one to fix first. --images-from
// scans them in one process and renders them together.
//
// The results stay separate. Each image gets its own analyze.Result, with its
// own target, its own INCOMPLETE banners and its own findings, and nothing is
// merged -- because merging would break the one promise this tool makes. A
// not_present for image A and an affected for image B are the same CVE with two
// different answers, and a single findings list has nowhere to put that. Worse,
// an image whose package database could not be read would drag its uncertainty
// across every other image in the run, or, if the flags fell the other way, be
// silently averaged out by thirty-nine clean ones. So: N results, rendered as
// N reports under one roll-up, and an image that could not be scanned is a row
// in the table rather than an absence from it.
//
// What is shared is everything that costs network: the OSV client, the triage
// feeds, and the distro-feed providers with their parsed-document caches. That
// sharing is the whole reason to do this in one process rather than in a shell
// loop -- forty images against the same Debian release download the security
// tracker once.

// batchSchemaVersion is the version of the JSON batch document.
//
// Its own number, and not analyze.SchemaVersion: the two shapes change for
// different reasons, and a reader that parses the wrapper still has to check
// the per-result version on each element of results.
const batchSchemaVersion = 1

// batchFailure is an image the scan could not reach at all -- no Result exists
// for it. Distinct from a Result whose Failed() is true, which is an image that
// was scanned and came back with holes in it.
type batchFailure struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// batchReport is what --images-from produces: the per-image results, in the
// order the list named them, plus the images that never produced one.
type batchReport struct {
	SchemaVersion int               `json:"schema_version"`
	Mode          string            `json:"mode"`
	Targets       int               `json:"targets"`
	Results       []*analyze.Result `json:"results"`
	Failures      []batchFailure    `json:"failures,omitempty"`

	// order is the list as it was given, kept unexported because it is a
	// rendering concern: it is what puts an image that could not be scanned
	// back in the row it was asked for, instead of in a pile at the bottom.
	order []string
}

// failed reports whether any image in the batch is a reason not to exit 0: one
// that could not be scanned, or one that was scanned incompletely.
//
// Deliberately batch-wide. A run over a fleet exits 1 if any single image in it
// is unreadable, because the alternative -- exiting 0 because thirty-nine of
// forty worked -- is how a hole in a scan becomes a passing pipeline.
func (br *batchReport) failed() bool {
	if len(br.Failures) > 0 {
		return true
	}
	for _, res := range br.Results {
		if res.Failed() {
			return true
		}
	}
	return false
}

// scanTarget is one image in a batch: what it is called, and -- when it is not
// coming from a registry -- what the local OCI layout calls it.
//
// The two are one string for --image and --images-from, and two for --haul,
// because hauler files a store entry under a name with the registry stripped
// off. ref is the one that reaches the report and the purls; storeRef only
// ever addresses bytes. See image.Source.
type scanTarget struct {
	ref      string
	storeRef string

	// assert is what the fleet list said about this image and no other. Nil
	// for every target that did not come from a list line that carried one,
	// which is all of them for --image and --haul. See scanAssert.
	assert *scanAssert
}

// imageTargets is the plain case: a list of entries, each its own address.
func imageTargets(entries []imageEntry) []scanTarget {
	out := make([]scanTarget, 0, len(entries))
	for _, e := range entries {
		out = append(out, scanTarget{ref: e.ref, assert: e.assert})
	}
	return out
}

// targetRefs is the inverse, for the places that only want the names.
func targetRefs(targets []scanTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.ref)
	}
	return out
}

// batchRun is everything runBatch needs from the command line. A struct rather
// than fifteen parameters, and only because the flag block it comes from is
// already fifteen lines long.
type batchRun struct {
	opts    analyze.Options // the shared scan settings; the target is set per image
	targets []scanTarget
	format  string
	render  renderOpts
	out     string
	noPager bool
	gist    bool
	gistPub bool
	vexOpts vexOutOptions // timestamp and logf are filled in per run below
	gate    failOn
	started time.Time
	logf    func(string, ...any)

	// afterScan releases whatever the targets were read out of, once the last
	// one has been. For --haul that is an unpacked copy of the bundle, which
	// can be tens of gigabytes and is of no use to the rendering that follows.
	// A defer would not do: every path out of here is an os.Exit.
	afterScan func()
}

// runBatch scans a fleet and exits. It never returns: like the single-image
// path it owns the process's exit status, and for the same reasons.
func runBatch(ctx context.Context, r batchRun) {
	br := scanBatch(ctx, r.opts, r.targets, r.logf)
	if r.afterScan != nil {
		r.afterScan()
	}

	rendered, err := renderBatch(br, r.format, r.render)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	emit(rendered, r.out, r.noPager, r.logf)

	if r.gist {
		desc := fmt.Sprintf("vexscan batch report for %d image(s)", br.Targets)
		url, err := uploadGist(ctx, desc, rendered, r.format, r.gistPub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: gist upload failed: %v\n", err)
			os.Exit(1)
		}
		r.logf("Uploaded report to gist")
		fmt.Println(url)
	}

	// Whether an image is eligible for --vex-out is decided per image; the
	// writing is then done once for the batch.
	//
	// The single-image rule is that a scan with holes in it must not have
	// not_affected statements written from it, because the component it failed
	// to read might be the one that would have kept a finding out of RULED OUT.
	// That rule is about one target. An image that could not be pulled says
	// nothing about the thirty-nine that were read cleanly, and withholding
	// their statements would not make anything safer -- it would just make the
	// flag useless on any fleet with one bad entry in it. So the incomplete ones
	// are dropped here and the rest are proposed together.
	//
	// Together rather than one at a time because the cost of the hub is paid per
	// call, not per image: the index is parsed once, and a merged "master"
	// document named by --vex-merge-into is rewritten once for the run instead
	// of once for every image in the list.
	//
	// It runs before the failures are reported for the same reason the report
	// is written before them: the work that succeeded is still worth having.
	if r.vexOpts.dir != "" {
		vexOpts := r.vexOpts
		vexOpts.timestamp = r.started.UTC().Format(time.RFC3339)
		vexOpts.logf = r.logf
		complete := make([]*analyze.Result, 0, len(br.Results))
		for _, res := range br.Results {
			if res.Failed() {
				r.logf("Skipping --vex-out for %s: its scan did not complete", res.Target)
				continue
			}
			complete = append(complete, res)
		}
		if len(complete) > 0 {
			if err := runVexOut(ctx, complete, vexOpts); err != nil {
				fmt.Fprintf(os.Stderr, "error: vex-out: %v\n", err)
				os.Exit(1)
			}
		}
	}

	if br.failed() {
		reportBatchFailures(br)
		// One unreadable image outranks the gate for the whole run, and the
		// gate is not consulted at all. A finding count that is missing an
		// image is not a number worth deciding a build on, and a clean gate
		// over it would be the batch's own hole reported as a pass.
		if r.gate.on {
			fmt.Fprintln(os.Stderr, "error: --fail-on was not evaluated, because the batch did not complete")
		}
		os.Exit(1)
	}

	if r.gate.on {
		g := batchGate(r.gate, br)
		if g.unweighable > 0 {
			// Not gated on --quiet, for the same reason the single-image note
			// is not: a gate that passed because it could not read a number has
			// to say so whatever the logging setting.
			fmt.Fprintf(os.Stderr,
				"note: %d counted finding(s) across the batch have no published severity and could not be weighed against %s.\n"+
					"      Use --fail-on any to gate on their presence.\n", g.unweighable, r.gate.label)
		}
		if g.tripped > 0 {
			fmt.Fprintln(os.Stderr, r.gate.describe(g))
			os.Exit(exitGate)
		}
	}
	os.Exit(0)
}

// scanBatch runs every image through the same Options, changing only the target.
//
// Serial, and deliberately so for now. Everything expensive in Options is
// shared across the iterations -- the OSV client, the triage feeds, the
// distro-feed providers and their parsed-document caches -- and that sharing is
// the entire reason this beats a shell loop. Running the images concurrently
// would multiply the win, but only after every one of those shared components
// has been audited for concurrent use, and a data race in the thing that
// decides whether a CVE is present is not a trade worth making for wall-clock.
//
// An image that fails is recorded and the scan moves on. Aborting on image 7 of
// 40 would make this worse than the shell loop it replaces.
func scanBatch(ctx context.Context, opts analyze.Options, targets []scanTarget, logf func(string, ...any)) *batchReport {
	br := &batchReport{
		SchemaVersion: batchSchemaVersion,
		Mode:          "batch",
		Targets:       len(targets),
		order:         targetRefs(targets),
	}
	// The run's options are the defaults; a target that came from a list line
	// carrying assertions gets them overlaid on a copy. Copied per image rather
	// than mutated in place, or image four would inherit image three's roots
	// and conclude things about a closure it never had.
	base := opts
	for i, t := range targets {
		ref := t.ref
		logf("[%d/%d] %s", i+1, len(targets), ref)
		opts := base
		opts.Image = ref
		opts.ImageLayoutRef = t.storeRef
		t.assert.apply(&opts)

		// Per-image, because the descriptor records what this scan of this
		// image cost, and a fleet's total tells a reader nothing about the one
		// report they are looking at.
		started := time.Now().UTC()
		res, err := analyze.Run(ctx, opts)
		if err != nil {
			// Reported as it happens as well as collected, so a long batch says
			// something went wrong at the moment it does rather than only at
			// the end. Not gated on --quiet: this is an error, not progress.
			fmt.Fprintf(os.Stderr, "error: %s could not be scanned: %v\n", ref, err)
			br.Failures = append(br.Failures, batchFailure{Target: ref, Error: err.Error()})
			if ctx.Err() != nil {
				// Interrupted. Every remaining image would fail the same way,
				// and forty identical context-cancelled lines help nobody.
				break
			}
			continue
		}
		stampDescriptor(res, started, time.Since(started))
		br.Results = append(br.Results, res)
	}
	return br
}

// renderBatch renders a batch in the requested format.
func renderBatch(br *batchReport, format string, o renderOpts) (string, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(br, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "sarif":
		return renderBatchSARIF(br)
	case "fixplan":
		return renderBatchFixPlan(br, o), nil
	case "summary":
		return renderBatchSummary(br, o), nil
	default: // --format was validated up front; inventory took another path
		return renderBatchText(br, o), nil
	}
}

// reportBatchFailures names every reason the batch is not a clean result, on
// stderr, after the report has been written.
//
// Each line carries its image. The single-image messages do not, because there
// is only one target and the header already named it; here there are forty, and
// a bare "ecosystem os did not complete" would send someone looking through all
// of them.
func reportBatchFailures(br *batchReport) {
	for _, f := range br.Failures {
		fmt.Fprintf(os.Stderr, "error: %s could not be scanned: %s\n", f.Target, f.Error)
	}
	for _, res := range br.Results {
		for _, e := range res.Ecosystems {
			if e.Error != "" {
				fmt.Fprintf(os.Stderr, "error: %s: ecosystem %s did not complete: %s\n", res.Target, e.ID, e.Error)
			}
		}
		if u := res.Unreadable; u != nil && u.Any() {
			fmt.Fprintf(os.Stderr, "error: %s: %d path(s) in the target could not be read: %s\n",
				res.Target, u.Count, strings.Join(u.Paths, ", "))
		}
	}
}

// runInventoryBatch is --format inventory over a fleet: one listing per image,
// in list order, and an image that could not be read is a labelled section
// rather than a gap.
func runInventoryBatch(ctx context.Context, opts analyze.Options, targets []scanTarget, out string, noPager bool, afterScan func(), logf func(string, ...any)) {
	var b strings.Builder
	bad := 0
	for i, t := range targets {
		if i > 0 {
			writeBatchRule(&b)
		}
		ref := t.ref
		logf("[%d/%d] %s", i+1, len(targets), ref)
		opts.Image = ref
		opts.ImageLayoutRef = t.storeRef
		inv, err := analyze.Inventory(ctx, opts)
		if err != nil {
			bad++
			fmt.Fprintf(os.Stderr, "error: %s could not be inventoried: %v\n", ref, err)
			fmt.Fprintf(&b, "vexscan inventory for %s\nINCOMPLETE: not inventoried: %v\n", ref, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if u := inv.Unreadable; u != nil && u.Any() {
			bad++
		}
		b.WriteString(renderInventory(inv))
	}

	if afterScan != nil {
		afterScan()
	}

	// Written first, then failed: a fleet inventory with holes in it is still
	// worth reading, and still not something a CI job should treat as the list.
	emit(b.String(), out, noPager, logf)
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "error: %d of %d image(s) could not be fully inventoried\n", bad, len(targets))
		os.Exit(1)
	}
}

// renderBatchText renders a batch for humans: the roll-up first, so the reader
// sees the shape of the fleet before the first image's table, then every
// image's full report in list order.
func renderBatchText(br *batchReport, o renderOpts) string {
	var b strings.Builder
	writeBatchHeader(&b, br, o.pal)
	writeBatchTable(&b, br, o.pal)

	for _, res := range br.Results {
		writeBatchRule(&b)
		b.WriteString(renderText(res, o))
	}
	writeBatchFooter(&b, br, o.pal)
	return b.String()
}

// renderBatchSummary is the format a fleet is actually read in: one row per
// image, and nothing else.
func renderBatchSummary(br *batchReport, o renderOpts) string {
	var b strings.Builder
	writeBatchHeader(&b, br, o.pal)
	writeBatchTable(&b, br, o.pal)
	writeBatchSeverity(&b, br)
	writeBatchFooter(&b, br, o.pal)
	return b.String()
}

// renderBatchFixPlan renders one fix plan per image.
//
// No roll-up table above it: a fix plan is per-image by construction -- the
// upgrade that clears a CVE in one image is not the upgrade that clears it in
// another -- and a combined count of upgrades across images would be a number
// nobody can act on.
func renderBatchFixPlan(br *batchReport, o renderOpts) string {
	var b strings.Builder
	writeBatchHeader(&b, br, o.pal)
	for i, res := range br.Results {
		if i > 0 {
			writeBatchRule(&b)
		}
		b.WriteString(renderFixPlan(res, o))
	}
	writeBatchFooter(&b, br, o.pal)
	return b.String()
}

// renderBatchSARIF emits one SARIF document with one run per image.
//
// SARIF has carried multiple runs since 2.1.0 and the properties on each name
// its target, so a fleet scan lands in a code-scanning dashboard as the fleet
// it is rather than as one flattened pile of results with no way to tell which
// image an alert came from.
func renderBatchSARIF(br *batchReport) (string, error) {
	runs := make([]sarifRun, 0, len(br.Results))
	for _, res := range br.Results {
		runs = append(runs, sarifRunFor(res))
	}
	return marshalSARIF(runs)
}

// writeBatchHeader names the run and, before anything else, the images that
// could not be scanned at all.
func writeBatchHeader(b *strings.Builder, br *batchReport, pal palette) {
	fmt.Fprintf(b, "vexscan batch report: %d image(s)\n", br.Targets)
	writeBatchCaveats(b, br, pal)
	b.WriteString("\n")
}

// writeBatchCaveats is the batch-level equivalent of writeCaveats: the reasons
// this run is not a clean answer, stated before the numbers rather than after
// them, and in the same INCOMPLETE spelling a reader already scans for.
func writeBatchCaveats(b *strings.Builder, br *batchReport, pal palette) {
	if len(br.Failures) == 0 {
		return
	}
	var block strings.Builder
	fmt.Fprintf(&block, "INCOMPLETE: %d of %d image(s) could not be scanned, so this batch is not a clean result:\n",
		len(br.Failures), br.Targets)
	for _, f := range br.Failures {
		fmt.Fprintf(&block, "  %s: %s\n", f.Target, f.Error)
	}
	b.WriteString(pal.banners(block.String()))
}

// writeBatchFooter repeats the batch caveats once the report is long enough
// that the header has scrolled away, for the same reason writeFooter does it
// per image: the banner is the guarantee, and a guarantee that scrolled off the
// top of a forty-image report has not been made.
func writeBatchFooter(b *strings.Builder, br *batchReport, pal palette) {
	if len(br.Failures) == 0 || strings.Count(b.String(), "\n") <= footerThreshold {
		return
	}
	writeBatchRule(b)
	writeBatchCaveats(b, br, pal)
}

// writeBatchRule separates one image's report from the next.
func writeBatchRule(b *strings.Builder) {
	b.WriteString("\n" + strings.Repeat("-", 78) + "\n\n")
}

// batchRow is one image's line in the roll-up.
type batchRow struct {
	target     string
	components int
	counts     summaryCounts
	scanned    bool // false for an image that never produced a result
	incomplete bool // scanned, but with holes -- its numbers are a floor
}

// writeBatchTable prints one row of counts per image, then a bold total.
//
// The columns are the ones --format summary uses per ecosystem, for the same
// reason and with the same rule: a status that is zero across the whole batch
// earns no column. The rows differ in one way. An image that could not be
// scanned still gets a row, with "-" where its numbers would be, because the
// alternative is a fleet table that is quietly one row short -- and a reader
// counting rows to check their list was covered would be reading a table that
// agrees with itself and not with the world.
func writeBatchTable(b *strings.Builder, br *batchReport, pal palette) {
	rows := batchRows(br)

	var total summaryCounts
	var totalComponents int
	for _, r := range rows {
		total.addAll(r.counts)
		totalComponents += r.components
	}

	showVexed := total.vexed > 0
	showUndet := total.undetermined > 0
	showRuled := total.ruledOut > 0

	header := []string{"IMAGE", "COMPONENTS", "AFFECTED"}
	if showVexed {
		header = append(header, "VEXED")
	}
	if showUndet {
		header = append(header, "UNDETERMINED")
	}
	if showRuled {
		header = append(header, "RULED OUT")
	}

	mkRow := func(label, components, affected, vexed, undet, ruled string) []string {
		row := []string{label, components, affected}
		if showVexed {
			row = append(row, vexed)
		}
		if showUndet {
			row = append(row, undet)
		}
		if showRuled {
			row = append(row, ruled)
		}
		return row
	}
	countRow := func(label string, components int, c summaryCounts) []string {
		return mkRow(label,
			strconv.Itoa(components), strconv.Itoa(c.affected), strconv.Itoa(c.vexed),
			strconv.Itoa(c.undetermined), strconv.Itoa(c.ruledOut))
	}

	table := [][]string{header}
	for _, r := range rows {
		switch {
		case !r.scanned:
			table = append(table, mkRow(r.target+" (NOT SCANNED)", "-", "-", "-", "-", "-"))
		case r.incomplete:
			// The counts are real as far as they go, and the suffix says how far
			// that is: an incomplete scan's numbers are a floor, never a total.
			table = append(table, countRow(r.target+" (INCOMPLETE)", r.components, r.counts))
		default:
			table = append(table, countRow(r.target, r.components, r.counts))
		}
	}
	// The total earns its row only when it sums more than one image; with a
	// single row it would just repeat it.
	if len(rows) > 1 {
		totalRow := countRow("TOTAL", totalComponents, total)
		for i := range totalRow {
			totalRow[i] = pal.bold(totalRow[i])
		}
		table = append(table, totalRow)
	}

	fmt.Fprintf(b, "%s\n", pal.heading("BATCH SUMMARY"))
	writeTable(b, table)
}

// batchRows tallies each image in the order the list named it, with the
// unscannable ones in the positions they were asked for rather than in a pile
// at the bottom -- so a reader checking the table against their list reads the
// two down the same line.
func batchRows(br *batchReport) []batchRow {
	failed := make(map[string]bool, len(br.Failures))
	byTarget := make(map[string]*analyze.Result, len(br.Results))
	for _, f := range br.Failures {
		failed[f.Target] = true
	}
	for _, res := range br.Results {
		byTarget[res.Target] = res
	}

	// Results carry the reference they were scanned under and failures carry
	// the one they were asked for, so both rejoin the original list on it. A
	// report built without one -- a test's literal -- still renders, just with
	// the failures last.
	order := br.order
	if len(order) == 0 {
		for _, res := range br.Results {
			order = append(order, res.Target)
		}
		for _, f := range br.Failures {
			order = append(order, f.Target)
		}
	}

	rows := make([]batchRow, 0, len(order))
	seen := map[string]bool{}
	for _, t := range order {
		if seen[t] {
			continue
		}
		seen[t] = true
		if failed[t] {
			rows = append(rows, batchRow{target: t})
			continue
		}
		res := byTarget[t]
		if res == nil {
			continue
		}
		r := batchRow{target: t, scanned: true, incomplete: res.Failed()}
		for _, f := range res.Findings {
			r.counts.add(bucketOf(f))
		}
		for _, e := range res.Ecosystems {
			// An ecosystem that errored contributed no inventory it can vouch
			// for; the INCOMPLETE suffix on the row already accounts for it.
			if e.Error == "" {
				r.components += e.Components
			}
		}
		rows = append(rows, r)
	}
	return rows
}

// writeBatchSeverity prints the severity spread of every affected row in the
// batch: the same population and the same line renderSummary prints per image,
// summed over the fleet.
func writeBatchSeverity(b *strings.Builder, br *batchReport) {
	counts := map[string]int{}
	for _, res := range br.Results {
		for _, f := range res.Findings {
			if bucketOf(f) == bucketAffected {
				counts[displaySeverity(f)]++
			}
		}
	}
	if spread := severitySpread(counts, false); spread != "" {
		fmt.Fprintf(b, "\naffected by severity: %s\n", spread)
	}
}

// batchGate evaluates --fail-on across every image in the batch.
//
// The counts sum and the trip is an OR: one image over the threshold fails the
// run, because a pipeline that ships a fleet ships the worst image in it. The
// unweighable count sums too, so the note about findings with no published
// severity is a batch-wide number rather than one line per image.
func batchGate(gate failOn, br *batchReport) gateResult {
	var g gateResult
	for _, res := range br.Results {
		r := gate.evaluate(res)
		g.counted += r.counted
		g.tripped += r.tripped
		g.unweighable += r.unweighable
	}
	return g
}
