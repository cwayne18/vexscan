package main

import (
	"context"
	"fmt"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/vex"
	"github.com/cwayne18/vexscan/internal/vexpr"
)

// vexOutOptions carries the --vex-out flags into the wiring, so the call site
// stays one struct literal instead of a long argument list.
type vexOutOptions struct {
	dir       string
	author    string
	hubs      []string
	timestamp string
	logf      func(string, ...any)
}

// runVexOut writes the OpenVEX documents for this scan's ruled-out findings
// into a directory, laid out as a VEX hub.
//
// When a --vexhub is given the documents are merged into what that hub already
// publishes -- read-only, over the same transport the scan used -- so the output
// is the hub's own files with statements added, and copying it over a clone
// produces a reviewable diff. With no --vexhub the output is a hub in its own
// right, index and all.
func runVexOut(ctx context.Context, res *analyze.Result, opts vexOutOptions) error {
	var hub vexpr.HubReader
	if len(opts.hubs) > 0 {
		h, err := vex.Open(ctx, opts.hubs[0])
		if err != nil {
			return err
		}
		opts.logf("vex-out: merging against %s (%d product(s) indexed)", h.URL, h.Size())
		hub = h
	}

	plan, err := vexpr.Propose(ctx, res, vexpr.Options{
		Hub:       hub,
		Author:    opts.author,
		Timestamp: opts.timestamp,
		Logf:      opts.logf,
	})
	if err != nil {
		return err
	}

	reportUnparsable(plan, opts.logf)
	if plan.Empty() {
		if plan.Skipped > 0 {
			opts.logf("vex-out: nothing to write (%d ruled-out finding(s) lacked a product, component or id)", plan.Skipped)
		} else {
			opts.logf("vex-out: nothing to write; no ruled-out findings the hub does not already cover")
		}
		return nil
	}

	if err := plan.Write(opts.dir); err != nil {
		return err
	}

	opts.logf("vex-out: wrote %d statement(s) across %d product(s) to %s",
		plan.Statements, len(plan.Products), opts.dir)
	for _, pc := range plan.Products {
		opts.logf("  %s", pc.Product)
		for _, v := range pc.Vulns {
			opts.logf("    + %s", v)
		}
	}
	for _, ch := range plan.Changes {
		opts.logf("  %s", ch.Path)
	}
	if plan.Skipped > 0 {
		opts.logf("  (%d ruled-out finding(s) skipped: no product, component or id)", plan.Skipped)
	}
	opts.logf("vex-out: review the diff before proposing it; contrib/vexhub-pr.sh does the git and gh steps")
	return nil
}

// reportUnparsable names every hub document the proposal declined to touch
// because it could not be read.
//
// This is a warning, not a footnote. Each entry is a product whose statements
// are missing from the output, and the reason is a document vexscan could not
// decode -- either a hub using something this version does not understand or a
// genuinely broken file. Either way whoever reviews the result needs to know
// the omission was deliberate, and the operator needs to know their scan's
// conclusions about those products went nowhere.
func reportUnparsable(plan *vexpr.Plan, logf func(string, ...any)) {
	for _, loc := range plan.Unparsable {
		logf("warning: vex-out: %s could not be parsed and was left untouched; nothing written for it", loc)
	}
}

// checkVexOut validates the --vex-out flags before the scan runs, so a missing
// author is a command-line error rather than a surprise after a five-minute
// image pull.
//
// --vex-author has no default because there is nobody to derive one from. The
// author of an OpenVEX statement is whoever is answerable for the claim, and a
// not_affected claim is one that tells other people's scanners to stop
// reporting a vulnerability. "vexscan" is not an answer to who said so.
func checkVexOut(dir, author string) error {
	if dir == "" {
		if author != "" {
			return fmt.Errorf("--vex-author has no effect without --vex-out")
		}
		return nil
	}
	if author == "" {
		return fmt.Errorf("--vex-out needs --vex-author to record on the statements, " +
			`e.g. --vex-author "Acme Security"`)
	}
	return nil
}
