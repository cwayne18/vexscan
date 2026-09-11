package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/csaf"
	"github.com/cwayne18/vexscan/internal/vex"
	"github.com/cwayne18/vexscan/internal/vexpr"
)

// vexOutOptions carries the --vex-out flags into the wiring, so the call site
// stays one struct literal instead of a long argument list.
type vexOutOptions struct {
	dir       string
	author    string
	format    string
	pubNS     string
	pubCat    string
	hubs      []string
	timestamp string
	logf      func(string, ...any)
}

// runVexOut writes the VEX documents for this scan's ruled-out findings into a
// directory, laid out as a VEX hub.
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
		Hub:                hub,
		Format:             vexpr.Format(opts.format),
		Author:             opts.author,
		Timestamp:          opts.timestamp,
		PublisherCategory:  opts.pubCat,
		PublisherNamespace: opts.pubNS,
		Logf:               opts.logf,
	})
	if err != nil {
		return err
	}

	skippedDocs := reportSkippedDocuments(plan, opts.logf)
	if plan.Empty() {
		switch {
		case skippedDocs > 0:
			// Saying the hub already covers everything would contradict the
			// warnings just printed: nothing was written because every document
			// this had statements for was left alone, not because there was
			// nothing to say.
			opts.logf("vex-out: nothing written; all %d document(s) with statements to add were left untouched", skippedDocs)
		case plan.Skipped > 0:
			opts.logf("vex-out: nothing to write (%d ruled-out finding(s) lacked a product, component or id)", plan.Skipped)
		default:
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

// reportSkippedDocuments names every hub document the proposal declined to
// touch.
//
// These are warnings, not footnotes. Each entry is a product whose statements
// are missing from the output, and whoever reviews the result needs to know the
// omission was deliberate -- the operator needs to know their scan's
// conclusions about those products went nowhere.
//
// The two reasons are kept apart because they ask different things. An
// unreadable document is a broken hub or a format this version does not
// understand, and there is nothing to do about it here. A declined one is
// usually a flag away from working, so its own reason is printed rather than a
// generic line.
// It returns how many there were, so the summary line can tell "nothing to add"
// apart from "nothing got through".
func reportSkippedDocuments(plan *vexpr.Plan, logf func(string, ...any)) int {
	for _, loc := range plan.Unparsable {
		logf("warning: vex-out: %s could not be parsed and was left untouched; nothing written for it", loc)
	}
	for _, u := range plan.Untouched {
		logf("warning: vex-out: %s left untouched: %s; nothing written for %s", u.Location, u.Reason, u.Product)
	}
	return len(plan.Unparsable) + len(plan.Untouched)
}

// checkVexOut validates the --vex-out flags before the scan runs, so a missing
// author is a command-line error rather than a surprise after a five-minute
// image pull.
//
// --vex-author has no default because there is nobody to derive one from. The
// author of a VEX statement is whoever is answerable for the claim, and a
// not_affected claim is one that tells other people's scanners to stop
// reporting a vulnerability. "vexscan" is not an answer to who said so.
// --vex-publisher-namespace is the same question in CSAF's terms, which is why
// it has no default either.
func checkVexOut(dir, author, format, pubNS, pubCat string) error {
	f, err := vexpr.ParseFormat(format)
	if err != nil {
		return fmt.Errorf("--vex-format: %w", err)
	}
	publisher := []struct{ name, val string }{
		{"--vex-publisher-namespace", pubNS},
		{"--vex-publisher-category", pubCat},
	}
	if dir == "" {
		for _, fl := range append([]struct{ name, val string }{{"--vex-author", author}}, publisher...) {
			if fl.val != "" {
				return fmt.Errorf("%s has no effect without --vex-out", fl.name)
			}
		}
		return nil
	}
	if author == "" {
		return fmt.Errorf("--vex-out needs --vex-author to record on the statements, " +
			`e.g. --vex-author "Acme Security"`)
	}
	if f != vexpr.FormatCSAF {
		for _, fl := range publisher {
			if fl.val != "" {
				return fmt.Errorf("%s describes a CSAF publisher and has no effect on --vex-format %s", fl.name, f)
			}
		}
		return nil
	}
	if pubNS == "" {
		return fmt.Errorf("--vex-format csaf needs --vex-publisher-namespace to identify the publisher, " +
			`e.g. --vex-publisher-namespace "https://acme.example"`)
	}
	if pubCat != "" && !csaf.ValidPublisherCategory(pubCat) {
		return fmt.Errorf("--vex-publisher-category %q is not one CSAF allows: %s",
			pubCat, strings.Join(csaf.PublisherCategories, ", "))
	}
	return nil
}
