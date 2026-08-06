package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/vexpr"
)

// vexhubPROptions carries the --vexhub-pr flags into the wiring, so the call
// site stays one struct literal instead of a long argument list.
type vexhubPROptions struct {
	pushRepo  string
	author    string
	dryRun    bool
	version   string
	timestamp string
	logf      func(string, ...any)
}

// runVexhubPR builds the pull request that adds vexscan's ruled-out findings to
// a VEX hub, and either prints it (--vexhub-pr-dry-run) or opens it.
//
// It picks the hub to target from --vexhub the same way a reader would expect:
// the first one that is a GitHub URL, since a raw base or a local directory
// cannot become a pull request. Everything else -- selecting findings, merging
// with what the hub already publishes, opening the PR -- is the vexpr package's
// job; this function only translates flags and reports the outcome.
func runVexhubPR(ctx context.Context, res *analyze.Result, hubs []string, opts vexhubPROptions) error {
	hub := firstGitHubHub(hubs)
	if hub == "" {
		return fmt.Errorf("no --vexhub is a GitHub URL; --vexhub-pr needs e.g. --vexhub https://github.com/rancher/vexhub")
	}

	plan, err := vexpr.Propose(ctx, res, vexpr.Options{
		HubURL:    hub,
		PushRepo:  opts.pushRepo,
		Author:    opts.author,
		Version:   opts.version,
		Timestamp: opts.timestamp,
		Logf:      opts.logf,
	})
	if err != nil {
		return err
	}

	if plan.Empty() {
		if plan.Skipped > 0 {
			opts.logf("vexhub-pr: nothing to propose (%d ruled-out finding(s) lacked a product, component or id)", plan.Skipped)
		} else {
			opts.logf("vexhub-pr: nothing to propose; no ruled-out findings that the hub does not already cover")
		}
		return nil
	}

	if opts.dryRun {
		printVexhubPRPlan(plan, hub)
		return nil
	}

	opts.logf("vexhub-pr: proposing %d statement(s) across %d product(s)", plan.Statements, len(plan.Products))
	prURL, err := plan.Submit(ctx)
	if err != nil {
		return err
	}
	opts.logf("vexhub-pr: opened pull request")
	fmt.Println(prURL)
	return nil
}

// printVexhubPRPlan writes what the PR would do, without touching the network.
func printVexhubPRPlan(plan *vexpr.Plan, hub string) {
	fmt.Printf("vexhub-pr dry run: would open a PR against %s\n", hub)
	fmt.Printf("  branch: %s\n", plan.Branch)
	fmt.Printf("  title:  %s\n", plan.Title)
	fmt.Printf("  %d statement(s) across %d product(s):\n", plan.Statements, len(plan.Products))
	for _, pc := range plan.Products {
		fmt.Printf("    %s\n", pc.Product)
		for _, v := range pc.Vulns {
			fmt.Printf("      + %s\n", v)
		}
	}
	if plan.Skipped > 0 {
		fmt.Printf("  (%d ruled-out finding(s) skipped: no product, component or id)\n", plan.Skipped)
	}
	fmt.Printf("  files changed (%d):\n", len(plan.Changes))
	for _, ch := range plan.Changes {
		fmt.Printf("    %s\n", ch.Path)
	}
}

// firstGitHubHub returns the first hub URL that is a github.com (or its raw
// mirror) location, which is the only kind --vexhub-pr can open a PR against.
func firstGitHubHub(hubs []string) string {
	for _, h := range hubs {
		h = strings.TrimSpace(h)
		if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
			continue
		}
		u, err := url.Parse(h)
		if err != nil {
			continue
		}
		if strings.EqualFold(u.Host, "github.com") || strings.EqualFold(u.Host, "raw.githubusercontent.com") {
			return h
		}
	}
	return ""
}
