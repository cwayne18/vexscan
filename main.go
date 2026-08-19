// Command vexscan checks whether specific CVEs in a Go module are actually
// present in the binaries shipped inside a container image, using pclntab
// presence tests and govulncheck, with an optional LLM exploitability check.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/buildinfo"
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/distrofeed"
	"github.com/cwayne18/vexscan/internal/distrofeed/debian"
	"github.com/cwayne18/vexscan/internal/distrofeed/suse"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/envx"
	"github.com/cwayne18/vexscan/internal/gist"
	"github.com/cwayne18/vexscan/internal/modgraph"
	"github.com/cwayne18/vexscan/internal/osv"
	"github.com/cwayne18/vexscan/internal/triage"
)

func main() {
	// --version carries two meanings for one more release; see version.go.
	var versionArg versionFlag
	flag.Var(&versionArg, "version", "print vexscan's version and exit (deprecated: --version=VERSION still overrides a module version; use --module-version)")

	var packages, ecosystems, roots, vexhubs, severities, rpms, preferVendors stringList
	flag.Var(&packages, "package", "package to check: a purl, an ecosystem:name shorthand (deb:openssl, golang:golang.org/x/net), or a bare name resolved against the inventory; repeatable")
	flag.Var(&ecosystems, "ecosystem", "restrict the scan to these ecosystems (golang, os, pypi, npm, maven, or a distro family like debian); repeatable, default all")
	flag.Var(&roots, "roots", "extra entrypoints for the reachability closures (shared libraries and language imports), for an image whose real command comes from outside its config; repeatable")
	flag.Var(&rpms, "rpm", "rpm package file to scan without installing it -- a path, a directory of them, or a URL; repeatable "+
		"(mutually exclusive with --image, --rootfs and --repo; reads only the header, so a URL costs kilobytes not megabytes)")
	flag.Var(&vexhubs, "vexhub", "VEX Hub repository to check findings against, e.g. https://github.com/rancher/vexhub (also accepts a raw base URL or a local directory); repeatable, earliest wins")
	flag.Var(&severities, "severity", "only report findings at these severities: "+
		strings.Join(cvss.Labels, ", ")+"; comma-separated or repeatable "+
		"(UNKNOWN means no rating was published, and must be named to be shown -- "+
		"every --repo finding is UNKNOWN, because govulncheck's OpenVEX carries no severity)")
	var (
		image  = flag.String("image", "", "container image reference to inspect (mutually exclusive with --rootfs and --repo)")
		rootfs = flag.String("rootfs", "", "filesystem tree already on disk to inspect -- an unpacked image, a mounted volume, a machine's own / (mutually exclusive with --image and --repo)")
		repo   = flag.String("repo", "", "git source repo to analyze via govulncheck source mode, e.g. github.com/rancher/rancher (mutually exclusive with --image and --rootfs)")
		sbom   = flag.String("sbom", "", "CycloneDX JSON bill of materials to scan -- a path, or '-' for stdin "+
			"(mutually exclusive with the other targets; a component names a package and nothing else, so every finding is undetermined)")
		ref        = flag.String("ref", "", "branch, tag, or commit to check out for --repo (default: repo default branch)")
		repoPath   = flag.String("repo-path", ".", "module subdirectory within --repo to scan")
		module     = flag.String("module", "", "deprecated alias for --package golang:MODULE")
		all        = flag.Bool("all", false, "check everything each ecosystem can inventory, instead of named packages (the default in --image mode when no --package/--cves is given)")
		cvesFlag   = flag.String("cves", "", "comma-separated CVE/GHSA/GO ids to check; alone, they are resolved against the whole target")
		cvesFile   = flag.String("cves-file", "", "path to a file with one CVE/GHSA/GO id per line (merged with --cves)")
		modVersion = flag.String("module-version", "", "override the module version (image mode only; default: read from each binary's build info)")
		showVer    = flag.Bool("V", false, "print vexscan's version and exit")
		goVersion  = flag.String("go-version", "", "pin the Go toolchain for --repo analysis, e.g. 1.24.0 (useful with --package golang:stdlib)")
		goos       = flag.String("os", "linux", "image OS variant to pull (image mode)")
		arch       = flag.String("arch", "amd64", "image architecture variant to pull (image mode)")
		osvEco     = flag.String("osv-ecosystem", "", "override the OSV ecosystem derived from the image's os-release, e.g. 'Debian:12'")
		osvURL     = flag.String("osv-url", "", "OSV API root to query instead of "+osv.DefaultBaseURL+" -- a caching proxy or a mirror serving the same v1 API. For a scan with no network at all use --osv-dir, which reads OSV's published data export directly (env: VEXSCAN_OSV_URL)")
		osvDir     = flag.String("osv-dir", "", "answer advisory lookups from a local copy of OSV's data export instead of the API: a directory of per-ecosystem JSON (gsutil -m rsync -r gs://osv-vulnerabilities DIR), or an all.zip. Version matching then happens here rather than on osv.dev, so read the NOTE the report prints about it (env: VEXSCAN_OSV_DIR)")
		dlopen     = flag.String("dlopen-policy", "taint", "what a reachable dlopen does to the closure: taint (block conclusions) or assume-none")
		dynamic    = flag.String("dynamic-import-policy", "taint", "what an import of a computed name does to a language import graph: taint (block conclusions) or assume-none; these are far more common than dlopen, so assume-none discards much more")
		triageOn   = flag.Bool("triage", false, "order findings by exploitation evidence: EPSS scores and CISA's known-exploited catalog. Adds two columns and sorts known-exploited first, then by EPSS percentile; nothing is hidden, and no severity changes. Downloads two public feeds (~4 MB, cached under VEXSCAN_TRIAGE_CACHE)")
		mine       = flag.Bool("mine-advisories", false, "with --llm, let the model read each advisory's prose for symbols to check against the image")
		rpmDeep    = flag.Bool("rpm-deep", false, "with --rpm, decompress each package's payload and extract its ELF objects so the dynsym-absent test can run (needs --mine-advisories to have a symbol to look for; costs the whole download, and still cannot run the reachability closure)")
		trustAbs   = flag.Bool("trust-import-absence", false, "let a missing dynamic import of the vulnerable symbol conclude not_in_execute_path (see README: this is weaker than it looks)")
		useLLM     = flag.Bool("llm", false, "consult a chat model on genuinely-affected CVEs for exploitability (needs a provider: --llm-endpoint or --llm-command; implies --details for --format text so the verdicts are shown)")
		llmURL     = flag.String("llm-endpoint", "", "OpenAI-compatible chat/completions URL for --llm -- an API provider, or a local Ollama (env: VEXSCAN_LLM_ENDPOINT; credential: VEXSCAN_LLM_TOKEN)")
		llmModel   = flag.String("llm-model", "", "model id for --llm-endpoint (env: VEXSCAN_LLM_MODEL; default gpt-4o)")
		llmCommand = flag.String("llm-command", "", "for --llm, run this installed CLI instead of calling an endpoint, e.g. 'claude -p'; the prompt arrives on its stdin (env: VEXSCAN_LLM_COMMAND)")
		format     = flag.String("format", "text", "output format: text, json, sarif (SARIF 2.1.0 for code-scanning dashboards), fixplan (a remediation-first view of the fixable findings), or inventory (list the image's OS packages and exit)")
		details    = flag.Bool("details", false, "with --format text, print the full evidence block under each row instead of the table alone")
		out        = flag.String("out", "", "write output to this file instead of stdout")
		gistFlag   = flag.Bool("gist", false, "also upload the output to a public GitHub gist and print its URL (needs GITHUB_TOKEN/GH_TOKEN with gist scope)")
		gistSecret = flag.Bool("gist-secret", false, "with --gist, create a secret (unlisted) gist instead of a public one")
		vexOut     = flag.String("vex-out", "", "write OpenVEX not_affected documents for every finding vexscan ruled out into this directory, laid out as a VEX hub; with --vexhub they are merged into what that hub already publishes, so the directory can be a clone of it (see contrib/vexhub-pr.sh)")
		vexAuthor  = flag.String("vex-author", "", "with --vex-out, the OpenVEX author to record on the statements -- required, and it is you: a not_affected claim is someone's assertion")
		failOnSev  = flag.String("fail-on", "", "exit 3 if any counted finding is at or above this severity: "+
			strings.Join(cvss.Labels, ", ")+", or 'any'. Off by default; see --fail-on-status for what counts")
		failOnStat = flag.String("fail-on-status", "", "which findings --fail-on weighs: a comma-separated list of "+
			"affected, undetermined, vexed, cleared, or 'all' (default affected -- vulnerable code present and loadable, "+
			"which is the gate no version-matching scanner can offer)")
		colorMode = flag.String("color", "auto", "colourise the text report: auto, always, never. "+
			"auto colours only a terminal, and never a file (--out), a gist (--gist), JSON output, or a run with NO_COLOR set")
		quiet       = flag.Bool("quiet", false, "suppress progress logging on stderr")
		noPager     = flag.Bool("no-pager", false, "never page the output, even when stdout is a terminal (VEXSCAN_PAGER picks the pager; setting it empty turns paging off for good)")
		distroFeeds = flag.Bool("distro-feeds", false, "clear OS-package false positives with the distribution's own security feed: a vendor <not-affected> or an already-shipped fix moves a row to ALREADY VEXED, and like --vexhub never changes a status. Debian's security tracker and SUSE's CSAF-VEX today; network, off by default")
	)
	flag.Var(&preferVendors, "prefer-vendor", "favour this security vendor's own CVSS score over the OSV-derived one, e.g. 'suse'; "+
		"repeatable for a priority order, and unlike --severity it can lower a rating (the vendor's score is authoritative when present). "+
		"Keyed by CVE, so it rescores findings in any ecosystem (Go modules included), not just OS packages; network, SUSE today")
	flag.Usage = usage
	flag.Parse()

	// Answered before anything else, so it works with no target, no network
	// and no other flag -- which is the state of whoever is asking.
	if versionArg.print || *showVer {
		if rest := flag.Args(); len(rest) == 1 && looksLikeVersion(rest[0]) {
			fail("--version now prints vexscan's own version; use --module-version=%s to override a module version", rest[0])
		}
		fmt.Println(buildinfo.String())
		return
	}
	checkPositional(&versionArg)

	// The old spelling still works, and still says where it went.
	if versionArg.override != "" {
		if *modVersion != "" && *modVersion != versionArg.override {
			fail("--version=%s and --module-version=%s disagree; they are the same setting", versionArg.override, *modVersion)
		}
		fmt.Fprintf(os.Stderr, "warning: --version as a module override is deprecated; use --module-version=%s\n", versionArg.override)
		*modVersion = versionArg.override
	}

	// --format inventory answers "what is installed in this image", which
	// needs no subject and no advisory lookup.
	inventoryMode := *format == "inventory"

	named := countNamed(*image, *rootfs, *repo, *sbom)
	if len(rpms) > 0 {
		named++
	}
	if named != 1 {
		fail("set exactly one of --image, --rootfs, --repo, --rpm or --sbom")
	}
	if *rpmDeep {
		if len(rpms) == 0 {
			fail("--rpm-deep only applies to --rpm")
		}
		if !*mine {
			// Not fatal: deep extraction still populates the tree, and a future
			// per-object test might use it. But the one test it enables today
			// needs a symbol to look for, and only mining supplies one, so
			// without it the extra download buys nothing.
			fmt.Fprintln(os.Stderr, "warning: --rpm-deep has no effect without --mine-advisories, which supplies the symbol its dynsym test looks for")
		}
	}
	switch *format {
	case "text", "json", "sarif", "fixplan", "inventory":
	default:
		fail("unknown --format %q; want text, json, sarif, fixplan, or inventory", *format)
	}
	// Caught here so a missing author is a command-line error before the scan,
	// not after it.
	if err := checkVexOut(*vexOut, *vexAuthor); err != nil {
		fail("%v", err)
	}
	// Canonicalized here, and strictly, so that a typo is a command-line error
	// before the pull rather than an empty report after it. cvss.Parse rather
	// than cvss.Normalize for one reason: Normalize("CRITCAL") is UNKNOWN, so
	// the lenient version would read a typo as a request for exactly the
	// unrated findings -- the one misreading that looks like a working scan.
	keep := make([]string, 0, len(severities))
	for _, s := range severities {
		label, ok := cvss.Parse(s)
		if !ok {
			fail("unknown --severity %q; want one of %s", s, strings.Join(cvss.Labels, ", "))
		}
		keep = append(keep, label)
	}
	cves := parseCVEs(*cvesFlag, *cvesFile)
	// Parsed before the pull for the same reason --severity is: a gate that
	// can never fire is worse than one that errors.
	gate, err := parseFailOn(*failOnSev, *failOnStat)
	if err != nil {
		fail("%v", err)
	}
	if gate.on && inventoryMode {
		fail("--fail-on has nothing to gate on with --format inventory, which resolves no advisories")
	}
	// Validated up front too: a misspelled --color is a setting the user
	// believes they changed, and finding out after a five-minute image pull is
	// finding out too late.
	colors, err := parseColor(*colorMode)
	if err != nil {
		fail("%v", err)
	}

	// --image with no subject means "scan the whole image": --all is the only
	// sensible default there, so assume it rather than making the user type it.
	// A named --package/--module/--cves still narrows the scan, and --all with
	// those is an error caught just below, so only fill it in when nothing else
	// selects a subject.
	if *image != "" && !*all && len(packages) == 0 && *module == "" && len(cves) == 0 {
		*all = true
	}
	// --llm's verdicts live in the per-finding evidence block, which only the
	// text report prints and only with --details; without it the model runs and
	// its output goes nowhere, so turn it on for the format that can show it.
	if *useLLM && *format == "text" {
		*details = true
	}

	if !inventoryMode {
		// Every other combination has a meaning; this one has none, and the
		// only honest thing to do with it is say what the three answers are.
		if len(packages) == 0 && *module == "" && len(cves) == 0 && !*all {
			fail("nothing to check: name a package with --package, give ids with --cves, or pass --all")
		}
		if *all && (len(packages) > 0 || *module != "") {
			fail("--all checks everything, so it cannot be combined with --package or --module")
		}
	}
	if *module != "" {
		// Not gated on --quiet: this is about the command line, not progress,
		// and the person who needs to read it is the one who typed it.
		fmt.Fprintf(os.Stderr, "warning: --module is deprecated; use --package golang:%s\n", *module)
	}
	dlopenPolicy, err := elfgraph.ParseDlopenPolicy(*dlopen)
	if err != nil {
		fail("%v", err)
	}
	dynamicPolicy, err := modgraph.ParseDynamicPolicy(*dynamic)
	if err != nil {
		fail("%v", err)
	}
	// --prefer-vendor and --distro-feeds both draw on the same vendor sources, so
	// they are resolved together: distroSources shares one provider instance per
	// vendor between them and reports any --prefer-vendor name it cannot score.
	distroFeedProviders, vendorScorers := distroSources(*distroFeeds, preferVendors)

	// The two advisory-source flags name the same thing twice, and honouring
	// both would mean silently picking one -- on a flag whose whole purpose is
	// deciding where the advisories came from. Resolved before the target
	// checks so it fails on the command line rather than after a pull.
	advisoryDir := pick(*osvDir, envx.Get("OSV_DIR"))
	advisoryURL := pick(*osvURL, envx.Get("OSV_URL"))
	if advisoryDir != "" && advisoryURL != "" {
		fail("--osv-dir reads a local data export and --osv-url queries an API; pass one")
	}

	logf := func(format string, args ...any) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if inventoryMode {
		runInventory(ctx, analyze.Options{
			Image:        *image,
			RootFS:       *rootfs,
			Repo:         *repo,
			RPM:          rpms,
			SBOM:         *sbom,
			OS:           *goos,
			Arch:         *arch,
			OSVEcosystem: *osvEco,
			Logf:         logf,
		}, *out, *noPager, logf)
		return
	}

	opts := analyze.Options{
		Image:              *image,
		RootFS:             *rootfs,
		Repo:               *repo,
		RPM:                rpms,
		RPMDeep:            *rpmDeep,
		SBOM:               *sbom,
		Ref:                *ref,
		Path:               *repoPath,
		Packages:           packages,
		Module:             *module,
		All:                *all,
		Ecosystems:         ecosystems,
		Severities:         keep,
		CVEs:               cves,
		Version:            *modVersion,
		OS:                 *goos,
		Arch:               *arch,
		OSVEcosystem:       *osvEco,
		OSVBaseURL:         advisoryURL,
		OSVDir:             advisoryDir,
		Roots:              roots,
		VEXHubs:            vexhubs,
		Triage:             triageLoader(*triageOn),
		DistroFeeds:        distroFeedProviders,
		VendorScorers:      vendorScorers,
		DlopenPolicy:       dlopenPolicy,
		DynamicPolicy:      dynamicPolicy,
		GoVersion:          *goVersion,
		UseLLM:             *useLLM,
		LLMEndpoint:        *llmURL,
		LLMModel:           *llmModel,
		LLMCommand:         *llmCommand,
		MineAdvisories:     *mine,
		TrustImportAbsence: *trustAbs,
		Logf:               logf,
	}
	// A misspelled selector is a command-line error, so it exits 2 and it says
	// so before the pull rather than after it.
	if err := analyze.Validate(opts); err != nil {
		fail("%v", err)
	}

	// The command owns the clock; see analyze.Descriptor for why the package
	// does not read one.
	started := time.Now().UTC()
	res, err := analyze.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	stampDescriptor(res, started, time.Since(started))

	// Resolved here and not in the writers, because the escapes have to be in
	// the string before emit decides where it goes -- and where it goes is half
	// of what decides whether they belong in it.
	pal := colors.palette(destination{file: *out != "", gist: *gistFlag, json: *format == "json" || *format == "sarif"})

	var rendered string
	switch *format {
	case "json":
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		rendered = string(b) + "\n"
	case "sarif":
		b, err := renderSARIF(res)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		rendered = b
	case "fixplan":
		rendered = renderFixPlan(res, renderOpts{pal: pal})
	default: // --format was validated up front; inventory returned earlier
		rendered = renderText(res, renderOpts{details: *details, pal: pal})
	}

	emit(rendered, *out, *noPager, logf)

	if *gistFlag {
		url, err := uploadGist(ctx, res, rendered, *format, !*gistSecret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: gist upload failed: %v\n", err)
			os.Exit(1)
		}
		logf("Uploaded report to gist")
		fmt.Println(url)
	}

	// The report is written first and the failure reported after, because an
	// incomplete report is still worth having -- but it must never exit 0. A
	// zero status on a scan that could not read a package database is how a
	// broken CI job passes.
	if res.Failed() {
		for _, e := range res.Ecosystems {
			if e.Error != "" {
				fmt.Fprintf(os.Stderr, "error: ecosystem %s did not complete: %s\n", e.ID, e.Error)
			}
		}
		if u := res.Unreadable; u != nil && u.Any() {
			fmt.Fprintf(os.Stderr, "error: %d path(s) in the target could not be read: %s\n",
				u.Count, strings.Join(u.Paths, ", "))
		}
		// The scan losing an ecosystem outranks the gate, and the gate is not
		// even consulted: a finding count from a partial scan is not a number
		// worth deciding a build on, and a clean gate over it would be the
		// scan's own hole reported as a pass.
		if gate.on {
			fmt.Fprintln(os.Stderr, "error: --fail-on was not evaluated, because the scan did not complete")
		}
		os.Exit(1)
	}

	// --vex-out only runs on a complete scan: an incomplete one might have
	// missed the very component that would have kept a finding out of RULED OUT,
	// and a not_affected statement written from a partial scan is exactly the
	// kind of wrong this tool must never be. It runs before the gate because the
	// gate decides a build's fate, which is unrelated to whether a hub should
	// learn what was ruled out.
	if *vexOut != "" {
		if err := runVexOut(ctx, res, vexOutOptions{
			dir:       *vexOut,
			author:    *vexAuthor,
			hubs:      vexhubs,
			timestamp: started.UTC().Format(time.RFC3339),
			logf:      logf,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "error: vex-out: %v\n", err)
			os.Exit(1)
		}
	}

	if gate.on {
		g := gate.evaluate(res)
		if g.unweighable > 0 {
			// Not gated on --quiet. A gate that passed because it could not
			// read a number has to say so whatever the logging setting, or the
			// silence is indistinguishable from a clean result.
			fmt.Fprintf(os.Stderr,
				"note: %d counted finding(s) have no published severity and could not be weighed against %s.\n"+
					"      Use --fail-on any to gate on their presence.\n", g.unweighable, gate.label)
		}
		if g.tripped > 0 {
			fmt.Fprintln(os.Stderr, gate.describe(g))
			os.Exit(exitGate)
		}
	}
}

// emit delivers a rendered report: to a file with --out, through a pager when
// someone is watching, and to stdout otherwise.
//
// Both output paths go through here so that --format inventory pages exactly
// like a scan does, and so there is one answer to "where did the report go".
//
// Paging is skipped for --out (nothing reaches stdout), for --no-pager, for an
// empty pager setting, and whenever stdout is not a character device -- a pipe,
// a redirect, a CI log. The bytes are identical in every case; the only
// question here is whether less gets to hold them first.
func emit(rendered, out string, noPager bool, logf func(string, ...any)) {
	if out != "" {
		if err := os.WriteFile(out, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		logf("Wrote %s", out)
		return
	}
	// page reports false for every failure it can have, including a $PAGER
	// naming something that is not installed, so the report is still printed.
	if !noPager && stdoutIsTerminal() && page(rendered) {
		return
	}
	fmt.Print(rendered)
}

// stampDescriptor fills in the half of the report's provenance that only the
// command knows: which build ran, when it started, and how long it took.
//
// Run always leaves a descriptor carrying the advisory source, so this adds to
// it rather than replacing it -- but it tolerates a nil one, because a Result
// built by anything other than Run is still a Result worth stamping.
func stampDescriptor(res *analyze.Result, started time.Time, took time.Duration) {
	if res.Descriptor == nil {
		res.Descriptor = &analyze.Descriptor{}
	}
	res.Descriptor.Tool = buildinfo.Name
	res.Descriptor.Version = buildinfo.Version()
	res.Descriptor.Started = started
	res.Descriptor.Duration = took.Round(100 * time.Millisecond).String()
}

// countNamed reports how many of the target flags were given a value.
func countNamed(vals ...string) int {
	n := 0
	for _, v := range vals {
		if v != "" {
			n++
		}
	}
	return n
}

// triageLoader is the feed loader for --triage, or nil when the flag is off.
//
// Options.Triage is a loader rather than a bool so that tests can point it at
// their own feeds, and nil is the off switch: with no loader the overlay never
// runs, every Priority stays nil, and the report renders exactly as it did
// before any of this existed.
func triageLoader(on bool) *triage.Loader {
	if !on {
		return nil
	}
	return triage.New()
}

// distroSources resolves the two flags that draw on a vendor's security data:
// --distro-feeds, which clears false positives, and --prefer-vendor, which
// favours a vendor's own CVSS score. It returns the feed providers the first
// turns on and the scorers the second names, in --prefer-vendor priority order.
//
// The two are built together so a vendor consulted by both is a single instance,
// which matters because the SUSE provider caches the CSAF documents it reads: a
// scan run with `--distro-feeds --prefer-vendor suse` then downloads each
// document once and both the score pass and the verdict pass share it.
//
// A --prefer-vendor name for a vendor that publishes no score vexscan can read is
// reported and dropped rather than silently ignored: today only SUSE does, so
// `--prefer-vendor debian` says so instead of quietly changing nothing.
func distroSources(feedsOn bool, prefer []string) ([]distrofeed.Provider, []distrofeed.Scorer) {
	// One instance per vendor, shared between the two lists.
	suseP := suse.New()

	var scorers []distrofeed.Scorer
	seen := map[string]bool{}
	for _, name := range prefer {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		switch key {
		case "suse":
			scorers = append(scorers, suseP)
		default:
			fmt.Fprintf(os.Stderr, "warning: --prefer-vendor %q is not a vendor vexscan can score today (known: suse); ignoring it\n", name)
		}
	}

	var feeds []distrofeed.Provider
	if feedsOn {
		// Each feed is keyed to the os-release it Handles, so an image only ever
		// consults the one that speaks for it: Debian's security tracker for
		// Debian, SUSE's CSAF-VEX for the SUSE Linux Enterprise family (including
		// SLE BCI images). Red Hat CSAF and Alpine secdb join as they land.
		feeds = []distrofeed.Provider{debian.New(), suseP}
	}
	return feeds, scorers
}

// pick returns the first non-empty of its arguments, which is how a flag that
// also has an environment variable resolves: the flag was typed for this run
// and the variable was exported for all of them.
func pick(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// fail prints a usage error and exits 2.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	flag.Usage()
	os.Exit(2)
}

// runInventory handles --format inventory, which lists the target's OS packages
// and exits without resolving a single advisory.
func runInventory(ctx context.Context, opts analyze.Options, out string, noPager bool, logf func(string, ...any)) {
	inv, err := analyze.Inventory(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	emit(renderInventory(inv), out, noPager, logf)

	// Written first, then failed: an inventory with holes in it is still worth
	// reading, and still not something a CI job should treat as the list.
	if u := inv.Unreadable; u != nil && u.Any() {
		fmt.Fprintf(os.Stderr, "error: %d path(s) could not be read: %s\n",
			u.Count, strings.Join(u.Paths, ", "))
		os.Exit(1)
	}
}

func renderInventory(inv *analyze.InventoryResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vexscan inventory for %s\n", inv.Target)
	if u := inv.Unreadable; u != nil && u.Any() {
		fmt.Fprintf(&b, "INCOMPLETE: %d path(s) could not be read, so this list has an unknown number of omissions:\n", u.Count)
		for _, p := range u.Paths {
			fmt.Fprintf(&b, "  %s\n", p)
		}
		if u.Count > len(u.Paths) {
			fmt.Fprintf(&b, "  ... and %d more\n", u.Count-len(u.Paths))
		}
	}

	for _, note := range inv.Notes {
		// NOTE and not INCOMPLETE: nothing was lost, and a reader who takes
		// this list for the whole document would be wrong in a way that is
		// worth one line to prevent.
		fmt.Fprintf(&b, "NOTE: %s\n", note)
	}

	switch {
	case inv.OS == nil && inv.Mode == "sbom":
		// Not the same statement as the one below. There was no os-release to
		// fail to read; the document simply named no OS package, and calling
		// that "unknown" would send someone looking for a file that was never
		// part of this input.
		b.WriteString("os:        not described (this document names no OS package)\n")
	case inv.OS == nil:
		b.WriteString("os:        unknown (no readable /etc/os-release)\n")
	default:
		name := inv.OS.PrettyName
		if name == "" {
			name = strings.TrimSpace(inv.OS.ID + " " + inv.OS.VersionID)
		}
		fmt.Fprintf(&b, "os:        %s\n", name)
		if inv.OS.Ecosystem != "" {
			fmt.Fprintf(&b, "ecosystem: %s\n", inv.OS.Ecosystem)
		} else {
			// Worth shouting about: with no ecosystem there is nothing to
			// query, and a scan would come back empty rather than clean.
			fmt.Fprintf(&b, "ecosystem: UNRESOLVED - %s\n", inv.OS.EcosystemError)
		}
	}

	if len(inv.Databases) == 0 {
		b.WriteString("\nNo dpkg, apk or rpm database found.\n")
	} else {
		fmt.Fprintf(&b, "packages:  %d\n", inv.Packages())
		for _, db := range inv.Databases {
			fmt.Fprintf(&b, "\n%s (%d packages, %s)\n", db.Format, len(db.Packages), db.DB)
			for _, p := range db.Packages {
				// The queried names are shown because they are the part a user is
				// most likely to want to check: OSV keys Debian and Alpine on the
				// source package, not the one the database lists.
				names := strings.Join(p.OSVNames(), ", ")
				fmt.Fprintf(&b, "  %-32s %-28s %-8s %s\n", p.Name, p.Version, p.Arch, names)
			}
		}
	}

	for _, l := range inv.Languages {
		fmt.Fprintf(&b, "\n%s (%d packages, %s)\n", l.Format, len(l.Packages), strings.Join(l.Roots, ", "))
		for _, p := range l.Packages {
			// The import names are shown next to the project name because their
			// divergence is the whole reason this reader exists: PyYAML installs
			// "yaml", and a reader checking a finding needs to see the mapping
			// the graph will be rooted on. A "?" marks a guess rather than
			// something the distribution's own metadata stated.
			imports := strings.Join(p.ImportNames, ", ")
			if !p.ImportNamesKnown {
				imports += " (guessed)"
			}
			files := fmt.Sprintf("%d files", len(p.Files))
			if !p.FilesKnown {
				files += " (no manifest)"
			}
			fmt.Fprintf(&b, "  %-32s %-16s %-20s %s\n", p.Name, p.Version, files, imports)
		}
		for _, m := range l.Unreadable {
			fmt.Fprintf(&b, "  ! unreadable manifest %s\n", m)
		}
	}
	return b.String()
}

// uploadGist pushes the rendered report to a GitHub gist and returns its URL.
func uploadGist(ctx context.Context, res *analyze.Result, rendered, format string, public bool) (string, error) {
	client, err := gist.NewClient("")
	if err != nil {
		return "", err
	}
	filename := "vexscan-report.txt"
	switch format {
	case "json":
		filename = "vexscan-report.json"
	case "sarif":
		filename = "vexscan-report.sarif"
	}
	desc := fmt.Sprintf("vexscan %s report for %s", res.Mode, res.Target)
	if res.Module != "" {
		desc += fmt.Sprintf(" (module %s)", res.Module)
	}
	return client.Create(ctx, filename, desc, rendered, public)
}

func parseCVEs(flagVal, file string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, part := range strings.Split(flagVal, ",") {
		add(part)
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read --cves-file: %v\n", err)
			os.Exit(2)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			add(line)
		}
	}
	return out
}

func usage() {
	// WriteString rather than Fprint: the purl example contains %2F, which vet
	// reads as a stray formatting directive in anything Printf-shaped.
	os.Stderr.WriteString(`vexscan - check whether a CVE's vulnerable code is actually present in an image, a filesystem, or a source repo

Every ecosystem brings its own deterministic presence test: pclntab
dead-code-elimination evidence and govulncheck for Go, the dynamic linker's
DT_NEEDED closure for OS packages, and the installed-distribution manifest plus
a static import closure for Python and npm. The LLM, if enabled, only ever
comments on what those tests could not rule out.

Usage:
  vexscan --image  REF  (--package SPEC... | --cves LIST | --all) [flags]
  vexscan --rootfs DIR  (--package SPEC... | --cves LIST | --all) [flags]
  vexscan --repo   REPO (--package SPEC... | --cves LIST | --all) [flags]
  vexscan --rpm    FILE (--package SPEC... | --cves LIST | --all) [flags]
  vexscan --sbom   FILE (--package SPEC... | --cves LIST | --all) [flags]
  vexscan --version

--rootfs runs the same analysis against a tree already on disk. It arrives with
no image config, so nothing declares an entrypoint: the language plugins mark
their conclusions undetermined and the shared-library closure falls back to
rooting every program it finds. Pass --roots to say what actually runs.

--rpm and --sbom scan packages nobody installed, so there is no filesystem to
trace and no reachability test can run. --rpm still reads each header's file
list, which is enough to rule out a package that ships no executable code at
all; a CycloneDX component carries no file list, so --sbom can rule out nothing
and every finding it produces is undetermined. The report says so at both ends.
Use them to triage a build artifact or a bill of materials; scan the image or
the tree when you want an answer about whether the code can run.

  syft debian:12 -o cyclonedx-json | vexscan --sbom - --all
  vexscan --sbom bom.json --all --ecosystem golang

--llm has no default provider. Point it at any OpenAI-compatible endpoint, at a
model running on this machine, or at a CLI you already have logged in:

  --llm-endpoint https://api.openai.com/v1/chat/completions   # VEXSCAN_LLM_TOKEN
  --llm-endpoint http://localhost:11434/v1/chat/completions --llm-model llama3.1
  --llm-command 'claude -p'

Whichever you pick cannot change a deterministic conclusion: the verdict is an
overlay on a finding that already has a status, and a mined symbol is checked
against the artifact before it can support one.

A --package SPEC is a purl, an "ecosystem:name" shorthand, or a bare name
resolved against whatever inventory contains it:

  golang:golang.org/x/net    deb:openssl    apk:musl    openssl
  pypi:PyYAML                pkg:pypi/pyyaml@6.0.1
  npm:@babel/traverse        pkg:npm/lodash@4.17.20
  pkg:golang/golang.org%2Fx%2Fnet@v0.17.0

Examples:
  # One Go module in a container image (pclntab + govulncheck binary mode)
  vexscan --image rancher/hardened-kubernetes:v1.30.1 \
    --package golang:golang.org/x/net --cves CVE-2023-39325,CVE-2023-44487

  # Where does this CVE land, anywhere in the image? (searches every ecosystem)
  vexscan --image debian:12 --cves CVE-2024-5535

  # One OS package, with the shared-library closure as the presence test
  vexscan --image debian:12 --package deb:openssl

  # Everything the image installs, OS packages only -- a table sorted by severity
  vexscan --image registry.access.redhat.com/ubi9/ubi:latest --all --ecosystem os

  # ... and the evidence behind every row of it
  vexscan --image registry.access.redhat.com/ubi9/ubi:latest --all --ecosystem os --details

  # ... or just the ones worth waking someone for (the report says what it hid)
  vexscan --image debian:12 --all --ecosystem os --severity CRITICAL,HIGH

  # ... or ordered by whether anyone is actually exploiting them, which is a
  # different question from severity and often a differently-ordered table
  vexscan --image debian:12 --all --ecosystem os --triage

  # One Python distribution, by any spelling of its name
  vexscan --image python:3.12-slim --package pypi:PyYAML

  # Every Node package the image installs, with the require closure applied
  vexscan --image node:22-slim --all --ecosystem npm

  # A filesystem tree rather than an image, with the entrypoint supplied
  vexscan --rootfs /mnt/rootfs --all --roots /usr/bin/myapp

  # Source repo (govulncheck source-mode reachability)
  vexscan --repo github.com/rancher/rancher \
    --package golang:golang.org/x/net --cves CVE-2023-39325

  # Standard library CVEs
  vexscan --image myorg/app:latest --package golang:stdlib --cves CVE-2025-22870
  vexscan --repo github.com/rancher/rancher --package golang:stdlib --go-version 1.24.0

  # A bill of materials from a build, with no image to hand
  vexscan --sbom sbom.cdx.json --all
  syft myorg/app:latest -o cyclonedx-json | vexscan --sbom - --all

  # List the packages in an image, with the names OSV will be queried by
  vexscan --image debian:12 --format inventory
  vexscan --rootfs /mnt/rootfs --format inventory

  # A remediation-first view: which packages to upgrade, and to what
  # (a current debian:12 is fully patched, so pick a tag that is behind)
  vexscan --image debian:bookworm-20230919 --all --format fixplan

  # SARIF for a code-scanning dashboard; ruled-out findings arrive suppressed
  vexscan --image myorg/app:latest --all --format sarif --out results.sarif

  # With an exploitability overlay, from a model running locally
  vexscan --image myorg/app:latest --all --llm \
    --llm-endpoint http://localhost:11434/v1/chat/completions --llm-model llama3.1

  # ... or from a CLI already installed and logged in
  vexscan --image myorg/app:latest --all --llm --llm-command 'claude -p'

  # Share the report as a public gist (needs GITHUB_TOKEN/GH_TOKEN with gist scope)
  vexscan --image rancher/hardened-kubernetes:v1.30.1 \
    --package golang:golang.org/x/net --cves CVE-2023-39325 --gist

  # Write what this scan ruled out into a clone of the hub, ready to review
  gh repo clone rancher/vexhub
  vexscan --image rancher/hardened-kubernetes:v1.30.1 --all \
    --vexhub ./vexhub --vex-out ./vexhub --vex-author 'Acme Security'
  git -C vexhub diff        # then contrib/vexhub-pr.sh, or commit it yourself

--triage answers a question severity does not: is anyone exploiting this? It
downloads EPSS (a 30-day exploitation-activity forecast, per CVE) and CISA's
known-exploited catalog, and reorders the table by them. Neither feed changes a
status or a severity: whether a vulnerability is being exploited elsewhere says
nothing about whether the code is present here. Both are keyed by CVE, so an
advisory that never got one cannot be scored, and the report names those rather
than filing them as zero. Absence from the KEV catalog means nothing at all.

Advisories come from api.osv.dev unless you say otherwise. Two flags say
otherwise, and they differ in who decides which advisories apply, not just in
where the bytes come from:

  vexscan --image myorg/app:latest --all --osv-url http://osv-proxy.corp:8000
  gsutil -m rsync -r gs://osv-vulnerabilities /srv/osv
  vexscan --image myorg/app:latest --all --osv-dir /srv/osv

--osv-url still queries a v1 OSV API, just a different one: a caching proxy in
front of osv.dev, or a mirror serving your own feed. osv.dev still matches the
installed version against each advisory's ranges. Use it to cut egress or to
pin a scan to a vendor's advisory set.

--osv-dir needs no server at all. It reads OSV's published data export -- the
same records the API serves -- from a directory or an all.zip, which makes it
the flag for a host with no network. The version matching then happens on this
machine, against dpkg, rpm, apk and semver ordering. Where no comparator can
order an ecosystem the advisory is kept rather than dropped, and the report
says how many and which: over-matching costs a reader a dismissal, and
under-matching costs them the vulnerability. Pass one or the other, never both.

--version prints vexscan's own version and exits. It used to mean "override the
module version read from a binary's build info"; that setting is now spelled
--module-version, and --version=VERSION still works with a warning for one more
release. vexscan takes no positional arguments, so "--version 1.2.3" is an
error rather than a scan of the wrong version.

A report longer than one screen is paged through $VEXSCAN_PAGER, $PAGER or
less, and repeats its summary and any INCOMPLETE notes at the bottom. Piped,
redirected or written with --out it is never paged, and the bytes are the same
either way. --no-pager turns it off for one run; VEXSCAN_PAGER= for good.

--color auto (the default) colours the text report on a terminal and nowhere
else: not into a pipe, not into --out, not into a --gist, not into JSON, and
not when NO_COLOR is set. --color always overrides all of that except JSON, for
piping into "less -R". Nothing is said in colour alone -- stripping the escapes
from a coloured report reproduces the plain one byte for byte.

--fail-on gates a pipeline on the findings. It is off by default, and it counts
only findings whose vulnerable code is present and loadable, unless
--fail-on-status widens it:

  vexscan --image myorg/app:latest --all --fail-on high
  vexscan --image myorg/app:latest --all --fail-on any --fail-on-status affected,undetermined

That default is the difference worth having. "--fail-on high" here means a HIGH
whose code the closure actually reached, not a HIGH whose version string
appears in a package database -- so a passing gate is a statement about the
image rather than about a filter. Severities order as the table orders them, so
an unrated finding counts from MEDIUM down; above that it cannot be weighed,
and the run says how many it could not weigh rather than passing quietly.

Exit status:
  0  the scan completed
  1  the scan failed, or an ecosystem could not be read (the report says which)
  2  the command line was wrong
  3  the scan completed and --fail-on matched (never mixed with 1: a broken
     scan is not a clean gate, and its findings are not counted at all)

Flags:
`)
	flag.PrintDefaults()
}
