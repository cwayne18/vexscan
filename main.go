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

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/cvss"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/gist"
	"github.com/cwayne18/vexscan/internal/modgraph"
)

func main() {
	var packages, ecosystems, roots, vexhubs, severities stringList
	flag.Var(&packages, "package", "package to check: a purl, an ecosystem:name shorthand (deb:openssl, golang:golang.org/x/net), or a bare name resolved against the inventory; repeatable")
	flag.Var(&ecosystems, "ecosystem", "restrict the scan to these ecosystems (golang, os, pypi, npm, maven, or a distro family like debian); repeatable, default all")
	flag.Var(&roots, "roots", "extra entrypoints for the reachability closures (shared libraries and language imports), for an image whose real command comes from outside its config; repeatable")
	flag.Var(&vexhubs, "vexhub", "VEX Hub repository to check findings against, e.g. https://github.com/rancher/vexhub (also accepts a raw base URL or a local directory); repeatable, earliest wins")
	flag.Var(&severities, "severity", "only report findings at these severities: "+
		strings.Join(cvss.Labels, ", ")+"; comma-separated or repeatable "+
		"(UNKNOWN means no rating was published, and must be named to be shown -- "+
		"every --repo finding is UNKNOWN, because govulncheck's OpenVEX carries no severity)")
	var (
		image      = flag.String("image", "", "container image reference to inspect (mutually exclusive with --rootfs and --repo)")
		rootfs     = flag.String("rootfs", "", "filesystem tree already on disk to inspect -- an unpacked image, a mounted volume, a machine's own / (mutually exclusive with --image and --repo)")
		repo       = flag.String("repo", "", "git source repo to analyze via govulncheck source mode, e.g. github.com/rancher/rancher (mutually exclusive with --image and --rootfs)")
		ref        = flag.String("ref", "", "branch, tag, or commit to check out for --repo (default: repo default branch)")
		repoPath   = flag.String("repo-path", ".", "module subdirectory within --repo to scan")
		module     = flag.String("module", "", "deprecated alias for --package golang:MODULE")
		all        = flag.Bool("all", false, "check everything each ecosystem can inventory, instead of named packages")
		cvesFlag   = flag.String("cves", "", "comma-separated CVE/GHSA/GO ids to check; alone, they are resolved against the whole target")
		cvesFile   = flag.String("cves-file", "", "path to a file with one CVE/GHSA/GO id per line (merged with --cves)")
		version    = flag.String("version", "", "override the module version (image mode only; default: read from each binary's build info)")
		goVersion  = flag.String("go-version", "", "pin the Go toolchain for --repo analysis, e.g. 1.24.0 (useful with --package golang:stdlib)")
		goos       = flag.String("os", "linux", "image OS variant to pull (image mode)")
		arch       = flag.String("arch", "amd64", "image architecture variant to pull (image mode)")
		osvEco     = flag.String("osv-ecosystem", "", "override the OSV ecosystem derived from the image's os-release, e.g. 'Debian:12'")
		dlopen     = flag.String("dlopen-policy", "taint", "what a reachable dlopen does to the closure: taint (block conclusions) or assume-none")
		dynamic    = flag.String("dynamic-import-policy", "taint", "what an import of a computed name does to a language import graph: taint (block conclusions) or assume-none; these are far more common than dlopen, so assume-none discards much more")
		mine       = flag.Bool("mine-advisories", false, "with --llm, let the model read each advisory's prose for symbols to check against the image")
		trustAbs   = flag.Bool("trust-import-absence", false, "let a missing dynamic import of the vulnerable symbol conclude not_in_execute_path (see README: this is weaker than it looks)")
		useLLM     = flag.Bool("llm", false, "consult a chat model on genuinely-affected CVEs for exploitability (needs a provider: --llm-endpoint or --llm-command)")
		llmURL     = flag.String("llm-endpoint", "", "OpenAI-compatible chat/completions URL for --llm -- an API provider, or a local Ollama (env: VEXSCAN_LLM_ENDPOINT; credential: VEXSCAN_LLM_TOKEN)")
		llmModel   = flag.String("llm-model", "", "model id for --llm-endpoint (env: VEXSCAN_LLM_MODEL; default gpt-4o)")
		llmCommand = flag.String("llm-command", "", "for --llm, run this installed CLI instead of calling an endpoint, e.g. 'claude -p'; the prompt arrives on its stdin (env: VEXSCAN_LLM_COMMAND)")
		format     = flag.String("format", "text", "output format: text, json, or inventory (list the image's OS packages and exit)")
		details    = flag.Bool("details", false, "with --format text, print the full evidence block under each row instead of the table alone")
		out        = flag.String("out", "", "write output to this file instead of stdout")
		gistFlag   = flag.Bool("gist", false, "also upload the output to a public GitHub gist and print its URL (needs GITHUB_TOKEN/GH_TOKEN with gist scope)")
		gistSecret = flag.Bool("gist-secret", false, "with --gist, create a secret (unlisted) gist instead of a public one")
		quiet      = flag.Bool("quiet", false, "suppress progress logging on stderr")
	)
	flag.Usage = usage
	flag.Parse()

	// --format inventory answers "what is installed in this image", which
	// needs no subject and no advisory lookup.
	inventoryMode := *format == "inventory"

	if named := countNamed(*image, *rootfs, *repo); named != 1 {
		fail("set exactly one of --image, --rootfs or --repo")
	}
	switch *format {
	case "text", "json", "inventory":
	default:
		fail("unknown --format %q; want text, json, or inventory", *format)
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
			OS:           *goos,
			Arch:         *arch,
			OSVEcosystem: *osvEco,
			Logf:         logf,
		}, *out, logf)
		return
	}

	opts := analyze.Options{
		Image:              *image,
		RootFS:             *rootfs,
		Repo:               *repo,
		Ref:                *ref,
		Path:               *repoPath,
		Packages:           packages,
		Module:             *module,
		All:                *all,
		Ecosystems:         ecosystems,
		Severities:         keep,
		CVEs:               cves,
		Version:            *version,
		OS:                 *goos,
		Arch:               *arch,
		OSVEcosystem:       *osvEco,
		Roots:              roots,
		VEXHubs:            vexhubs,
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

	res, err := analyze.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var rendered string
	switch *format {
	case "json":
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		rendered = string(b) + "\n"
	default: // --format was validated up front; inventory returned earlier
		rendered = renderText(res, *details)
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		logf("Wrote %s", *out)
	} else {
		fmt.Print(rendered)
	}

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
		os.Exit(1)
	}
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

// fail prints a usage error and exits 2.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	flag.Usage()
	os.Exit(2)
}

// runInventory handles --format inventory, which lists the target's OS packages
// and exits without resolving a single advisory.
func runInventory(ctx context.Context, opts analyze.Options, out string, logf func(string, ...any)) {
	inv, err := analyze.Inventory(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	rendered := renderInventory(inv)
	if out != "" {
		if err := os.WriteFile(out, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		logf("Wrote %s", out)
	} else {
		fmt.Print(rendered)
	}

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

	switch {
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
	if format == "json" {
		filename = "vexscan-report.json"
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

--rootfs runs the same analysis against a tree already on disk. It arrives with
no image config, so nothing declares an entrypoint: the language plugins mark
their conclusions undetermined and the shared-library closure falls back to
rooting every program it finds. Pass --roots to say what actually runs.

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

  # List the packages in an image, with the names OSV will be queried by
  vexscan --image debian:12 --format inventory
  vexscan --rootfs /mnt/rootfs --format inventory

  # With an exploitability overlay, from a model running locally
  vexscan --image myorg/app:latest --all --llm \
    --llm-endpoint http://localhost:11434/v1/chat/completions --llm-model llama3.1

  # ... or from a CLI already installed and logged in
  vexscan --image myorg/app:latest --all --llm --llm-command 'claude -p'

  # Share the report as a public gist (needs GITHUB_TOKEN/GH_TOKEN with gist scope)
  vexscan --image rancher/hardened-kubernetes:v1.30.1 \
    --package golang:golang.org/x/net --cves CVE-2023-39325 --gist

Exit status:
  0  the scan completed
  1  the scan failed, or an ecosystem could not be read (the report says which)
  2  the command line was wrong

Flags:
`)
	flag.PrintDefaults()
}
