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
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/gist"
)

func main() {
	var packages, ecosystems, roots stringList
	flag.Var(&packages, "package", "package to check: a purl, an ecosystem:name shorthand (deb:openssl, golang:golang.org/x/net), or a bare name resolved against the inventory; repeatable")
	flag.Var(&ecosystems, "ecosystem", "restrict the scan to these ecosystems (golang, os, or a distro family like debian); repeatable, default all")
	flag.Var(&roots, "roots", "extra entrypoints for the shared-library closure, for an image whose real command comes from outside its config; repeatable")
	var (
		image      = flag.String("image", "", "container image reference to inspect (mutually exclusive with --repo)")
		repo       = flag.String("repo", "", "git source repo to analyze via govulncheck source mode, e.g. github.com/rancher/rancher (mutually exclusive with --image)")
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
		mine       = flag.Bool("mine-advisories", false, "with --llm, let the model read each advisory's prose for symbols to check against the image")
		trustAbs   = flag.Bool("trust-import-absence", false, "let a missing dynamic import of the vulnerable symbol conclude not_in_execute_path (see README: this is weaker than it looks)")
		useLLM     = flag.Bool("llm", false, "consult a GitHub Models LLM on genuinely-affected CVEs for exploitability")
		llmModel   = flag.String("llm-model", "openai/gpt-4o", "GitHub Models model id for --llm")
		format     = flag.String("format", "text", "output format: text, json, or inventory (list the image's OS packages and exit)")
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

	if (*image == "") == (*repo == "") {
		fail("set exactly one of --image or --repo")
	}
	switch *format {
	case "text", "json", "inventory":
	default:
		fail("unknown --format %q; want text, json, or inventory", *format)
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
		Repo:               *repo,
		Ref:                *ref,
		Path:               *repoPath,
		Packages:           packages,
		Module:             *module,
		All:                *all,
		Ecosystems:         ecosystems,
		CVEs:               cves,
		Version:            *version,
		OS:                 *goos,
		Arch:               *arch,
		OSVEcosystem:       *osvEco,
		Roots:              roots,
		DlopenPolicy:       dlopenPolicy,
		GoVersion:          *goVersion,
		UseLLM:             *useLLM,
		LLMModel:           *llmModel,
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
		rendered = renderText(res)
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
		os.Exit(1)
	}
}

// fail prints a usage error and exits 2.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	flag.Usage()
	os.Exit(2)
}

// runInventory handles --format inventory, which lists the image's OS packages
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
		return
	}
	fmt.Print(rendered)
}

func renderInventory(inv *analyze.InventoryResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vexscan inventory for %s\n", inv.Target)

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
		return b.String()
	}

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

func renderText(res *analyze.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vexscan report (%s) for %s\n", res.Mode, res.Target)
	if res.Module != "" {
		fmt.Fprintf(&b, "module: %s\n", res.Module)
	}
	for _, e := range res.Ecosystems {
		if e.Error != "" {
			// Above the findings, not below: a reader who stops after the
			// summary must still see that part of the target went unexamined.
			fmt.Fprintf(&b, "INCOMPLETE: ecosystem %s did not run - %s\n", e.ID, e.Error)
		}
	}
	b.WriteString("\n")

	if len(res.Findings) == 0 {
		// Empty because nothing was wrong and empty because nothing was read
		// look identical, and only one of them is good news.
		if res.Failed() {
			b.WriteString("No findings, but the scan was incomplete: see above.\n")
			b.WriteString("This is not a clean result.\n")
		} else {
			b.WriteString("No findings: nothing selected was found in this target,\n")
			b.WriteString("or no matching advisories were published for it.\n")
		}
		return b.String()
	}

	// Group by status for a readable summary.
	counts := map[analyze.Status]int{}
	for _, f := range res.Findings {
		counts[f.Status]++
	}
	fmt.Fprintf(&b, "summary: %d not_present, %d not_in_execute_path, %d linked, %d reachable, %d undetermined\n\n",
		counts[analyze.StatusNotPresent], counts[analyze.StatusNotInPath],
		counts[analyze.StatusLinked], counts[analyze.StatusReachable],
		counts[analyze.StatusUndetermined])

	for _, f := range res.Findings {
		id := f.CVE
		if f.GoID != "" && f.GoID != f.CVE {
			id = fmt.Sprintf("%s (%s)", f.CVE, f.GoID)
		}
		fmt.Fprintf(&b, "%-22s %s\n", statusLabel(f.Status), component(f))
		fmt.Fprintf(&b, "  cve:      %s\n", id)
		if f.Ecosystem != "" {
			fmt.Fprintf(&b, "  from:     %s\n", f.Ecosystem)
		}
		if f.Binary != "" {
			fmt.Fprintf(&b, "  binary:   %s%s\n", f.Binary, strippedNote(f.Stripped))
		}
		if len(f.Packages) > 0 {
			fmt.Fprintf(&b, "  packages: %s (%s)\n", strings.Join(f.Packages, ", "), f.Granularity)
		}
		if f.Justification != "" {
			fmt.Fprintf(&b, "  vex:      %s [%s]\n", f.Justification, f.Method)
		} else if f.Method != "" && f.Status == analyze.StatusReachable {
			fmt.Fprintf(&b, "  method:   %s\n", f.Method)
		}
		if f.Reason != "" {
			fmt.Fprintf(&b, "  reason:   %s\n", f.Reason)
		}
		if f.LLM != nil {
			fmt.Fprintf(&b, "  llm:      exploitable=%s confidence=%s\n", f.LLM.Exploitable, f.LLM.Confidence)
			if f.LLM.Rationale != "" {
				fmt.Fprintf(&b, "            %s\n", f.LLM.Rationale)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func statusLabel(s analyze.Status) string {
	switch s {
	case analyze.StatusNotPresent:
		return "[NOT PRESENT]"
	case analyze.StatusNotInPath:
		return "[NOT REACHABLE]"
	case analyze.StatusLinked:
		return "[LINKED]"
	case analyze.StatusReachable:
		return "[REACHABLE]"
	default:
		return "[UNDETERMINED]"
	}
}

// component names what a finding is about. An id that matched nothing in the
// target has no component at all, and printing "@" for it would look like a
// package whose name failed to render.
func component(f analyze.Finding) string {
	switch {
	case f.Package == "":
		return "(no matching component)"
	case f.Version == "":
		return f.Package
	default:
		return f.Package + "@" + f.Version
	}
}

// strippedNote annotates a binary that carries no symbol table. Nil means the
// question does not apply: an OS package is not a Go binary.
func strippedNote(stripped *bool) string {
	if stripped != nil && *stripped {
		return " (stripped)"
	}
	return ""
}

func usage() {
	fmt.Fprint(os.Stderr, `vexscan - check whether a CVE's vulnerable code is actually present in an image or source repo

Every ecosystem brings its own deterministic presence test: pclntab
dead-code-elimination evidence and govulncheck for Go, the dynamic linker's
DT_NEEDED closure for OS packages. The LLM, if enabled, only ever comments on
what those tests could not rule out.

Usage:
  vexscan --image REF  (--package SPEC... | --cves LIST | --all) [flags]
  vexscan --repo  REPO (--package SPEC... | --cves LIST | --all) [flags]

A --package SPEC is a purl, an "ecosystem:name" shorthand, or a bare name
resolved against whatever inventory contains it:

  golang:golang.org/x/net    deb:openssl    apk:musl    openssl
  pkg:golang/golang.org%2Fx%2Fnet@v0.17.0

Examples:
  # One Go module in a container image (pclntab + govulncheck binary mode)
  vexscan --image rancher/hardened-kubernetes:v1.30.1 \
    --package golang:golang.org/x/net --cves CVE-2023-39325,CVE-2023-44487

  # Where does this CVE land, anywhere in the image? (searches every ecosystem)
  vexscan --image debian:12 --cves CVE-2024-5535

  # One OS package, with the shared-library closure as the presence test
  vexscan --image debian:12 --package deb:openssl

  # Everything the image installs, OS packages only
  vexscan --image registry.access.redhat.com/ubi9/ubi:latest --all --ecosystem os

  # Source repo (govulncheck source-mode reachability)
  vexscan --repo github.com/rancher/rancher \
    --package golang:golang.org/x/net --cves CVE-2023-39325

  # Standard library CVEs
  vexscan --image myorg/app:latest --package golang:stdlib --cves CVE-2025-22870
  vexscan --repo github.com/rancher/rancher --package golang:stdlib --go-version 1.24.0

  # List the OS packages in an image, with the names OSV will be queried by
  vexscan --image debian:12 --format inventory

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
