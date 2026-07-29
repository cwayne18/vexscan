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
	"github.com/cwayne18/vexscan/internal/gist"
)

func main() {
	var (
		image      = flag.String("image", "", "container image reference to inspect (mutually exclusive with --repo)")
		repo       = flag.String("repo", "", "git source repo to analyze via govulncheck source mode, e.g. github.com/rancher/rancher (mutually exclusive with --image)")
		ref        = flag.String("ref", "", "branch, tag, or commit to check out for --repo (default: repo default branch)")
		repoPath   = flag.String("repo-path", ".", "module subdirectory within --repo to scan")
		module     = flag.String("module", "", "Go module import path to evaluate, or 'stdlib' for the standard library (required)")
		cvesFlag   = flag.String("cves", "", "comma-separated CVE/GHSA/GO ids to check; empty checks every advisory found for the module version")
		cvesFile   = flag.String("cves-file", "", "path to a file with one CVE/GHSA/GO id per line (merged with --cves)")
		version    = flag.String("version", "", "override the module version (image mode only; default: read from each binary's build info)")
		goVersion  = flag.String("go-version", "", "pin the Go toolchain for --repo analysis, e.g. 1.24.0 (useful with --module stdlib)")
		goos       = flag.String("os", "linux", "image OS variant to pull (image mode)")
		arch       = flag.String("arch", "amd64", "image architecture variant to pull (image mode)")
		useLLM     = flag.Bool("llm", false, "consult a GitHub Models LLM on genuinely-affected CVEs for exploitability")
		llmModel   = flag.String("llm-model", "openai/gpt-4o", "GitHub Models model id for --llm")
		format     = flag.String("format", "text", "output format: text or json")
		out        = flag.String("out", "", "write output to this file instead of stdout")
		gistFlag   = flag.Bool("gist", false, "also upload the output to a public GitHub gist and print its URL (needs GITHUB_TOKEN/GH_TOKEN with gist scope)")
		gistSecret = flag.Bool("gist-secret", false, "with --gist, create a secret (unlisted) gist instead of a public one")
		quiet      = flag.Bool("quiet", false, "suppress progress logging on stderr")
	)
	flag.Usage = usage
	flag.Parse()

	if *module == "" {
		fmt.Fprintln(os.Stderr, "error: --module is required")
		flag.Usage()
		os.Exit(2)
	}
	if (*image == "") == (*repo == "") {
		fmt.Fprintln(os.Stderr, "error: set exactly one of --image or --repo")
		flag.Usage()
		os.Exit(2)
	}

	cves := parseCVEs(*cvesFlag, *cvesFile)

	logf := func(format string, args ...any) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	res, err := analyze.Run(ctx, analyze.Options{
		Image:     *image,
		Repo:      *repo,
		Ref:       *ref,
		Path:      *repoPath,
		Module:    *module,
		CVEs:      cves,
		Version:   *version,
		OS:        *goos,
		Arch:      *arch,
		GoVersion: *goVersion,
		UseLLM:    *useLLM,
		LLMModel:  *llmModel,
		Logf:      logf,
	})
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
	case "text":
		rendered = renderText(res)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown --format %q\n", *format)
		os.Exit(2)
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
	desc := fmt.Sprintf("vexscan %s report for %s (module %s)", res.Mode, res.Target, res.Module)
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
	fmt.Fprintf(&b, "module: %s\n\n", res.Module)

	if len(res.Findings) == 0 {
		b.WriteString("No findings: the module was not linked into any Go binary in this image,\n")
		b.WriteString("or no matching advisories were found.\n")
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
		fmt.Fprintf(&b, "%-22s %s@%s\n", statusLabel(f.Status), f.Module, f.Version)
		fmt.Fprintf(&b, "  cve:      %s\n", id)
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

func strippedNote(stripped bool) string {
	if stripped {
		return " (stripped)"
	}
	return ""
}

func usage() {
	fmt.Fprint(os.Stderr, `vexscan - check whether Go-module CVEs are actually present in an image or source repo

Usage:
  vexscan --image REF   --module PATH [--cves LIST] [flags]
  vexscan --repo  REPO  --module PATH [--cves LIST] [flags]

Examples:
  # Container image (pclntab + govulncheck binary mode)
  vexscan --image rancher/hardened-kubernetes:v1.30.1 --module golang.org/x/net \
    --cves CVE-2023-39325,CVE-2023-44487

  # Source repo (govulncheck source-mode reachability)
  vexscan --repo github.com/rancher/rancher --module golang.org/x/net \
    --cves CVE-2023-39325

  # Standard library CVEs (module "stdlib")
  vexscan --image myorg/app:latest --module stdlib --cves CVE-2025-22870
  vexscan --repo github.com/rancher/rancher --module stdlib --go-version 1.24.0

  # Share the report as a public gist (needs GITHUB_TOKEN/GH_TOKEN with gist scope)
  vexscan --image rancher/hardened-kubernetes:v1.30.1 --module golang.org/x/net \
    --cves CVE-2023-39325 --gist

Flags:
`)
	flag.PrintDefaults()
}
