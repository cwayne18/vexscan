// Package source analyzes a Go project straight from its source repository
// rather than a shipped image. It clones the repo and runs govulncheck in
// source mode, whose call-graph reachability analysis is authoritative (and
// strictly better than the pclntab heuristic used for stripped binaries): for
// every advisory in the dependency graph it reports whether the vulnerable code
// is unused (vulnerable_code_not_present), imported-but-unreachable
// (vulnerable_code_not_in_execute_path) or actually called (affected).
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cwayne18/vexscan/internal/envx"
)

// Statement is one parsed govulncheck OpenVEX statement.
type Statement struct {
	GoID          string   // canonical GO- id (openvex "name")
	Aliases       []string // CVE-/GHSA- ids
	Module        string   // affected module import path (decoded from the purl)
	Version       string   // affected module version
	Status        string   // "affected" | "not_affected"
	Justification string   // openvex justification for not_affected
}

// IDs returns every identifier this statement is known by (GoID + aliases).
func (s Statement) IDs() []string {
	return append([]string{s.GoID}, s.Aliases...)
}

// CloneAndScan clones repoArg (optionally at ref) and runs govulncheck source
// mode from subPath within the checkout. The checkout is removed before return.
// If repoArg points at an existing local directory (or a file:// URL) it is
// scanned in place instead of being cloned. goVersion, when non-empty, pins the
// Go toolchain used for analysis (GOTOOLCHAIN=go<goVersion>), which matters for
// standard-library findings since those depend on the toolchain version.
func CloneAndScan(ctx context.Context, repoArg, ref, subPath, goVersion string, logf func(string, ...any)) ([]Statement, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if local := localPath(repoArg); local != "" {
		workdir := joinSub(local, subPath)
		logf("Scanning local checkout %s...", workdir)
		logf("Running govulncheck (source mode)...")
		return govulncheckSource(ctx, workdir, goVersion)
	}

	dir, err := os.MkdirTemp("", "vexscan-src-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	cloneURL := normalizeRepo(repoArg)
	logf("Cloning %s%s...", cloneURL, refNote(ref))
	if err := clone(ctx, cloneURL, ref, dir); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}

	workdir := joinSub(dir, subPath)
	logf("Running govulncheck (source mode) — this downloads the module graph and may take a while...")
	return govulncheckSource(ctx, workdir, goVersion)
}

// localPath returns a filesystem directory for repoArg when it refers to a
// local checkout (a file:// URL or an existing directory), else "".
func localPath(repoArg string) string {
	if strings.HasPrefix(repoArg, "file://") {
		return strings.TrimPrefix(repoArg, "file://")
	}
	if strings.HasPrefix(repoArg, "/") || strings.HasPrefix(repoArg, "./") || strings.HasPrefix(repoArg, "../") || repoArg == "." {
		if fi, err := os.Stat(repoArg); err == nil && fi.IsDir() {
			return repoArg
		}
	}
	return ""
}

func joinSub(dir, subPath string) string {
	if subPath == "" || subPath == "." {
		return dir
	}
	return dir + string(os.PathSeparator) + strings.TrimPrefix(subPath, "/")
}

// normalizeRepo turns the many accepted forms into an https clone URL:
//
//	github.com/rancher/rancher  -> https://github.com/rancher/rancher.git
//	https://github.com/x/y      -> https://github.com/x/y.git
//	git@github.com:x/y.git      -> git@github.com:x/y.git (left as-is)
//	rancher/rancher             -> https://github.com/rancher/rancher.git
func normalizeRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	if strings.HasPrefix(repo, "git@") || strings.HasPrefix(repo, "ssh://") {
		return repo
	}
	repo = strings.TrimPrefix(repo, "https://")
	repo = strings.TrimPrefix(repo, "http://")
	repo = strings.TrimSuffix(repo, "/")

	// Bare owner/repo with no host -> assume github.com.
	if !strings.Contains(repo, "/") {
		return repo // let git error out meaningfully
	}
	first := repo[:strings.Index(repo, "/")]
	if !strings.Contains(first, ".") {
		repo = "github.com/" + repo
	}
	if !strings.HasSuffix(repo, ".git") {
		repo += ".git"
	}
	return "https://" + repo
}

func refNote(ref string) string {
	if ref == "" {
		return ""
	}
	return " @ " + ref
}

// normalizeGoVersion strips a leading "go" or "v" so a caller may pass "1.24.0",
// "go1.24.0" or "v1.24.0" interchangeably for the toolchain pin.
func normalizeGoVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "go")
	v = strings.TrimPrefix(v, "v")
	return v
}

func clone(ctx context.Context, url, ref, dir string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found on PATH: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Fast path: shallow clone of a branch or tag.
	args := []string{"clone", "--depth", "1", "--quiet"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, url, dir)
	if out, err := run(ctx, "", "git", args...); err == nil {
		return nil
	} else if ref == "" {
		return fmt.Errorf("%w: %s", err, out)
	}

	// Fallback: ref is likely a commit SHA. Blobless clone, then check it out.
	_ = os.RemoveAll(dir)
	if out, err := run(ctx, "", "git", "clone", "--filter=blob:none", "--quiet", url, dir); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	if out, err := run(ctx, dir, "git", "checkout", "--quiet", ref); err != nil {
		return fmt.Errorf("checkout %s: %w: %s", ref, err, out)
	}
	return nil
}

// openVEXDoc mirrors the subset of govulncheck's OpenVEX output we consume.
type openVEXDoc struct {
	Statements []struct {
		Vulnerability struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"vulnerability"`
		Products      []product `json:"products"`
		Status        string    `json:"status"`
		Justification string    `json:"justification"`
	} `json:"statements"`
}

type product struct {
	Subcomponents []struct {
		ID string `json:"@id"`
	} `json:"subcomponents"`
}

// defaultGovulncheckVersion is the module version of govulncheck built and run
// via `go run`. Override with VEXSCAN_GOVULNCHECK_VERSION.
const defaultGovulncheckVersion = "latest"

func govulncheckSource(ctx context.Context, workdir, goVersion string) ([]Statement, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("go toolchain not found on PATH (required for source mode): %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	version := envx.Get("GOVULNCHECK_VERSION")
	if version == "" {
		version = defaultGovulncheckVersion
	}

	// Build and run govulncheck through `go run` from inside the target module
	// rather than invoking a fixed govulncheck binary. This makes source mode
	// robust to modules that require a newer Go than the one vexscan ships
	// with, and avoids two related failure modes:
	//   * a prebuilt govulncheck rejecting a module whose go.mod needs a newer
	//     Go ("go.mod requires go >= 1.26.0 (running go 1.25 ...)"), and
	//   * the "source-processing packages" version mismatch that occurs when the
	//     toolchain loading packages differs from the one govulncheck was built
	//     with.
	// GOTOOLCHAIN=auto lets Go download whatever version the module's go.mod
	// requires; some environments (and the official golang base image) pin it to
	// "local", which would otherwise make source mode fail on newer modules.
	// When the caller pins a Go version (relevant for stdlib findings, which are
	// toolchain-specific) we force that exact toolchain instead.
	toolchain := "GOTOOLCHAIN=auto"
	if goVersion != "" {
		toolchain = "GOTOOLCHAIN=go" + normalizeGoVersion(goVersion)
	}
	pkg := "golang.org/x/vuln/cmd/govulncheck@" + version
	cmd := exec.CommandContext(ctx, goBin, "-C", workdir, "run", pkg, "-format", "openvex", "./...")
	cmd.Env = append(os.Environ(), toolchain)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// govulncheck exits non-zero when vulnerabilities are found; that is not an
	// error for us, so only fail when it produced no parseable output.
	runErr := cmd.Run()

	if strings.TrimSpace(stdout.String()) == "" {
		return nil, diagnoseNoOutput(ctx, runErr, stderr.String())
	}

	var doc openVEXDoc
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("parse govulncheck output: %w", err)
	}

	out := make([]Statement, 0, len(doc.Statements))
	for _, st := range doc.Statements {
		module, version := parsePurl(st.Products)
		out = append(out, Statement{
			GoID:          st.Vulnerability.Name,
			Aliases:       st.Vulnerability.Aliases,
			Module:        module,
			Version:       version,
			Status:        st.Status,
			Justification: st.Justification,
		})
	}
	return out, nil
}

// diagnoseNoOutput turns an empty-stdout govulncheck run into an actionable
// error. The most common cause on very large repos (e.g. rancher/rancher) is
// the OS OOM killer terminating govulncheck mid-analysis: the inner process
// dies with SIGKILL and `go run` reports "signal: killed" on stderr.
func diagnoseNoOutput(ctx context.Context, runErr error, stderr string) error {
	stderrTxt := strings.TrimSpace(stderr)

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("govulncheck timed out (30m) analyzing this repo. "+
			"Very large repos can exceed this; narrow the scan with --repo-path <subdir>, "+
			"or use --image mode against a built image instead.%s", stderrSuffix(stderrTxt))
	}

	if wasKilled(runErr, stderrTxt) {
		return fmt.Errorf("govulncheck was killed before producing output (likely out of memory). "+
			"Source-mode call-graph analysis of large repos such as rancher/rancher can need several GB of RAM. "+
			"Try one of: give the process more memory (in a container, raise the memory limit, e.g. docker run --memory=8g ...); "+
			"scope the scan to a subdirectory with --repo-path <subdir>; "+
			"or use --image mode against a built image instead.%s", stderrSuffix(stderrTxt))
	}

	if stderrTxt == "" && runErr != nil {
		stderrTxt = runErr.Error()
	}
	return fmt.Errorf("govulncheck produced no output: %s", stderrTxt)
}

// wasKilled reports whether the govulncheck run ended in a SIGKILL, either on
// the go-run wrapper itself or on the govulncheck child (which surfaces as a
// "signal: killed" line on stderr).
func wasKilled(runErr error, stderrTxt string) bool {
	if strings.Contains(stderrTxt, "signal: killed") {
		return true
	}
	if ee, ok := runErr.(*exec.ExitError); ok {
		if ps := ee.ProcessState; ps != nil && ps.ExitCode() == -1 {
			return true
		}
	}
	return false
}

func stderrSuffix(stderrTxt string) string {
	if stderrTxt == "" {
		return ""
	}
	return "\ngovulncheck stderr: " + stderrTxt
}

// parsePurl extracts module + version from the first golang purl subcomponent,
// e.g. pkg:golang/golang.org%2Fx%2Fnet@v0.7.0 -> golang.org/x/net, v0.7.0.
func parsePurl(products []product) (module, version string) {
	for _, p := range products {
		for _, sc := range p.Subcomponents {
			id := sc.ID
			const prefix = "pkg:golang/"
			if !strings.HasPrefix(id, prefix) {
				continue
			}
			body := strings.TrimPrefix(id, prefix)
			if at := strings.LastIndex(body, "@"); at >= 0 {
				version = body[at+1:]
				body = body[:at]
			}
			if decoded, err := url.PathUnescape(body); err == nil {
				module = decoded
			} else {
				module = body
			}
			return module, version
		}
	}
	return "", ""
}

func run(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
