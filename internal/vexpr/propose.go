package vexpr

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/cwayne18/vexscan/internal/analyze"
)

// Options configures a PR proposal.
type Options struct {
	// HubURL is the --vexhub the PR targets. Only a github.com (or its
	// raw.githubusercontent.com form) URL can be turned into a pull request; a
	// raw base or a local directory cannot, and is reported as such.
	HubURL string
	// PushRepo is "owner/repo" to push the branch to -- a fork the caller
	// maintains. Empty pushes a branch straight to the hub repository, which is
	// the right default for a token with write access to it.
	PushRepo string
	// Author overrides the OpenVEX author. Empty derives it from the
	// authenticated GitHub user.
	Author string
	// Token overrides the GitHub token; empty reads GITHUB_TOKEN / GH_TOKEN.
	Token string
	// Version is vexscan's version, recorded in the commit for provenance.
	Version string
	// Timestamp is the scan time, used on every statement so a re-run of the
	// same scan produces the same document.
	Timestamp string
	// Logf receives progress lines. Nil discards them.
	Logf func(string, ...any)

	// apiBase overrides the GitHub API root. It exists for tests, which point
	// it at an httptest server; it is unexported so it cannot leak into the
	// public surface.
	apiBase string
}

// FileChange is one file the PR creates or rewrites, path relative to the
// repository root.
type FileChange struct {
	Path    string
	Content []byte
}

// Plan is everything a PR would change, computed but not yet pushed. It is
// returned so --vexhub-pr-dry-run can show the exact diff before anything is
// written, and Submit turns it into a real pull request.
type Plan struct {
	Changes    []FileChange
	Products   []ProductChange
	Statements int
	// Skipped is how many ruled-out findings could not be written as a
	// matchable statement (no product, component or id).
	Skipped int

	Branch string
	Title  string
	Body   string

	// unexported: what Submit needs to act.
	gh            *githubClient
	pushOwner     string
	pushName      string
	upstreamOwner string
	upstreamName  string
	baseBranch    string
	baseSHA       string
	head          string
}

// ProductChange records, for the summary, which vulnerabilities were added to
// one product's document.
type ProductChange struct {
	Product string
	Vulns   []string
}

// Empty reports whether the plan would change nothing -- every ruled-out finding
// was already covered, or there were none to begin with.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Propose computes the pull request that would add vexscan's ruled-out findings
// to the hub, reading the hub's current state to merge rather than clobber. It
// performs no writes; Submit does.
func Propose(ctx context.Context, res *analyze.Result, opts Options) (*Plan, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	proposals, skipped := selectProposals(res, opts.Timestamp)
	if len(proposals) == 0 {
		return &Plan{Skipped: skipped}, nil
	}

	upstreamOwner, upstreamName, err := parseGitHubRepo(opts.HubURL)
	if err != nil {
		return nil, err
	}
	gh, err := newGitHubClient(opts.Token, opts.Version)
	if err != nil {
		return nil, err
	}
	if opts.apiBase != "" {
		gh.API = opts.apiBase
	}

	login, err := gh.login(ctx)
	if err != nil {
		return nil, err
	}
	author := opts.Author
	if author == "" {
		author = fmt.Sprintf("%s (via vexscan)", login)
	}

	pushOwner, pushName := upstreamOwner, upstreamName
	if opts.PushRepo != "" {
		pushOwner, pushName, err = splitOwnerRepo(opts.PushRepo)
		if err != nil {
			return nil, err
		}
	}

	up, err := gh.repo(ctx, upstreamOwner, upstreamName)
	if err != nil {
		return nil, err
	}
	baseBranch := up.DefaultBranch

	// The branch is created on the push repo, so it must be based on a commit
	// that repo has. For a direct push that is the hub's default head; for a
	// fork it is the fork's own default head, which the contributor keeps in
	// sync.
	baseSHA, err := pushBaseSHA(ctx, gh, pushOwner, pushName, upstreamOwner, upstreamName, baseBranch)
	if err != nil {
		return nil, err
	}

	idxRaw, ok, err := gh.fileAt(ctx, pushOwner, pushName, "index.json", baseSHA)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("vexpr: %s/%s has no index.json; is it a VEX hub?", pushOwner, pushName)
	}
	idx, err := parseIndex(idxRaw)
	if err != nil {
		return nil, err
	}

	var (
		changes      []FileChange
		productChgs  []ProductChange
		stmtTotal    int
		indexTouched bool
	)
	for _, prop := range proposals {
		loc, idxChanged, err := idx.ensure(prop.Product)
		if err != nil {
			logf("  ! vexhub-pr: %s skipped: %v", prop.Product, err)
			continue
		}
		var doc *Doc
		if existing, ok, err := gh.fileAt(ctx, pushOwner, pushName, loc, baseSHA); err != nil {
			return nil, err
		} else if ok {
			if d, ok := ParseDoc(existing); ok {
				doc = d
			}
		}
		if doc == nil {
			doc = NewDoc(author, opts.Timestamp)
		}

		before := len(doc.Statements)
		added := mergeStatements(doc, prop, author, opts.Timestamp)
		if added == 0 {
			// Nothing new for this product: leave the index untouched even if
			// ensure would have added a key (it only does so for a product with
			// no document, which always yields added > 0, so this is a guard).
			continue
		}
		indexTouched = indexTouched || idxChanged

		content, err := doc.Marshal()
		if err != nil {
			return nil, err
		}
		changes = append(changes, FileChange{Path: loc, Content: content})
		stmtTotal += added
		productChgs = append(productChgs, ProductChange{
			Product: prop.Product,
			Vulns:   addedVulns(doc.Statements[before:]),
		})
	}

	if len(changes) == 0 {
		return &Plan{Skipped: skipped}, nil
	}
	if indexTouched {
		idxContent, err := idx.marshal()
		if err != nil {
			return nil, err
		}
		changes = append(changes, FileChange{Path: "index.json", Content: idxContent})
	}

	branch := "vexscan/ruled-out-" + branchStamp(opts.Timestamp)
	head := branch
	if pushOwner != upstreamOwner {
		head = pushOwner + ":" + branch
	}
	title := fmt.Sprintf("Add %d vexscan not_affected statement(s)", stmtTotal)
	body := buildBody(res.Target, opts.Version, productChgs)

	return &Plan{
		Changes:       changes,
		Products:      productChgs,
		Statements:    stmtTotal,
		Skipped:       skipped,
		Branch:        branch,
		Title:         title,
		Body:          body,
		gh:            gh,
		pushOwner:     pushOwner,
		pushName:      pushName,
		upstreamOwner: upstreamOwner,
		upstreamName:  upstreamName,
		baseBranch:    baseBranch,
		baseSHA:       baseSHA,
		head:          head,
	}, nil
}

// Submit pushes the plan as a branch and opens the pull request, returning its
// URL.
func (p *Plan) Submit(ctx context.Context) (string, error) {
	if p.Empty() {
		return "", fmt.Errorf("vexpr: nothing to submit")
	}
	message := p.Title + "\n\n" + p.Body
	sha, err := p.gh.commitFiles(ctx, p.pushOwner, p.pushName, p.baseSHA, message, p.Changes)
	if err != nil {
		return "", err
	}
	if err := p.gh.createBranch(ctx, p.pushOwner, p.pushName, p.Branch, sha); err != nil {
		return "", err
	}
	return p.gh.openPR(ctx, p.upstreamOwner, p.upstreamName, p.head, p.baseBranch, p.Title, p.Body)
}

// pushBaseSHA is the commit a new branch is based on: the hub's default head for
// a direct push, or the fork's own default head for a fork push.
func pushBaseSHA(ctx context.Context, gh *githubClient, pushOwner, pushName, upOwner, upName, upBranch string) (string, error) {
	if pushOwner == upOwner && pushName == upName {
		return gh.branchHead(ctx, upOwner, upName, upBranch)
	}
	fork, err := gh.repo(ctx, pushOwner, pushName)
	if err != nil {
		return "", err
	}
	return gh.branchHead(ctx, pushOwner, pushName, fork.DefaultBranch)
}

// addedVulns lists the vulnerability names of a slice of statements, for the
// summary.
func addedVulns(sts []Statement) []string {
	out := make([]string, 0, len(sts))
	for _, s := range sts {
		out = append(out, s.Vulnerability.Name)
	}
	sort.Strings(out)
	return out
}

// buildBody is the pull request description: what produced it, and every
// statement it adds, grouped by product.
func buildBody(target, version string, products []ProductChange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Automated by [vexscan](https://github.com/cwayne18/vexscan)")
	if version != "" {
		fmt.Fprintf(&b, " %s", version)
	}
	b.WriteString(".\n\n")
	if target != "" {
		fmt.Fprintf(&b, "Scan target: `%s`\n\n", target)
	}
	b.WriteString("These `not_affected` statements record findings vexscan ruled out because " +
		"the vulnerable code is not present or cannot run. Each carries the OpenVEX " +
		"justification behind the verdict; review before merging.\n\n")
	for _, pc := range products {
		fmt.Fprintf(&b, "### `%s`\n", pc.Product)
		for _, v := range pc.Vulns {
			fmt.Fprintf(&b, "- %s\n", v)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// parseGitHubRepo pulls owner and repo out of a hub URL, accepting the same
// github.com form the reader does plus its raw.githubusercontent.com rewrite.
// Anything else -- a bare raw base, a local directory -- cannot become a PR.
func parseGitHubRepo(location string) (owner, repo string, err error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return "", "", fmt.Errorf("vexpr: no --vexhub given to open a PR against")
	}
	if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
		return "", "", fmt.Errorf("vexpr: --vexhub %q is not a GitHub URL; --vexhub-pr needs e.g. https://github.com/rancher/vexhub", location)
	}
	u, err := url.Parse(location)
	if err != nil {
		return "", "", fmt.Errorf("vexpr: %s: %w", location, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch {
	case strings.EqualFold(u.Host, "github.com"):
		if len(parts) < 2 {
			return "", "", fmt.Errorf("vexpr: %s: not an owner/repo URL", location)
		}
		return parts[0], strings.TrimSuffix(parts[1], ".git"), nil
	case strings.EqualFold(u.Host, "raw.githubusercontent.com"):
		if len(parts) < 2 {
			return "", "", fmt.Errorf("vexpr: %s: not an owner/repo URL", location)
		}
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("vexpr: --vexhub host %q is not GitHub; --vexhub-pr can only open PRs against github.com hubs", u.Host)
	}
}

// splitOwnerRepo parses an "owner/repo" push target.
func splitOwnerRepo(s string) (owner, repo string, err error) {
	s = strings.TrimSpace(s)
	owner, repo, ok := strings.Cut(s, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("vexpr: --vexhub-pr-repo %q is not in owner/repo form", s)
	}
	return owner, strings.TrimSuffix(repo, ".git"), nil
}

// branchStamp turns a scan timestamp into a branch-name-safe suffix.
func branchStamp(ts string) string {
	if ts == "" {
		return "latest"
	}
	repl := strings.NewReplacer("-", "", ":", "", ".", "")
	s := repl.Replace(ts)
	if s == "" {
		return "latest"
	}
	return s
}
