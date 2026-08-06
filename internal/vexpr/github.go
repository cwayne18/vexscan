package vexpr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// defaultAPI is GitHub's REST API root. It is a field on the client so tests can
// point it at an httptest server, the same arrangement internal/gist uses.
const defaultAPI = "https://api.github.com"

// githubClient talks to the GitHub REST API with a token, deliberately not the
// gh CLI: vexscan ships as a container image and this has to work there with the
// same GITHUB_TOKEN / GH_TOKEN the --gist and --llm paths already rely on.
type githubClient struct {
	HTTP    *http.Client
	API     string
	Token   string
	Version string // vexscan version, for the committer identity
}

// newGitHubClient builds a client, reading the token from the argument or, when
// empty, from GITHUB_TOKEN then GH_TOKEN. It errors when none is set, because a
// PR flow that silently did nothing without a token would be worse than one that
// says why up front.
func newGitHubClient(token, version string) (*githubClient, error) {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found (set GITHUB_TOKEN or GH_TOKEN); the token needs pull-request scope on the hub repository")
	}
	return &githubClient{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		API:     defaultAPI,
		Token:   token,
		Version: version,
	}, nil
}

// repoInfo is the slice of a repository's metadata this flow needs.
type repoInfo struct {
	DefaultBranch string `json:"default_branch"`
}

// login returns the authenticated user's handle, used to author the OpenVEX
// document and to build a fork's head ref.
func (c *githubClient) login(ctx context.Context) (string, error) {
	var u struct {
		Login string `json:"login"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/user", nil, &u); err != nil {
		return "", err
	}
	if u.Login == "" {
		return "", fmt.Errorf("vexpr: /user returned no login")
	}
	return u.Login, nil
}

// repo fetches a repository's metadata.
func (c *githubClient) repo(ctx context.Context, owner, name string) (repoInfo, error) {
	var r repoInfo
	_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s", owner, name), nil, &r)
	return r, err
}

// branchHead returns the commit sha a branch points at.
func (c *githubClient) branchHead(ctx context.Context, owner, name, branch string) (string, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	path := fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", owner, name, branch)
	if _, err := c.do(ctx, http.MethodGet, path, nil, &ref); err != nil {
		return "", err
	}
	if ref.Object.SHA == "" {
		return "", fmt.Errorf("vexpr: branch %s has no head sha", branch)
	}
	return ref.Object.SHA, nil
}

// fileAt returns the contents of a file at a commit, and whether it exists. A
// 404 is the ordinary "no document here yet" case and is reported as ok=false,
// not as an error.
func (c *githubClient) fileAt(ctx context.Context, owner, name, path, ref string) (content []byte, ok bool, err error) {
	var resp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", owner, name, path, ref)
	status, err := c.do(ctx, http.MethodGet, endpoint, nil, &resp)
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if resp.Encoding != "base64" {
		return nil, false, fmt.Errorf("vexpr: %s: unexpected content encoding %q", path, resp.Encoding)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(resp.Content, "\n", ""))
	if err != nil {
		return nil, false, fmt.Errorf("vexpr: %s: decode content: %w", path, err)
	}
	return raw, true, nil
}

// treeSHA returns the tree a commit points at, needed as the base for a new
// tree that changes only a few files.
func (c *githubClient) treeSHA(ctx context.Context, owner, name, commitSHA string) (string, error) {
	var commit struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	path := fmt.Sprintf("/repos/%s/%s/git/commits/%s", owner, name, commitSHA)
	if _, err := c.do(ctx, http.MethodGet, path, nil, &commit); err != nil {
		return "", err
	}
	if commit.Tree.SHA == "" {
		return "", fmt.Errorf("vexpr: commit %s has no tree", commitSHA)
	}
	return commit.Tree.SHA, nil
}

// commitFiles writes every change as one commit on top of baseSHA and returns
// the new commit's sha. The files ride in the tree as inline content, so no
// separate blob upload is needed.
func (c *githubClient) commitFiles(ctx context.Context, owner, name, baseSHA, message string, changes []FileChange) (string, error) {
	baseTree, err := c.treeSHA(ctx, owner, name, baseSHA)
	if err != nil {
		return "", err
	}

	type treeEntry struct {
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	entries := make([]treeEntry, 0, len(changes))
	for _, ch := range changes {
		entries = append(entries, treeEntry{
			Path: ch.Path, Mode: "100644", Type: "blob", Content: string(ch.Content),
		})
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	treeReq := map[string]any{"base_tree": baseTree, "tree": entries}
	if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/trees", owner, name), treeReq, &tree); err != nil {
		return "", err
	}

	var commit struct {
		SHA string `json:"sha"`
	}
	commitReq := map[string]any{"message": message, "tree": tree.SHA, "parents": []string{baseSHA}}
	if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/commits", owner, name), commitReq, &commit); err != nil {
		return "", err
	}
	if commit.SHA == "" {
		return "", fmt.Errorf("vexpr: commit response had no sha")
	}
	return commit.SHA, nil
}

// createBranch points a new branch at a commit. A branch that already exists is
// reported as an error rather than force-moved: a name collision means a stale
// branch from a previous run, and clobbering it could discard an open PR.
func (c *githubClient) createBranch(ctx context.Context, owner, name, branch, sha string) error {
	req := map[string]any{"ref": "refs/heads/" + branch, "sha": sha}
	status, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/refs", owner, name), req, nil)
	if status == http.StatusUnprocessableEntity {
		return fmt.Errorf("vexpr: branch %s already exists on %s/%s; delete it or wait for its PR to merge", branch, owner, name)
	}
	return err
}

// openPR opens a pull request against the upstream repository and returns its
// html url. head is "branch" when pushing to the upstream itself, or
// "forkOwner:branch" when pushing from a fork.
func (c *githubClient) openPR(ctx context.Context, owner, name, head, base, title, body string) (string, error) {
	req := map[string]any{"title": title, "head": head, "base": base, "body": body}
	var resp struct {
		HTMLURL string `json:"html_url"`
	}
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls", owner, name), req, &resp)
	if err != nil {
		return "", err
	}
	if resp.HTMLURL == "" {
		return "", fmt.Errorf("vexpr: pull request response had no url")
	}
	return resp.HTMLURL, nil
}

// do performs one API call. It returns the HTTP status so callers can treat a
// 404 or 422 as a case rather than a failure, and decodes a JSON body into out
// when out is non-nil and the status is a success.
func (c *githubClient) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.API+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("vexpr: %s %s: status %d: %s", method, path, resp.StatusCode, apiMessage(raw))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("vexpr: %s %s: decode response: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// apiMessage pulls the "message" out of a GitHub error body, falling back to a
// trimmed snippet of the raw response.
func apiMessage(raw []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Message != "" {
		return e.Message
	}
	s := strings.Join(strings.Fields(string(raw)), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
