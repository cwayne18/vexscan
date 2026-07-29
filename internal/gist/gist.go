// Package gist uploads a vexscan report to a GitHub gist so results can be
// shared with a single URL. It uses the same GITHUB_TOKEN / GH_TOKEN that the
// --llm path relies on, so it works inside the container image without the gh
// CLI.
package gist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultEndpoint is the GitHub REST API gists endpoint.
const DefaultEndpoint = "https://api.github.com/gists"

// Client creates gists via the GitHub REST API.
type Client struct {
	HTTP     *http.Client
	Endpoint string
	Token    string
}

// NewClient builds a Client. The token is read from GITHUB_TOKEN (or GH_TOKEN)
// unless supplied explicitly. It errors if no token is available.
func NewClient(token string) (*Client, error) {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found (set GITHUB_TOKEN or GH_TOKEN); the token needs gist scope")
	}
	return &Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Endpoint: DefaultEndpoint,
		Token:    token,
	}, nil
}

type gistFile struct {
	Content string `json:"content"`
}

type createRequest struct {
	Description string              `json:"description"`
	Public      bool                `json:"public"`
	Files       map[string]gistFile `json:"files"`
}

type createResponse struct {
	HTMLURL string `json:"html_url"`
	Message string `json:"message"`
}

// Create uploads content as a single-file gist (public when public is true) and
// returns its html_url.
func (c *Client) Create(ctx context.Context, filename, description, content string, public bool) (string, error) {
	if strings.TrimSpace(filename) == "" {
		filename = "vexscan-report.txt"
	}
	// The GitHub API rejects files whose content is empty.
	if content == "" {
		content = "(empty report)\n"
	}

	reqBody := createRequest{
		Description: description,
		Public:      public,
		Files:       map[string]gistFile{filename: {Content: content}},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}

	var cr createResponse
	decodeErr := json.Unmarshal(raw, &cr)

	if res.StatusCode != http.StatusCreated {
		if decodeErr == nil && cr.Message != "" {
			hint := ""
			if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
				hint = " (does the token have gist scope?)"
			}
			return "", fmt.Errorf("create gist: %s (status %d)%s", cr.Message, res.StatusCode, hint)
		}
		return "", fmt.Errorf("create gist: status %d: %s", res.StatusCode, snippet(raw))
	}
	if decodeErr != nil {
		return "", fmt.Errorf("create gist: could not parse response: %s", snippet(raw))
	}
	if cr.HTMLURL == "" {
		return "", fmt.Errorf("create gist: response contained no url")
	}
	return cr.HTMLURL, nil
}

func snippet(b []byte) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(string(b))), " ")
	const max = 200
	if len(s) > max {
		s = s[:max] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
