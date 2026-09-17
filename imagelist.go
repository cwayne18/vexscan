package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// The image list.
//
// --image scans one image; --images-from scans a fleet. The list is the
// plainest thing that can carry one: one reference per line, "#" starts a
// comment, blank lines are skipped, and a reference named twice is scanned
// once. That is the shape --cves-file already reads, and the shape the output
// of a registry catalogue query, a Kubernetes `get pods -o jsonpath`, or a
// hand-maintained fleet.txt already has.
//
// A path, a URL, or "-" for stdin, because those are the three places a fleet
// list actually lives: a file beside the pipeline definition, an endpoint some
// inventory service publishes, and the end of a pipe. The URL case sends no
// credentials -- a list that needs authentication should be fetched by the
// thing that holds the token and piped in.

// imageListMax bounds what one list may make this read.
//
// A list is lines of image references; a hundred thousand of them is far past
// any real fleet and far short of what an unbounded read off a URL that answers
// with something other than a list could be.
const imageListMax = 8 << 20

// imageListClient fetches a remote list. The timeouts sit on the transport for
// the same reason rpmsrc's do: they bound the parts that hang without progress
// rather than putting a deadline on a transfer that is merely large.
var imageListClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	},
}

// readImageList reads the references named by --images-from: a file path, an
// http(s) URL, or "-" for stdin.
func readImageList(ctx context.Context, spec string) ([]string, error) {
	var (
		data []byte
		err  error
	)
	switch {
	case spec == "-":
		data, err = io.ReadAll(io.LimitReader(os.Stdin, imageListMax))
	case strings.HasPrefix(spec, "http://"), strings.HasPrefix(spec, "https://"):
		data, err = fetchImageList(ctx, spec)
	default:
		data, err = os.ReadFile(spec)
	}
	if err != nil {
		return nil, err
	}
	// A hauler manifest is a list of images too, just declared rather than
	// written out, and it is the file a team that builds hauls already keeps
	// beside the pipeline. Recognised by its API group so that nothing else
	// changes shape underneath an existing list; see haulmanifest.go.
	if s := string(data); looksLikeHaulerManifest(s) {
		return parseHaulerManifest(s)
	}
	return parseImageList(string(data)), nil
}

func fetchImageList(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := imageListClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server answered %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, imageListMax))
}

// parseImageList turns the bytes of a list into image references.
//
// Everything from a "#" to the end of the line is a comment: an image reference
// cannot contain one, so there is no ambiguity, and a fleet list is exactly the
// kind of file people annotate. Order is the file's order, which is the order
// the report will print, so a reader can diff the two.
func parseImageList(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}
