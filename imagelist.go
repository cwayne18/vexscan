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

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/elfgraph"
	"github.com/cwayne18/vexscan/internal/modgraph"
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
//
// A line may also carry the reachability assertions for its own image:
//
//	docker.io/rancher/mirrored-kube-vip-kube-vip-iptables:v0.6.0 roots=/usr/sbin/xtables-nft-multi exec-policy=assume-none
//
// which exists because those flags are otherwise process-global and the
// assertions they carry are not. "This entrypoint execs iptables, and iptables
// is the whole list" is true of one image in a fleet of sixty; applied to the
// other fifty-nine it is either meaningless or false. Worse, since an
// unresolvable --roots path is now a blocking taint, a global --roots aimed at
// one image withholds every conclusion about the rest. The per-line form is
// what makes the assertion sayable at the scale a fleet is actually scanned at.

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

// imageEntry is one line of a fleet list: the reference, and the assertions
// that line makes about that image. A nil assert is the common case -- a list
// of bare references -- and means the global flags apply unchanged.
type imageEntry struct {
	ref    string
	assert *scanAssert
}

// scanAssert is the per-image half of the reachability policy flags.
//
// Every field is a pointer, or nil-able, because "not said on this line" and
// "said, as the default value" are different. A line that names no exec-policy
// inherits whatever --exec-policy was given for the run; a line that says
// exec-policy=taint overrides a global assume-none back to the safe setting,
// and that has to be expressible or the per-line form could only ever loosen.
type scanAssert struct {
	// Roots replaces the global --roots for this image rather than adding to
	// it. A line that names its own roots is a complete statement about what
	// that image runs, and the global list is a default for the images that do
	// not make one. Adding instead would mean a fleet list could never undo a
	// global root, which is the situation this whole form exists to escape.
	Roots []string

	DlopenPolicy  *elfgraph.DlopenPolicy
	ExecPolicy    *elfgraph.ExecPolicy
	DynamicPolicy *modgraph.DynamicPolicy
}

// apply overlays the assertions onto a copy of the run's options.
func (a *scanAssert) apply(opts *analyze.Options) {
	if a == nil {
		return
	}
	if a.Roots != nil {
		opts.Roots = a.Roots
	}
	if a.DlopenPolicy != nil {
		opts.DlopenPolicy = *a.DlopenPolicy
	}
	if a.ExecPolicy != nil {
		opts.ExecPolicy = *a.ExecPolicy
	}
	if a.DynamicPolicy != nil {
		opts.DynamicPolicy = *a.DynamicPolicy
	}
}

// readImageList reads the references named by --images-from: a file path, an
// http(s) URL, or "-" for stdin.
func readImageList(ctx context.Context, spec string) ([]imageEntry, error) {
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
		refs, err := parseHaulerManifest(s)
		if err != nil {
			return nil, err
		}
		out := make([]imageEntry, 0, len(refs))
		for _, r := range refs {
			out = append(out, imageEntry{ref: r})
		}
		return out, nil
	}
	return parseImageList(string(data))
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
//
// Whitespace after the reference begins the per-image assertions, which an
// image reference also cannot contain. See scanAssert.
func parseImageList(s string) ([]imageEntry, error) {
	seen := map[string]int{}
	var out []imageEntry
	for n, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		ref, assert, err := parseImageLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		// A reference named twice is scanned once, as it always has been -- a
		// fleet list assembled from two sources repeats itself and the second
		// row would say nothing the first did not.
		//
		// Unless one of the two carries assertions, which is not a repeat but a
		// contradiction: the list is saying this image runs one thing and also
		// something else, and silently keeping either one means scanning under
		// a claim the user did not make. There is no safe default to pick, so
		// there is no default.
		if i, dup := seen[ref]; dup {
			if assert != nil || out[i].assert != nil {
				return nil, fmt.Errorf("line %d: %s is named twice with different assertions; say it once", n+1, ref)
			}
			continue
		}
		seen[ref] = len(out)
		out = append(out, imageEntry{ref: ref, assert: assert})
	}
	return out, nil
}

// parseImageLine splits one list line into its reference and its assertions.
//
// An unknown key is an error rather than something skipped, even though
// skipping would fail closed -- the assertion simply would not apply and the
// run would conclude less. The report would still be honest and the user would
// still be wrong about what they had asked for, which is how a pipeline ends up
// carrying a typo for a year. A list is read before anything is pulled, so
// saying so costs nothing.
func parseImageLine(line string) (string, *scanAssert, error) {
	fields := strings.Fields(line)
	ref := fields[0]
	if len(fields) == 1 {
		return ref, nil, nil
	}

	a := &scanAssert{}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return "", nil, fmt.Errorf("%q is not key=value; a reference may be followed only by assertions", f)
		}
		switch k {
		case "roots":
			// Split on commas, because a root is a path and a path cannot
			// contain one. Repeating the key appends, so a long list can be
			// broken up the way the repeatable --roots flag allows.
			for _, r := range strings.Split(v, ",") {
				if r = strings.TrimSpace(r); r != "" {
					a.Roots = append(a.Roots, r)
				}
			}
			if a.Roots == nil {
				return "", nil, fmt.Errorf("roots= names no path")
			}
		case "dlopen-policy":
			p, err := elfgraph.ParseDlopenPolicy(v)
			if err != nil {
				return "", nil, err
			}
			a.DlopenPolicy = &p
		case "exec-policy":
			p, err := elfgraph.ParseExecPolicy(v)
			if err != nil {
				return "", nil, err
			}
			a.ExecPolicy = &p
		case "dynamic-import-policy":
			p, err := modgraph.ParseDynamicPolicy(v)
			if err != nil {
				return "", nil, err
			}
			a.DynamicPolicy = &p
		default:
			return "", nil, fmt.Errorf("unknown assertion %q: want roots, dlopen-policy, exec-policy or dynamic-import-policy", k)
		}
	}
	return ref, a, nil
}
