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

	// Profile is the name of the [profile] block this line drew its defaults
	// from, and is empty on a line that spelled its assertions out. It changes
	// nothing about the scan; it is carried so the report and the emitted VEX can
	// say which named profile a conditional conclusion rests on. See
	// analyze.RuntimeAssertion.
	Profile string

	DlopenPolicy  *elfgraph.DlopenPolicy
	ExecPolicy    *elfgraph.ExecPolicy
	DynamicPolicy *modgraph.DynamicPolicy

	// Entrypoint, Cmd and EntrypointFrom are what a deployment source says this
	// image is started with, replacing the entrypoint its config declares.
	//
	// Written either by a Kubernetes manifest read as a list (see k8sEntries)
	// or by entrypoint= and cmd= on a line, which exist because Kubernetes is
	// not the only thing that overrides an entrypoint: docker run --entrypoint,
	// a compose service's `entrypoint:`, a Nomad task's `command`, and a
	// systemd unit's ExecStart all do, and none of them have a manifest this
	// program can read. Withholding the key would not stop anyone asserting
	// this -- it would only stop them asserting it accurately, and push them to
	// the nearest thing that is allowed, which is --roots, which adds a root
	// and leaves the shell the image declares rooted beside it.
	//
	// EntrypointFrom is the file the claim came from, and it is carried rather
	// than derived because it is the only part a reviewer can go and check.
	Entrypoint     []string
	Cmd            []string
	EntrypointFrom string

	// DlopenAssumeNoneFor are the callers this line waves off by name. Unlike
	// the policies it is a list, so it follows the roots= rule rather than the
	// policy one: a line naming its own callers replaces the profile's list
	// instead of extending it, because a line that knows which loaders its
	// image has is making a complete statement about them.
	DlopenAssumeNoneFor []string
}

// apply overlays the assertions onto a copy of the run's options.
func (a *scanAssert) apply(opts *analyze.Options) {
	if a == nil {
		return
	}
	if a.Roots != nil {
		opts.Roots = a.Roots
	}
	if a.EntrypointFrom != "" {
		opts.Entrypoint, opts.Cmd, opts.EntrypointFrom = a.Entrypoint, a.Cmd, a.EntrypointFrom
	}
	if a.Profile != "" {
		opts.Profile = a.Profile
	}
	if a.DlopenPolicy != nil {
		opts.DlopenPolicy = *a.DlopenPolicy
	}
	if a.DlopenAssumeNoneFor != nil {
		opts.DlopenAssumeNoneFor = a.DlopenAssumeNoneFor
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
	// A Kubernetes manifest is a list of images too, and the only list that
	// also says how each one is started. Recognised the same way the hauler
	// manifest is, by what the document declares itself to be, so nothing that
	// is already a plain list changes shape. See k8smanifest.go.
	if s := string(data); looksLikeK8sManifest(s) {
		return k8sEntries(s, listSource(spec))
	}
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
	return parseImageList(listSource(spec), string(data))
}

// listSource names the list in a sentence a reader has to act on.
//
// The spec is fine for that as it stands, except for the one that is not a
// name: "-". The recommended way to scan a cluster is
// `kubectl get ds -A -o yaml | vexscan --images-from -`, which would otherwise
// put "the image runs /usr/bin/calico-node per -" in every report it produced.
// A reviewer cannot check "-", and the point of carrying the source at all is
// that it is the part they can check.
func listSource(spec string) string {
	if spec == "-" {
		return "standard input"
	}
	return spec
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
func parseImageList(from, s string) ([]imageEntry, error) {
	lines := strings.Split(s, "\n")
	// Profiles are collected first so a list can define them at the bottom, or
	// beside the image that motivated one. A definition that had to precede
	// every use would make the obvious layout -- a block of profiles at the end,
	// or one next to the odd image it exists for -- an error for no reason.
	profiles, err := parseProfiles(from, lines)
	if err != nil {
		return nil, err
	}

	seen := map[string]int{}
	var out []imageEntry
	for n, line := range lines {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if isProfileLine(line) {
			continue // already collected
		}
		ref, assert, err := parseImageLine(from, line, profiles)
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
func parseImageLine(from, line string, profiles map[string]*scanAssert) (string, *scanAssert, error) {
	fields := strings.Fields(line)
	ref := fields[0]
	if len(fields) == 1 {
		return ref, nil, nil
	}

	// The profile is resolved before the line's own keys are read, so a key the
	// line states wins over the same key in the profile it names. A profile is a
	// default for a shape of image; the line is what is true about this one.
	a := &scanAssert{}
	for _, f := range fields[1:] {
		if name, ok := strings.CutPrefix(f, "profile="); ok {
			if name == "" {
				return "", nil, fmt.Errorf("profile= names no profile")
			}
			p, known := profiles[name]
			if !known {
				return "", nil, fmt.Errorf("unknown profile %q; define it with a [profile %s] line", name, name)
			}
			*a = *p
			a.Profile = name
		}
	}

	if err := applyAssertFields(from, a, fields[1:], false); err != nil {
		return "", nil, err
	}
	return ref, a, nil
}

// applyAssertFields reads key=value assertions onto a, overwriting whatever a
// already carries for the keys it names. Shared by an image line and a [profile]
// definition so the two can never drift into accepting different grammars.
//
// inProfile says the fields came from a [profile] definition, where profile= is
// not a key: only an image line resolves one, so a profile that named another
// would be read, accepted, and silently ignored.
func applyAssertFields(from string, a *scanAssert, fields []string, inProfile bool) error {
	// A line that names its own roots makes a complete statement about what that
	// image runs, so the first roots= here clears whatever a profile supplied
	// rather than adding to it -- the same rule that makes a line's roots replace
	// the global --roots. Later roots= on the same line still append, so a long
	// list can be broken up the way the repeatable flag allows.
	ownRoots, ownDlopen := false, false
	// entrypoint= and cmd= follow the same clear-then-append rule, one argv
	// token per occurrence. They are tracked separately from each other because
	// they are separately overridable: a line that states cmd= and not
	// entrypoint= is saying the image's own entrypoint runs with different
	// arguments, which is a different claim from replacing it.
	ownEntrypoint, ownCmd := false, false
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return fmt.Errorf("%q is not key=value; a reference may be followed only by assertions", f)
		}
		switch k {
		case "profile":
			if inProfile {
				// Profiles are collected in one pass and resolved in another, so
				// nothing would expand this one. Accepting it would drop an
				// assertion the author believed they had made -- and drop it
				// towards concluding less, which is the direction that does not
				// announce itself in a report.
				return fmt.Errorf("a profile cannot name another profile; spell the assertions out")
			}
			// Resolved by the caller, which needs the name before any other key
			// is read. Accepted here so it is not an unknown assertion.
		case "roots":
			if !ownRoots {
				a.Roots, ownRoots = nil, true
			}
			// Split on commas, because a root is a path and a path cannot
			// contain one.
			for _, r := range strings.Split(v, ",") {
				if r = strings.TrimSpace(r); r != "" {
					a.Roots = append(a.Roots, r)
				}
			}
			if a.Roots == nil {
				return fmt.Errorf("roots= names no path")
			}
		case "dlopen-assume-none":
			// Same clear-then-append rule as roots=, for the same reason, and
			// with the same comma split: these are paths and SONAMEs, neither
			// of which can contain a comma.
			if !ownDlopen {
				a.DlopenAssumeNoneFor, ownDlopen = nil, true
			}
			for _, c := range strings.Split(v, ",") {
				if c = strings.TrimSpace(c); c != "" {
					a.DlopenAssumeNoneFor = append(a.DlopenAssumeNoneFor, c)
				}
			}
			if a.DlopenAssumeNoneFor == nil {
				return fmt.Errorf("dlopen-assume-none= names no caller")
			}
		case "entrypoint", "cmd":
			// One token per occurrence, and no comma split: an argument may
			// contain a comma and a path may not, so the rule that works for
			// roots= would silently cut `--listen=1.2.3.4,5.6.7.8` in half.
			//
			// An empty value is "replaced with nothing" rather than "not
			// stated", which is the distinction the whole override turns on and
			// the reason these are assigned an empty slice before anything is
			// appended. `cmd=` says the image's arguments are dropped;
			// `entrypoint=` would say no program is started at all, which is
			// not a runnable claim, so it is refused.
			if k == "entrypoint" {
				if !ownEntrypoint {
					a.Entrypoint, ownEntrypoint = []string{}, true
				}
				if v == "" {
					return fmt.Errorf("entrypoint= names no program; to say this image runs with no arguments, use cmd=")
				}
				a.Entrypoint = append(a.Entrypoint, v)
			} else {
				if !ownCmd {
					a.Cmd, ownCmd = []string{}, true
				}
				if v != "" {
					a.Cmd = append(a.Cmd, v)
				}
			}
			// The source travels with the claim: it is what a reviewer reading
			// "not the entrypoint its config declares" in the report has to go
			// and check, and without it apply drops the override entirely.
			a.EntrypointFrom = from
		case "dlopen-policy":
			p, err := elfgraph.ParseDlopenPolicy(v)
			if err != nil {
				return err
			}
			a.DlopenPolicy = &p
		case "exec-policy":
			p, err := elfgraph.ParseExecPolicy(v)
			if err != nil {
				return err
			}
			a.ExecPolicy = &p
		case "dynamic-import-policy":
			p, err := modgraph.ParseDynamicPolicy(v)
			if err != nil {
				return err
			}
			a.DynamicPolicy = &p
		default:
			want := "profile, roots, entrypoint, cmd, dlopen-policy, dlopen-assume-none, exec-policy or dynamic-import-policy"
			if inProfile {
				want = "roots, entrypoint, cmd, dlopen-policy, dlopen-assume-none, exec-policy or dynamic-import-policy"
			}
			return fmt.Errorf("unknown assertion %q: want %s", k, want)
		}
	}
	return nil
}

// profilePrefix opens a profile definition line.
const profilePrefix = "[profile "

// isProfileLine reports whether a list line defines a profile rather than naming
// an image. Checked on the comment-stripped line, since a definition may be
// annotated like anything else in the list.
func isProfileLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), profilePrefix)
}

// parseProfiles collects the named assertion profiles a list defines.
//
// A Rancher fleet is a hundred images whose deployment shapes repeat -- a
// hardened Go daemon with one entrypoint, a supervisor wrapped in a shell, a CLI
// that execs nothing. Spelling the same roots= and exec-policy= out on each line
// makes the list unmaintainable and, worse, makes it drift: half the lines get
// updated and the other half keep asserting something that stopped being true.
// A profile is the same assertion said once.
//
//	[profile go-daemon] exec-policy=assume-none
//	[profile calico]    roots=/usr/bin/calico-node exec-policy=assume-none
//
//	docker.io/rancher/hardened-calico:v3.32.0-build20260511 profile=calico
//	docker.io/rancher/hardened-coredns:v1.11.1-build20240910 profile=go-daemon roots=/coredns
//
// The name is carried onto the scan and out into the report and the emitted VEX,
// so a conclusion that rests on a profile says which one. That is the point of
// naming them rather than expanding them: "under the asserted runtime profile
// 'calico'" is something a reviewer can look up and disagree with.
//
// A profile that defines nothing, a name defined twice, and a name used but
// never defined are all errors, reported before anything is pulled. The rule is
// the one the rest of this file already follows: a list is read once, cheaply,
// and every way of being wrong about what you asked for should surface there
// rather than as a report that quietly concluded less.
func parseProfiles(from string, lines []string) (map[string]*scanAssert, error) {
	var profiles map[string]*scanAssert
	for n, line := range lines {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if !isProfileLine(line) {
			continue
		}
		line = strings.TrimSpace(line)
		close := strings.IndexByte(line, ']')
		if close < 0 {
			return nil, fmt.Errorf("line %d: %s has no closing \"]\"", n+1, profilePrefix)
		}
		name := strings.TrimSpace(line[len(profilePrefix):close])
		if name == "" {
			return nil, fmt.Errorf("line %d: [profile ] names no profile", n+1)
		}
		if _, dup := profiles[name]; dup {
			return nil, fmt.Errorf("line %d: profile %q is defined twice; say it once", n+1, name)
		}
		a := &scanAssert{}
		if err := applyAssertFields(from, a, strings.Fields(line[close+1:]), true); err != nil {
			return nil, fmt.Errorf("line %d: profile %q: %w", n+1, name, err)
		}
		if a.Roots == nil && a.DlopenPolicy == nil && a.ExecPolicy == nil &&
			a.DynamicPolicy == nil && a.DlopenAssumeNoneFor == nil {
			// An empty profile is almost certainly a half-written one. Applying
			// it would be a no-op that reads, on the line that names it, like an
			// assertion being made.
			return nil, fmt.Errorf("line %d: profile %q asserts nothing", n+1, name)
		}
		if profiles == nil {
			profiles = map[string]*scanAssert{}
		}
		profiles[name] = a
	}
	return profiles, nil
}
