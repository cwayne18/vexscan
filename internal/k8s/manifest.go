// Package k8s reads what a Kubernetes manifest says each image is started
// with.
//
// It exists for one fact the image configuration cannot supply: a container
// that sets `command:` does not run the image's ENTRYPOINT. Nothing in the
// image records that, so a closure built from the image alone roots the
// declared entrypoint -- very often /bin/bash on a hardened image -- and every
// library only that shell reaches comes back as running code. The manifest is
// where the truth about a deployment is already written down, usually under
// review, usually in the same repository. Reading it is cheaper and more
// auditable than asking a user to restate it as flags.
//
// What this package does not do is judge. It reports what the manifest says;
// whether a `command:` of /bin/sh is worth anything is decided by the closure,
// which puts a manifest-supplied command through exactly the same shell
// detection and escalation as a config-supplied one.
package k8s

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Container is one container's deployment shape: the image, and the argv the
// manifest overrides, if it overrides one.
//
// Command and Args are nil when the manifest does not set them and non-nil
// (possibly empty) when it does, because those mean different things: an unset
// `args:` leaves the image's CMD running, and an empty one drops it.
type Container struct {
	Image   string
	Command []string
	Args    []string

	// Where locates this container for an error message -- "DaemonSet
	// calico-node, container calico-node". A manifest is often thousands of
	// lines of generated YAML and a conflict is unactionable without it.
	Where string
}

// Overrides reports whether the manifest says anything about what this
// container runs. A container that sets neither is still worth returning: it
// names an image to scan, and the image's own entrypoint is the right answer
// for it.
func (c Container) Overrides() bool { return c.Command != nil || c.Args != nil }

// workloads maps a document kind to the path, below the document root, at
// which its pod spec lives. Listing them rather than searching for the first
// `containers:` key anywhere is deliberate: a CRD is free to have a field of
// that name meaning something else, and attaching one workload's command to
// another workload's image is the one error here that makes a report wrong
// rather than merely incomplete.
var workloads = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
	"PodTemplate":           {"template", "spec"},
}

// Parse reads every container out of a stream of Kubernetes manifests.
//
// The stream may hold many documents -- the usual `kubectl get -o yaml`,
// `helm template` or concatenated-with-`---` shape -- and the usual mix of
// Services, ConfigMaps and RBAC alongside the workloads. Those are skipped,
// but only because they hold no containers: a document whose kind this package
// does not know, and which does hold containers, is an error rather than a
// silent omission. Skipping it would drop images from the scan while looking
// exactly like a manifest that did not mention them.
func Parse(r io.Reader, name string) ([]Container, error) {
	dec := yaml.NewDecoder(r)
	var out []Container
	for i := 0; ; i++ {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: document %d: %w", name, i+1, err)
		}
		if doc == nil {
			continue // a --- separator with nothing after it
		}
		cs, err := containersOf(doc, name)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no Kubernetes workload with containers found; "+
			"this reads Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, "+
			"ReplicationController, Job, CronJob and List documents", name)
	}
	return out, nil
}

// containersOf pulls the containers out of one document, descending through a
// List into its items.
func containersOf(doc map[string]any, name string) ([]Container, error) {
	kind, _ := doc["kind"].(string)
	if kind == "List" {
		items, _ := doc["items"].([]any)
		var out []Container
		for _, it := range items {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			cs, err := containersOf(m, name)
			if err != nil {
				return nil, err
			}
			out = append(out, cs...)
		}
		return out, nil
	}

	path, known := workloads[kind]
	if !known {
		if hasContainers(doc) {
			return nil, fmt.Errorf("%s: a %q document has containers in it, and this does not know "+
				"where a %s keeps its pod spec, so its images would be silently left out; "+
				"extract the workloads, or scan those images with --image",
				name, kindName(doc, kind), kindName(doc, kind))
		}
		return nil, nil
	}

	spec := descend(doc, path)
	if spec == nil {
		return nil, nil
	}
	where := kindName(doc, kind)
	var out []Container
	for _, field := range []string{"initContainers", "containers"} {
		list, _ := spec[field].([]any)
		for _, it := range list {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			c, err := containerOf(m, where, name)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// containerOf reads one container entry.
func containerOf(m map[string]any, where, name string) (Container, error) {
	image, _ := m["image"].(string)
	cname, _ := m["name"].(string)
	if cname != "" {
		where += ", container " + cname
	}
	if strings.TrimSpace(image) == "" {
		return Container{}, fmt.Errorf("%s: %s has no image", name, where)
	}
	command, err := strList(m, "command", where, name)
	if err != nil {
		return Container{}, err
	}
	args, err := strList(m, "args", where, name)
	if err != nil {
		return Container{}, err
	}
	c := Container{Image: image, Command: command, Args: args, Where: where}

	// A container that sets its own PATH resolves a bare command against that
	// PATH and not the image's. Nothing here reads the container environment,
	// so rather than resolve the command against a PATH that is not the one in
	// force, this refuses the case where the difference could matter. An
	// absolute command is unaffected, which is nearly all of them.
	if p, ok := envOf(m, "PATH"); ok {
		if argv0 := firstOf(command); argv0 != "" && !strings.HasPrefix(argv0, "/") {
			return Container{}, fmt.Errorf("%s: %s sets PATH=%q and starts %q, which is not an absolute path, "+
				"so which program that names depends on an environment this does not read; "+
				"give the command as an absolute path in the manifest",
				name, where, p, argv0)
		}
	}
	return c, nil
}

// firstOf is the program the manifest's override starts, or "" when it starts
// none. Only command counts: args[0] is an argument to whatever ENTRYPOINT the
// image declares, not a program name, so no PATH of the container's resolves
// it.
func firstOf(command []string) string {
	if len(command) > 0 {
		return command[0]
	}
	return ""
}

// envOf returns the container's literal value for an environment variable.
// A valueFrom entry has no literal value here and is reported as unset, which
// is the safe direction: it means the PATH check below does not fire, and the
// check only ever refuses.
func envOf(m map[string]any, key string) (string, bool) {
	list, _ := m["env"].([]any)
	for _, it := range list {
		e, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := e["name"].(string); n != key {
			continue
		}
		if v, ok := e["value"].(string); ok {
			return v, true
		}
	}
	return "", false
}

// strList reads a YAML string list, keeping unset and empty apart. A non-string
// element is an error rather than a coercion -- `command: [8080]` is a manifest
// that does not mean what it says, and guessing at it roots the wrong program.
func strList(m map[string]any, key, where, name string) ([]string, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: %s has a %s that is not a list", name, where, key)
	}
	out := []string{}
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: %s has a non-string in %s: %v", name, where, key, v)
		}
		out = append(out, s)
	}
	return out, nil
}

// descend walks a path of map keys, returning nil if any step is missing or is
// not a map.
func descend(m map[string]any, path []string) map[string]any {
	for _, k := range path {
		next, ok := m[k].(map[string]any)
		if !ok {
			return nil
		}
		m = next
	}
	return m
}

// hasContainers reports whether a "containers" or "initContainers" list of
// mappings appears anywhere in the document. Used only to decide whether an
// unrecognised kind is worth refusing, so a false positive costs an error
// message and a false negative costs an image quietly not being scanned.
func hasContainers(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if (k == "containers" || k == "initContainers") && isContainerList(val) {
				return true
			}
			if hasContainers(val) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if hasContainers(e) {
				return true
			}
		}
	}
	return false
}

func isContainerList(v any) bool {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := m["image"]; !ok {
			return false
		}
	}
	return true
}

// kindName is "DaemonSet calico-node", falling back to whatever of the two is
// known.
func kindName(doc map[string]any, kind string) string {
	if kind == "" {
		kind = "document"
	}
	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		return kind
	}
	n, _ := meta["name"].(string)
	if n == "" {
		return kind
	}
	return kind + " " + n
}

// Dedupe collapses containers that say the same thing about the same image and
// refuses ones that disagree.
//
// The collapse is what makes this usable on a real cluster: one image runs in a
// Deployment and a DaemonSet, or in three replicas of the same spec, and
// scanning it three times answers the same question three times. The refusal is
// the other half. Two containers running one image with two different commands
// is not a repeat -- it is the manifest saying the image is started two
// different ways, with two different closures, and picking either one reports a
// conclusion that is only true of half the cluster.
func Dedupe(cs []Container) ([]Container, error) {
	seen := map[string]Container{}
	var order []string
	for _, c := range cs {
		prev, ok := seen[c.Image]
		if !ok {
			seen[c.Image] = c
			order = append(order, c.Image)
			continue
		}
		if sameArgv(prev, c) {
			continue
		}
		return nil, fmt.Errorf("%s runs %s and %s runs %s, so one scan cannot answer for both; "+
			"scan them separately with --image",
			prev.Where, argvOf(prev), c.Where, argvOf(c))
	}
	out := make([]Container, 0, len(order))
	for _, ref := range order {
		out = append(out, seen[ref])
	}
	return out, nil
}

func sameArgv(a, b Container) bool {
	return eq(a.Command, b.Command) && eq(a.Args, b.Args)
}

// eq compares two override halves, treating nil and empty as different for the
// same reason strList does.
func eq(a, b []string) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// argvOf renders a container's override for an error message.
func argvOf(c Container) string {
	if !c.Overrides() {
		return "the image's own entrypoint"
	}
	argv := append(append([]string{}, c.Command...), c.Args...)
	if len(argv) == 0 {
		return "no command at all"
	}
	return strings.Join(argv, " ")
}
