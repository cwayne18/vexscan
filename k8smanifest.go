package main

import (
	"fmt"
	"strings"

	"github.com/cwayne18/vexscan/internal/k8s"
)

// Kubernetes manifests as an --images-from list.
//
// The list is "what my cluster runs", which is the question a fleet scan is
// usually standing in for anyway, and it is already written down. What makes it
// worth reading rather than transcribing is the half a text list cannot carry:
// a container's `command:` replaces the image's ENTRYPOINT, and no amount of
// staring at the image reveals that.
//
// That difference is not cosmetic. A hardened image whose config entrypoint is
// /bin/bash has bash rooted in its closure, and bash's dlopen blocks every
// conclusion the closure would otherwise reach -- on rancher/hardened-calico,
// seven OS findings that are otherwise reported as linked code. In the cluster
// that image runs `command: [/usr/bin/calico-node]` and bash is never executed.
// The manifest is where that is recorded.
//
// It is read here rather than in internal/k8s for the same reason the hauler
// manifest is read here: the parsing is that package's job, and turning the
// result into a fleet list is this one's.

// k8sKinds are the document kinds whose presence makes a file a Kubernetes
// manifest rather than a list of references. It is the same set
// internal/k8s.Parse knows how to descend, plus List.
var k8sKinds = map[string]bool{
	"Pod": true, "Deployment": true, "DaemonSet": true, "StatefulSet": true,
	"ReplicaSet": true, "ReplicationController": true, "Job": true,
	"CronJob": true, "PodTemplate": true, "List": true,
}

// looksLikeK8sManifest reports whether the bytes are Kubernetes YAML rather
// than a list of references.
//
// It tests the text for a top-level `kind:` naming a workload, for the reason
// looksLikeHaulerManifest tests the text: a list of image references is also a
// valid YAML document, so the file has to say what it is before it is read as
// something other than a list. `kind:` must be unindented, because a nested one
// belongs to some other object -- a CRD's embedded template, a kustomize patch
// target -- and a file whose only workload is nested is one this cannot read
// correctly anyway.
func looksLikeK8sManifest(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "kind:")
		if !ok {
			continue
		}
		if k8sKinds[strings.Trim(strings.TrimSpace(rest), `"'`)] {
			return true
		}
	}
	return false
}

// k8sEntries turns a manifest into fleet list entries, one per distinct image.
//
// Every container becomes an entry, including ones the manifest starts with
// their own entrypoint, and every entry carries EntrypointFrom whether the
// manifest overrode anything or not. That is the point of recording the source
// rather than just the override: a user who points a scan at a manifest is
// entitled to know which of their images the manifest actually spoke for, and
// an image it left alone looks otherwise exactly like one it corrected.
func k8sEntries(s, from string) ([]imageEntry, error) {
	cs, err := k8s.Parse(strings.NewReader(s), from)
	if err != nil {
		return nil, err
	}
	cs, err = k8s.Dedupe(cs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", from, err)
	}
	out := make([]imageEntry, 0, len(cs))
	for _, c := range cs {
		out = append(out, imageEntry{
			ref: c.Image,
			assert: &scanAssert{
				Entrypoint:     c.Command,
				Cmd:            c.Args,
				EntrypointFrom: from,
			},
		})
	}
	return out, nil
}
