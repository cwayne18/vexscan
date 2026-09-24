package main

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
)

const calicoManifest = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: calico-node
spec:
  template:
    spec:
      containers:
        - name: calico-node
          image: docker.io/rancher/hardened-calico:v3.32.0
          command: ["/usr/bin/calico-node"]
        - name: sidecar
          image: docker.io/rancher/mirrored-pause:3.6
`

// TestLooksLikeK8sManifest is the switch that decides whether a file keeps the
// meaning it has had since --images-from existed. A false positive reads a
// fleet list as a manifest and scans nothing.
func TestLooksLikeK8sManifest(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"a daemonset", calicoManifest, true},
		{"a quoted kind", "kind: \"Deployment\"\n", true},
		{"a plain reference list", "alpine:3.20\ndebian:12\n", false},
		{"a list with a comment", "# kind: Pod\nalpine:3.20\n", false},
		{
			"a hauler manifest",
			"apiVersion: content.hauler.cattle.io/v1\nkind: Images\nspec:\n  images:\n    - name: alpine:3.20\n",
			false,
		},
		{
			"a kind nested inside something else",
			"apiVersion: example.com/v1\nkind: Thing\nspec:\n  template:\n    kind: Pod\n",
			false,
		},
		{"a Service alone", "kind: Service\nspec:\n  ports: [{port: 80}]\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeK8sManifest(tc.in); got != tc.want {
				t.Errorf("looksLikeK8sManifest = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestK8sEntriesCarryTheCommandAsAnAssertion: the entry is what the scan reads,
// so a manifest whose command never reaches scanAssert is a manifest that was
// parsed and then thrown away.
func TestK8sEntriesCarryTheCommandAsAnAssertion(t *testing.T) {
	got, err := k8sEntries(calicoManifest, "deploy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want an entry per image, got %d: %+v", len(got), got)
	}
	calico := got[0]
	if calico.ref != "docker.io/rancher/hardened-calico:v3.32.0" {
		t.Errorf("ref = %q", calico.ref)
	}
	if calico.assert == nil {
		t.Fatal("no assertion on the entry, so the manifest's command reaches no scan")
	}
	if len(calico.assert.Entrypoint) != 1 || calico.assert.Entrypoint[0] != "/usr/bin/calico-node" {
		t.Errorf("Entrypoint = %v", calico.assert.Entrypoint)
	}
	if calico.assert.EntrypointFrom != "deploy.yaml" {
		t.Errorf("EntrypointFrom = %q; a conclusion has to say which file it rests on", calico.assert.EntrypointFrom)
	}
}

// TestK8sEntriesRecordTheSourceEvenWithNoOverride. The sidecar runs its own
// entrypoint, and that is worth saying: a user who pointed a scan at a manifest
// is entitled to know which of their images it did not speak for, and an image
// left alone otherwise looks exactly like one it corrected.
func TestK8sEntriesRecordTheSourceEvenWithNoOverride(t *testing.T) {
	got, err := k8sEntries(calicoManifest, "deploy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pause := got[1]
	if pause.assert == nil || pause.assert.EntrypointFrom != "deploy.yaml" {
		t.Fatalf("the un-overridden image does not record that a manifest was read for it: %+v", pause.assert)
	}
	if pause.assert.Entrypoint != nil || pause.assert.Cmd != nil {
		t.Errorf("an override was invented for a container that set none: %+v", pause.assert)
	}
}

// TestK8sEntriesRefuseAConflict surfaces internal/k8s's refusal through the
// fleet-list path, named with the file so the user can find it.
func TestK8sEntriesRefuseAConflict(t *testing.T) {
	_, err := k8sEntries(`
kind: Pod
metadata: {name: a}
spec: {containers: [{name: c, image: i:1, command: [/x]}]}
---
kind: Pod
metadata: {name: b}
spec: {containers: [{name: c, image: i:1, command: [/y]}]}
`, "deploy.yaml")
	if err == nil {
		t.Fatal("one image started two ways was collapsed into one scan")
	}
	if !strings.Contains(err.Error(), "deploy.yaml") {
		t.Errorf("the error does not name the manifest: %v", err)
	}
}

// TestManifestAssertionReplacesRatherThanRoots is the guard on apply. A
// manifest command written into Roots would leave the image's own entrypoint
// rooted, which is the bug this whole feature exists to fix and which no test
// of the parser would catch.
func TestManifestAssertionReplacesRatherThanRoots(t *testing.T) {
	got, err := k8sEntries(calicoManifest, "deploy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts := analyze.Options{}
	got[0].assert.apply(&opts)

	if len(opts.Entrypoint) != 1 || opts.Entrypoint[0] != "/usr/bin/calico-node" {
		t.Errorf("the manifest command did not reach Options.Entrypoint: %v", opts.Entrypoint)
	}
	if len(opts.Roots) != 0 {
		t.Errorf("the manifest command was written to Roots, which adds to the config entrypoint rather than replacing it: %v", opts.Roots)
	}
	if opts.EntrypointFrom != "deploy.yaml" {
		t.Errorf("EntrypointFrom = %q", opts.EntrypointFrom)
	}
}

// TestManifestSourceSurvivesAnImageItLeftAlone. apply is where the provenance
// either reaches the scan or is dropped, and dropping it for the images the
// manifest did not override is the case that looks like nothing went wrong.
func TestManifestSourceSurvivesAnImageItLeftAlone(t *testing.T) {
	got, err := k8sEntries(calicoManifest, "deploy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts := analyze.Options{}
	got[1].assert.apply(&opts)

	if opts.EntrypointFrom != "deploy.yaml" {
		t.Error("an image the manifest did not override reaches the scan with no record that a manifest was read")
	}
	if opts.Entrypoint != nil || opts.Cmd != nil {
		t.Errorf("an override was invented: %v %v", opts.Entrypoint, opts.Cmd)
	}
}

// TestK8sCommandWithoutArgsDropsTheImageCmd pins the Kubernetes rule that a
// container giving a command and no args runs only that command: the image's
// CMD is ignored, not appended. vexscan keeps an unset Cmd and an empty one
// apart, and reading "no args:" as "unset" would compose an argv -- the
// command followed by the image's CMD -- that the cluster never runs.
func TestK8sCommandWithoutArgsDropsTheImageCmd(t *testing.T) {
	got, err := k8sEntries(`
kind: DaemonSet
metadata: {name: canal}
spec:
  template:
    spec:
      containers:
        - name: kube-flannel
          image: rancher/hardened-flannel:v0.28.9
          command: [/opt/bin/flanneld, --ip-masq]
`, "canal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	a := got[0].assert
	if a == nil || a.Cmd == nil {
		t.Fatalf("Cmd = %+v, want an empty non-nil slice so the image's CMD is dropped", a)
	}
	if len(a.Cmd) != 0 {
		t.Errorf("Cmd = %v, want empty", a.Cmd)
	}
}

// TestK8sArgsWithoutCommandLeavesTheEntrypointAlone is the other half: a
// container that sets only args is still running the image's own ENTRYPOINT,
// and inventing an empty one for it would drop the program that actually runs.
func TestK8sArgsWithoutCommandLeavesTheEntrypointAlone(t *testing.T) {
	got, err := k8sEntries(`
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: rancher/hardened-coredns:v1.14.7
      args: [-conf, /etc/coredns/Corefile]
`, "pod.yaml")
	if err != nil {
		t.Fatal(err)
	}
	a := got[0].assert
	if a == nil || a.Entrypoint != nil {
		t.Fatalf("Entrypoint = %+v, want nil so the image's own entrypoint still runs", a)
	}
	if !equalStrings(a.Cmd, []string{"-conf", "/etc/coredns/Corefile"}) {
		t.Errorf("Cmd = %v", a.Cmd)
	}
}
