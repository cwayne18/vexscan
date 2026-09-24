package k8s

import (
	"strings"
	"testing"
)

func parse(t *testing.T, yaml string) []Container {
	t.Helper()
	cs, err := Parse(strings.NewReader(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cs
}

func parseErr(t *testing.T, yaml string) string {
	t.Helper()
	cs, err := Parse(strings.NewReader(yaml), "test.yaml")
	if err == nil {
		t.Fatalf("Parse accepted this and returned %d container(s); it must not", len(cs))
	}
	return err.Error()
}

const daemonSet = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: calico-node
spec:
  template:
    spec:
      initContainers:
        - name: install-cni
          image: docker.io/rancher/hardened-calico:v3.32.0
          command: ["/opt/cni/bin/install"]
      containers:
        - name: calico-node
          image: docker.io/rancher/hardened-calico:v3.32.0
          command: ["/usr/bin/calico-node"]
          args: ["-felix"]
`

// TestParseReadsCommandAndArgs is the fact the whole feature rests on: the
// manifest says what runs, and the image config does not.
func TestParseReadsCommandAndArgs(t *testing.T) {
	cs := parse(t, daemonSet)
	if len(cs) != 2 {
		t.Fatalf("want 2 containers (the init container counts -- it runs the image too), got %d: %+v", len(cs), cs)
	}
	// initContainers come first, as they do at runtime.
	if got := cs[0].Command; len(got) != 1 || got[0] != "/opt/cni/bin/install" {
		t.Errorf("init container command = %v", got)
	}
	main := cs[1]
	if got := main.Command; len(got) != 1 || got[0] != "/usr/bin/calico-node" {
		t.Errorf("command = %v", got)
	}
	if got := main.Args; len(got) != 1 || got[0] != "-felix" {
		t.Errorf("args = %v", got)
	}
	if main.Image != "docker.io/rancher/hardened-calico:v3.32.0" {
		t.Errorf("image = %q", main.Image)
	}
	if !strings.Contains(main.Where, "DaemonSet calico-node") || !strings.Contains(main.Where, "container calico-node") {
		t.Errorf("Where does not locate the container: %q", main.Where)
	}
}

// TestParseKeepsUnsetAndEmptyApart is the distinction Kubernetes makes and a
// closure depends on: an unset args leaves the image CMD running, an empty one
// drops it. Reading both as "empty" silently removes arguments that decide what
// a wrapper entrypoint forwards to.
func TestParseKeepsUnsetAndEmptyApart(t *testing.T) {
	cs := parse(t, `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - {name: unset, image: a:1, command: ["/x"]}
    - {name: empty, image: b:1, command: ["/x"], args: []}
`)
	if len(cs) != 2 {
		t.Fatalf("got %d containers", len(cs))
	}
	if cs[0].Args != nil {
		t.Errorf("a container with no args: reported args %#v rather than nothing", cs[0].Args)
	}
	if cs[1].Args == nil {
		t.Error("a container with args: [] reported the same as one that set no args at all")
	}
	if len(cs[1].Args) != 0 {
		t.Errorf("args: [] read as %#v", cs[1].Args)
	}
}

// TestParseReadsEveryWorkloadKind walks the shapes a real cluster dump holds,
// each of which keeps its pod spec at a different depth.
func TestParseReadsEveryWorkloadKind(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"Pod", "kind: Pod\nspec:\n  containers:\n    - {name: c, image: i:1, command: [/x]}\n"},
		{"Deployment", "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - {name: c, image: i:1, command: [/x]}\n"},
		{"StatefulSet", "kind: StatefulSet\nspec:\n  template:\n    spec:\n      containers:\n        - {name: c, image: i:1, command: [/x]}\n"},
		{"Job", "kind: Job\nspec:\n  template:\n    spec:\n      containers:\n        - {name: c, image: i:1, command: [/x]}\n"},
		{"CronJob", "kind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - {name: c, image: i:1, command: [/x]}\n"},
		{"List", "kind: List\nitems:\n  - kind: Pod\n    spec:\n      containers:\n        - {name: c, image: i:1, command: [/x]}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := parse(t, tc.yaml)
			if len(cs) != 1 || cs[0].Image != "i:1" || len(cs[0].Command) != 1 {
				t.Fatalf("a %s did not yield its one container: %+v", tc.name, cs)
			}
		})
	}
}

// TestParseSkipsDocumentsWithNoContainers: a manifest file is mostly Services,
// ConfigMaps and RBAC, and none of that is an error.
func TestParseSkipsDocumentsWithNoContainers(t *testing.T) {
	cs := parse(t, `
kind: Service
metadata: {name: s}
spec:
  ports: [{port: 80}]
---
kind: ConfigMap
data: {a: b}
---
kind: Pod
spec:
  containers:
    - {name: c, image: i:1, command: [/x]}
`)
	if len(cs) != 1 {
		t.Fatalf("got %d containers, want the one Pod's", len(cs))
	}
}

// TestParseRefusesAnUnknownKindThatHasContainers is the fail-closed rule.
// Skipping a kind this cannot descend would drop its images from the scan, and
// a fleet report is read as a list of everything that runs -- an image missing
// from it looks exactly like an image nobody deployed.
func TestParseRefusesAnUnknownKindThatHasContainers(t *testing.T) {
	err := parseErr(t, `
apiVersion: apps.example.com/v1
kind: WeirdWorkload
metadata: {name: w}
spec:
  podSpec:
    containers:
      - {name: c, image: i:1, command: [/x]}
`)
	if !strings.Contains(err, "WeirdWorkload") {
		t.Errorf("the error does not name the kind it could not read: %q", err)
	}
	if !strings.Contains(err, "silently left out") {
		t.Errorf("the error does not say what the cost of skipping would have been: %q", err)
	}
}

// TestParseRefusesAManifestWithNoWorkloads: a user who points a scan at the
// wrong file gets told, rather than getting an empty fleet that scanned nothing
// and reported no findings.
func TestParseRefusesAManifestWithNoWorkloads(t *testing.T) {
	err := parseErr(t, "kind: Service\nspec:\n  ports: [{port: 80}]\n")
	if !strings.Contains(err, "no Kubernetes workload") {
		t.Errorf("unhelpful error: %q", err)
	}
}

// TestParseRefusesANonStringCommand: `command: [8080]` is a manifest that does
// not mean what it says, and coercing it roots a program named "8080".
func TestParseRefusesANonStringCommand(t *testing.T) {
	err := parseErr(t, "kind: Pod\nspec:\n  containers:\n    - {name: c, image: i:1, command: [8080]}\n")
	if !strings.Contains(err, "non-string in command") {
		t.Errorf("unhelpful error: %q", err)
	}
}

// TestParseRefusesAContainerWithNoImage: there is nothing to scan, and an entry
// silently dropped is an image missing from the fleet table.
func TestParseRefusesAContainerWithNoImage(t *testing.T) {
	err := parseErr(t, "kind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n    - {name: c, command: [/x]}\n")
	if !strings.Contains(err, "has no image") {
		t.Errorf("unhelpful error: %q", err)
	}
}

// TestParseRefusesARelativeCommandUnderAContainerPATH. Nothing here reads the
// container environment, so a bare command under a PATH the manifest sets
// resolves against the image's PATH instead -- a different program, rooting a
// different closure, with nothing in the report to show for it.
func TestParseRefusesARelativeCommandUnderAContainerPATH(t *testing.T) {
	err := parseErr(t, `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: i:1
      command: ["server"]
      env:
        - {name: PATH, value: /opt/bin}
`)
	if !strings.Contains(err, "/opt/bin") || !strings.Contains(err, "absolute") {
		t.Errorf("unhelpful error: %q", err)
	}
}

// TestParseAllowsAnAbsoluteCommandUnderAContainerPATH: the refusal above is
// narrow on purpose. An absolute command resolves to the same file whatever
// PATH says, so refusing it would reject manifests for no reason.
func TestParseAllowsAnAbsoluteCommandUnderAContainerPATH(t *testing.T) {
	cs := parse(t, `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: i:1
      command: ["/usr/bin/server"]
      env:
        - {name: PATH, value: /opt/bin}
`)
	if len(cs) != 1 {
		t.Fatalf("got %d containers", len(cs))
	}
}

// TestParseAllowsARelativeArgUnderAContainerPATH: args[0] is an argument to the
// image's ENTRYPOINT, not a program, so no PATH resolves it and the refusal
// must not fire.
func TestParseAllowsARelativeArgUnderAContainerPATH(t *testing.T) {
	cs := parse(t, `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: i:1
      args: ["serve"]
      env:
        - {name: PATH, value: /opt/bin}
`)
	if len(cs) != 1 {
		t.Fatalf("got %d containers", len(cs))
	}
}

// TestParseKeepsAContainerThatOverridesNothing. It still names an image to
// scan, and Overrides is how a caller tells the two apart.
func TestParseKeepsAContainerThatOverridesNothing(t *testing.T) {
	cs := parse(t, "kind: Pod\nspec:\n  containers:\n    - {name: c, image: i:1}\n")
	if len(cs) != 1 {
		t.Fatalf("a container with no command was dropped, so its image would not be scanned: %+v", cs)
	}
	if cs[0].Overrides() {
		t.Error("a container that sets neither command nor args reports that it overrides something")
	}
}

// TestDedupeCollapsesContainersThatAgree is what makes this usable on a real
// cluster, where one image runs in several workloads with the same command.
func TestDedupeCollapsesContainersThatAgree(t *testing.T) {
	got, err := Dedupe([]Container{
		{Image: "i:1", Command: []string{"/x"}, Where: "Deployment a"},
		{Image: "i:1", Command: []string{"/x"}, Where: "DaemonSet b"},
		{Image: "j:1", Where: "Deployment c"},
	})
	if err != nil {
		t.Fatalf("two containers saying the same thing were refused: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(got), got)
	}
	if got[0].Image != "i:1" || got[1].Image != "j:1" {
		t.Errorf("Dedupe did not keep the manifest's order: %+v", got)
	}
}

// TestDedupeRefusesContainersThatDisagree. One image started two ways has two
// closures, and a single scan reporting either one is reporting a conclusion
// that is false of half the cluster.
func TestDedupeRefusesContainersThatDisagree(t *testing.T) {
	_, err := Dedupe([]Container{
		{Image: "i:1", Command: []string{"/x"}, Where: "Deployment a, container one"},
		{Image: "i:1", Command: []string{"/y"}, Where: "DaemonSet b, container two"},
	})
	if err == nil {
		t.Fatal("two commands for one image were collapsed into one scan")
	}
	for _, want := range []string{"Deployment a, container one", "/x", "DaemonSet b, container two", "/y"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so the conflict cannot be found: %q", want, err)
		}
	}
}

// TestDedupeRefusesAnOverrideAgainstNone: "runs its own entrypoint" and "runs
// /x" are as different as two different commands are, and this is the case a
// comparison that only looked at the override's contents would let through.
func TestDedupeRefusesAnOverrideAgainstNone(t *testing.T) {
	_, err := Dedupe([]Container{
		{Image: "i:1", Where: "Deployment a"},
		{Image: "i:1", Command: []string{"/x"}, Where: "DaemonSet b"},
	})
	if err == nil {
		t.Fatal("an image run with its own entrypoint in one place and an override in another was collapsed")
	}
	if !strings.Contains(err.Error(), "the image's own entrypoint") {
		t.Errorf("the error does not say what the other one runs: %q", err)
	}
}

// TestDedupeRefusesEmptyAgainstUnset holds the nil/empty distinction all the
// way to the conflict check, where collapsing them would pick one silently.
func TestDedupeRefusesEmptyAgainstUnset(t *testing.T) {
	_, err := Dedupe([]Container{
		{Image: "i:1", Command: []string{"/x"}, Where: "Deployment a"},
		{Image: "i:1", Command: []string{"/x"}, Args: []string{}, Where: "DaemonSet b"},
	})
	if err == nil {
		t.Fatal("args: [] and no args at all were treated as the same deployment")
	}
}

// TestParseReadsEveryDocument: stopping at the first would scan whatever
// happened to be at the top of a `kubectl get -o yaml`.
func TestParseReadsEveryDocument(t *testing.T) {
	cs := parse(t, `
kind: Pod
spec: {containers: [{name: c, image: a:1, command: [/x]}]}
---
kind: Pod
spec: {containers: [{name: c, image: b:1, command: [/y]}]}
---
`)
	if len(cs) != 2 {
		t.Fatalf("got %d containers, want both documents': %+v", len(cs), cs)
	}
}

// TestParseRefusesUnreadableYAML rather than returning what it managed to read
// before the syntax error.
func TestParseRefusesUnreadableYAML(t *testing.T) {
	err := parseErr(t, "kind: Pod\nspec:\n  containers:\n   - name: c\n      image: i:1\n")
	if !strings.Contains(err, "test.yaml") {
		t.Errorf("the error does not name the file: %q", err)
	}
}
