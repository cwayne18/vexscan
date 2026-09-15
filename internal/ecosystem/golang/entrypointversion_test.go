package golang

import (
	"reflect"
	"testing"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/target"
)

func TestEntrypointPaths(t *testing.T) {
	tests := []struct {
		name string
		cfg  target.ImageConfig
		want []string
	}{{
		// The case this whole file is for. catatonit occupies argv[0] and hands
		// off across a "--" to the binary the image actually exists to run.
		name: "init shim hands off past a separator",
		cfg: target.ImageConfig{
			Entrypoint: []string{"/usr/bin/catatonit", "--"},
			Cmd:        []string{"/nginx-ingress-controller"},
		},
		want: []string{"/usr/bin/catatonit", "/nginx-ingress-controller"},
	}, {
		name: "plain entrypoint",
		cfg:  target.ImageConfig{Entrypoint: []string{"/pod_nanny"}},
		want: []string{"/pod_nanny"},
	}, {
		// Everything after an option belongs to the program, so the Corefile
		// must not be taken for something the image runs.
		name: "scanning stops at the first option",
		cfg: target.ImageConfig{
			Entrypoint: []string{"/coredns", "-conf", "/etc/coredns/Corefile"},
		},
		want: []string{"/coredns"},
	}, {
		// A bare name expands over PATH rather than being resolved on disk.
		name: "bare name expands across PATH",
		cfg: target.ImageConfig{
			Cmd: []string{"entry"},
			Env: []string{"PATH=/usr/local/bin:/bin"},
		},
		want: []string{"/usr/local/bin/entry", "/bin/entry"},
	}, {
		name: "relative path resolves against the working directory",
		cfg: target.ImageConfig{
			WorkingDir: "/app",
			Cmd:        []string{"./server"},
		},
		want: []string{"/app/server"},
	}, {
		// A rootfs, or an image whose config sets neither. Nil, not a panic.
		name: "no command at all",
		cfg:  target.ImageConfig{},
		want: nil,
	}, {
		// A shell entrypoint names the shell, and nothing about the Go binaries
		// alongside it. klipper-helm is exactly this.
		name: "shell entrypoint names only the shell",
		cfg:  target.ImageConfig{Cmd: []string{"/bin/bash"}},
		want: []string{"/bin/bash"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := entrypointPaths(tt.cfg)
			want := map[string]bool{}
			for _, p := range tt.want {
				want[p] = true
			}
			if len(tt.want) == 0 {
				if got != nil {
					t.Fatalf("entrypointPaths = %v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("entrypointPaths = %v, want %v", got, want)
			}
		})
	}
}

// The evidence beats the naming. No dash-token of "nginx-ingress-controller"
// equals "ingress-nginx", so every name test refuses this tag -- and the image
// config says outright that this binary is what the image runs.
func TestRunningTheBinaryIsAuthorityTheNameTestsRefuse(t *testing.T) {
	const (
		mod = "k8s.io/ingress-nginx"
		ref = "registry.rancher.com/rancher/nginx-ingress-controller:v1.15.1-prime11"
	)
	if why := tagAuthority(mod, ref, "v1.15.1-prime11", false); why != "" {
		t.Fatalf("name tests = %q, want refusal: the premise here is that they cannot match", why)
	}
	got, _, why := moduleVersionFromImageTag(mod, ref, true)
	if got != "v1.15.1-prime11" {
		t.Errorf("version = %q, want v1.15.1-prime11", got)
	}
	if why == "" {
		t.Error("why = \"\", want the entrypoint authority")
	}
}

// Running the binary says nothing about whether the tag is a version. An image
// that runs its binary and is tagged "latest" still has no version to read.
func TestRunningTheBinaryDoesNotMakeANonVersionATag(t *testing.T) {
	for _, tag := range []string{"latest", "20240101", ""} {
		ref := "myorg/app"
		if tag != "" {
			ref += ":" + tag
		}
		if got, _, why := moduleVersionFromImageTag("example.com/app", ref, true); got != "" || why != "" {
			t.Errorf("tag %q: got (%q, %q), want refusal", tag, got, why)
		}
	}
}

// End to end through inventory, on the shape the real ingress-nginx image has.
//
// Three things are being separated. The binary the image runs takes the tag.
// So does /wait-shutdown, which the image does not run but which is the same
// module out of the same build -- the tag states that project's version, not
// that file's. A binary of some *other* module is left at "(devel)" to
// over-report, because nothing here says anything about its version.
func TestTheTagGoesToTheModuleTheImageRunsNotJustTheFile(t *testing.T) {
	root := t.TempDir()
	const ref = "registry.example.com/rancher/nginx-ingress-controller:v1.15.1"

	runs := mainVersionBinary(root+"/nginx-ingress-controller", "k8s.io/ingress-nginx", "(devel)")
	sibling := mainVersionBinary(root+"/wait-shutdown", "k8s.io/ingress-nginx", "(devel)")
	bystander := mainVersionBinary(root+"/usr/bin/sidecar", "github.com/some/sidecar", "(devel)")

	bins := []binscan.Binary{runs, sibling, bystander}
	p := New(Options{Image: ref})
	p.runsModule = runModules(root, target.ImageConfig{
		Entrypoint: []string{"/usr/bin/catatonit", "--"},
		Cmd:        []string{"/nginx-ingress-controller"},
	}, bins)
	comps := p.groupAll(root, bins)

	c := mainComponent(comps, "k8s.io/ingress-nginx")
	if c == nil {
		t.Fatal("no component for the module the image runs")
	}
	if c.Version != "v1.15.1" {
		t.Errorf("version = %q, want v1.15.1 from the tag", c.Version)
	}
	st := c.Extra.(*state)
	if st.inferred.origin != "image-tag-version" {
		t.Errorf("origin = %q, want image-tag-version", st.inferred.origin)
	}

	// The sibling binary rides in that same component rather than leaving a
	// second one behind at "(devel)": one module at one version, two files.
	var ing []string
	for _, c := range comps {
		if c.Name == "k8s.io/ingress-nginx" {
			ing = append(ing, c.Version)
		}
	}
	if len(ing) != 1 {
		t.Errorf("ingress-nginx components = %v, want exactly one: /wait-shutdown is the same module", ing)
	}

	if c := mainComponent(comps, "github.com/some/sidecar"); c == nil {
		t.Error("no component for the bystander binary")
	} else if !isDevelVersion(c.Version) {
		t.Errorf("bystander version = %q, want it left uncomparable: the image does not run it", c.Version)
	}
}

// A shell entrypoint names the shell, so the Go binaries beside it get no
// authority from it. This is klipper-helm, whose "entry" is a script.
func TestShellEntrypointGrantsNoAuthority(t *testing.T) {
	root := t.TempDir()
	bin := mainVersionBinary(root+"/usr/bin/helm-set-status", "github.com/k3s-io/helm-set-status", "(devel)")

	bins := []binscan.Binary{bin}
	p := New(Options{Image: "rancher/klipper-helm:v0.13.3"})
	p.runsModule = runModules(root, target.ImageConfig{Entrypoint: []string{"entry"}}, bins)

	c := mainComponent(p.groupAll(root, bins), "github.com/k3s-io/helm-set-status")
	if c == nil {
		t.Fatal("no component")
	}
	if !isDevelVersion(c.Version) {
		t.Errorf("version = %q, want it left uncomparable: a script is what the image runs", c.Version)
	}
}
