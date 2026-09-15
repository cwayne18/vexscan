package golang

import (
	"path"
	"strings"

	"github.com/cwayne18/vexscan/internal/binscan"
	"github.com/cwayne18/vexscan/internal/target"
)

// This file reads an answer the image's own configuration already states:
// which binary is this image for?
//
// tagAuthority's other tests approximate that by name. "rancher/hardened-
// kubernetes" names k8s.io/kubernetes only because somebody spelled it that
// way, and the approximation fails on the images that need it most: the image
// for k8s.io/ingress-nginx is called "nginx-ingress-controller", and no
// dash-token of the one equals the other, so its tag was refused and a stripped
// `-trimpath` build -- which ldflagsversion.go and elfversion.go can also say
// nothing about -- fell all the way through to "(devel)" and drew every
// advisory ever filed against the module.
//
// The OCI config does not approximate. An image whose Cmd is
// /nginx-ingress-controller is that binary's image whatever it has been named,
// and reading its tag as that binary's version is the same claim the name tests
// try to reach by inference. So this is the first authority tagAuthority
// consults, and it is the one that needs no guess about spelling.
//
// It is still not proof: an image can run a binary and be tagged with something
// other than that binary's version. That is why it decides only what the *tag*
// may be read as, after the artifact itself has been asked twice and had
// nothing to say, and why the finding carries its provenance either way.

// runModules returns the main modules of the binaries the image's own default
// command runs, or nil when it runs no Go binary this scan found.
//
// The answer is a set of modules rather than of binaries because the question
// tagAuthority asks is whose version the tag states, and that is settled per
// project, not per file. ingress-nginx builds three binaries from its tree --
// the controller, /dbg and /wait-shutdown -- and its image runs one of them;
// the tag is the same module's version in all three, and they are the same
// build of the same checkout. This is the shape the name tests in tagAuthority
// already have, which grant "rancher/hardened-kubernetes" to k8s.io/kubernetes
// wherever in the image it appears.
func runModules(root string, cfg target.ImageConfig, bins []binscan.Binary) map[string]bool {
	runs := entrypointPaths(cfg)
	if len(runs) == 0 {
		return nil
	}
	var out map[string]bool
	for _, bin := range bins {
		if !runs[target.Rel(root, bin.Path)] {
			continue
		}
		if m := mainModulePath(bin); m != "" {
			if out == nil {
				out = map[string]bool{}
			}
			out[m] = true
		}
	}
	return out
}

// entrypointPaths returns the image paths the image's default command names as
// programs to run, or nil when it names none. Outside image mode there is no
// config and so no answer, which is the zero value.
//
// Only the leading run of argv is read. Scanning stops at the first option,
// because everything after one is that program's own arguments: "/coredns -conf
// /etc/coredns/Corefile" runs coredns, and the path after the flag is a file it
// reads. A bare "--" is a separator rather than an option -- it is how the init
// shims that so often occupy argv[0] hand off to the real program, as
// catatonit does in the ingress-nginx image -- so it is stepped over.
//
// A bare name is not resolved against the filesystem; it expands to one
// candidate per PATH directory. The only question ever asked of this set is
// whether a binary already in hand belongs to it, and for that a superset over
// the image's own PATH is the same answer without the I/O: two directories on
// PATH holding a same-named Go binary hold the same program.
func entrypointPaths(cfg target.ImageConfig) map[string]bool {
	var out map[string]bool
	add := func(p string) {
		if out == nil {
			out = map[string]bool{}
		}
		out[p] = true
	}
	for _, arg := range cfg.Argv() {
		switch {
		case arg == "" || arg == "--":
			continue
		case strings.HasPrefix(arg, "-"):
			return out
		case strings.HasPrefix(arg, "/"):
			add(path.Clean(arg))
		case strings.Contains(arg, "/"):
			// Relative to the working directory the image declares, the way a
			// runtime would resolve it.
			add(path.Join("/", cfg.WorkingDir, arg))
		default:
			for _, dir := range cfg.PathDirs() {
				add(path.Join(dir, arg))
			}
		}
	}
	return out
}
