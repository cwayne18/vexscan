package target

import (
	"path"
	"strings"
)

// defaultPath is what the dynamic loader and shells fall back to when an image
// config sets no PATH. It matches the Docker default.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// ImageConfig is the subset of the OCI image configuration vexscan reasons
// about. Entrypoint and Cmd matter most: they are what roots the ELF
// reachability closure. Without them there is nothing to walk the
// shared-library graph from, and every library in the image has to be treated
// as potentially loaded.
type ImageConfig struct {
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"working_dir,omitempty"`
	User       string   `json:"user,omitempty"`
}

// Argv is the command the image runs by default: Entrypoint with Cmd appended,
// matching how a runtime composes them when Entrypoint is set.
func (c ImageConfig) Argv() []string {
	argv := make([]string, 0, len(c.Entrypoint)+len(c.Cmd))
	argv = append(argv, c.Entrypoint...)
	argv = append(argv, c.Cmd...)
	return argv
}

// LookupEnv returns the value of key in the image environment. Later entries
// win, as they do when a runtime builds the environment.
func (c ImageConfig) LookupEnv(key string) (string, bool) {
	val, ok := "", false
	for _, kv := range c.Env {
		k, v, found := strings.Cut(kv, "=")
		if found && k == key {
			val, ok = v, true
		}
	}
	return val, ok
}

// PathDirs is the image's PATH, split, falling back to the runtime default when
// the config sets none. Used to resolve a bare argv[0] to an actual file.
func (c ImageConfig) PathDirs() []string {
	p, ok := c.LookupEnv("PATH")
	if !ok || strings.TrimSpace(p) == "" {
		p = defaultPath
	}
	var dirs []string
	for _, d := range strings.Split(p, ":") {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, path.Clean("/"+d))
		}
	}
	return dirs
}

// Image is an extracted container image: its filesystem plus the configuration
// that says how it is meant to be run.
//
// It also carries a rootfs the user already had on disk, which is the same
// thing minus the parts only a registry can supply. Nothing here is required:
// no analyzer reads Ref, OS or Arch, and Config is optional by construction --
// a plugin that wants an entrypoint and finds none taints its conclusions
// rather than failing. So a tree with nothing but FS set is a scannable target,
// just one that can say less.
type Image struct {
	// Ref is the target as the user named it: an image reference, or the
	// directory a rootfs was read from.
	Ref string
	// OS and Arch are the platform variant that was pulled. Both are empty for
	// a rootfs, which was never pulled and whose platform nobody declared.
	OS   string
	Arch string

	// Config is how the image says it is meant to be run. It is the zero value
	// for a rootfs: a directory carries no entrypoint, no env and no PATH.
	Config ImageConfig
	FS     RootFS
}

// Source is a checked-out source tree.
//
// Unlike an image it has no meaningful "inside" path space — analysis tools run
// against host paths — so Dir, not FS, is what most consumers want. FS exists so
// that plugins which merely look for manifest files (go.mod, package-lock.json,
// requirements.txt) can share one code path with image mode.
type Source struct {
	// Ref is the repo as the user named it: a URL, owner/repo, or local path.
	Ref string
	// Rev is the resolved branch, tag or commit, when known.
	Rev string
	// Dir is the host directory of the module to analyze — the checkout root
	// joined with any requested subdirectory.
	Dir string
	// Subdir is that subdirectory relative to the checkout root ("." at the
	// top level).
	Subdir string

	FS RootFS
}
