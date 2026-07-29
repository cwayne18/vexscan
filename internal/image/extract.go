// Package image copies and flattens a container image's filesystem to a local
// directory using skopeo, and reports the image configuration.
//
// Flattening is faithful enough to reason about what the image actually ships:
// whiteouts are applied (so a file deleted by a later layer is really gone),
// symlinks are recreated as symlinks (so shared-library soname resolution can
// follow them), and hardlinks are materialized. Extraction is hostile-input
// safe: every entry path is resolved inside the destination root, so a layer
// containing a symlink to /etc cannot write through it.
package image

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// Overlay whiteout markers. An opaque marker hides everything the lower layers
// put in its directory; a plain marker hides one named sibling.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// maxSymlinkHops bounds symlink resolution so a layer containing a link cycle
// cannot hang extraction.
const maxSymlinkHops = 64

// Config is the subset of the OCI image configuration vexscan needs. Entrypoint
// and Cmd are what root the ELF reachability closure: without them there is
// nothing to walk the shared-library graph from, and every library in the image
// has to be treated as potentially loaded.
type Config struct {
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	Env        []string `json:"env,omitempty"`
	WorkingDir string   `json:"working_dir,omitempty"`
	User       string   `json:"user,omitempty"`
}

// Extractor flattens container images.
type Extractor struct {
	// OS and Arch select the platform variant to pull (default linux/amd64).
	OS   string
	Arch string
	// SkopeoPath overrides the skopeo binary (default: found on PATH).
	SkopeoPath string
}

// NewExtractor returns an Extractor with linux/amd64 defaults.
func NewExtractor() *Extractor {
	return &Extractor{OS: "linux", Arch: "amd64", SkopeoPath: "skopeo"}
}

type ociManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// configFile is the on-disk OCI image config blob.
type configFile struct {
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
		User       string   `json:"User"`
	} `json:"config"`
}

// Extract copies image into a temporary OCI dir with skopeo and untars every
// layer, in order, into dest. Later layers overwrite earlier ones and their
// whiteouts delete from earlier ones, yielding the final image filesystem
// state. It returns the image configuration.
func (e *Extractor) Extract(ctx context.Context, image, dest string) (*Config, error) {
	if _, err := exec.LookPath(e.SkopeoPath); err != nil {
		return nil, fmt.Errorf("skopeo not found on PATH: %w", err)
	}

	raw, err := os.MkdirTemp("", "vexscan-oci-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(raw)

	cmd := exec.CommandContext(ctx, e.SkopeoPath, "copy", "-q",
		"--override-os", e.OS, "--override-arch", e.Arch,
		"docker://"+image, "dir:"+raw)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("skopeo copy failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	manifestBytes, err := os.ReadFile(filepath.Join(raw, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m ociManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destAbs, 0o755); err != nil {
		return nil, err
	}

	for _, layer := range m.Layers {
		blob := blobPath(raw, layer.Digest)
		if blob == "" {
			continue
		}
		if _, err := os.Stat(blob); err != nil {
			continue
		}
		if err := untar(blob, destAbs); err != nil {
			return nil, fmt.Errorf("extract layer %s: %w", layer.Digest, err)
		}
	}

	// A missing or unparseable config is not fatal: the rest of the analysis
	// still works, callers just lose the closure roots and have to treat the
	// whole image as potentially reachable.
	return readConfig(blobPath(raw, m.Config.Digest)), nil
}

// blobPath maps a "sha256:<hex>" descriptor digest to the blob file skopeo
// wrote, which is named by the bare hex.
func blobPath(raw, digest string) string {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return ""
	}
	return filepath.Join(raw, parts[1])
}

// readConfig parses an image config blob, returning an empty Config when it is
// absent or malformed.
func readConfig(blob string) *Config {
	if blob == "" {
		return &Config{}
	}
	data, err := os.ReadFile(blob)
	if err != nil {
		return &Config{}
	}
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return &Config{}
	}
	return &Config{
		Entrypoint: cf.Config.Entrypoint,
		Cmd:        cf.Config.Cmd,
		Env:        cf.Config.Env,
		WorkingDir: cf.Config.WorkingDir,
		User:       cf.Config.User,
	}
}

// untar extracts a (possibly gzip/bzip2-compressed) tar blob into destAbs. It
// is intentionally tolerant: individual bad entries are skipped rather than
// aborting the whole layer.
func untar(blob, destAbs string) error {
	f, err := os.Open(blob)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := decompress(f)
	if err != nil {
		return err
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Corrupt trailing data: stop but don't fail the whole run.
			break
		}

		name := path.Clean("/" + hdr.Name)
		if name == "/" {
			continue
		}
		dir, base := path.Split(name)

		// Whiteouts delete from the layers below instead of adding anything.
		// Check the opaque marker first: it also carries the .wh. prefix.
		if base == whiteoutOpaque {
			if p, err := resolve(destAbs, dir); err == nil {
				clearDir(p)
			}
			continue
		}
		if strings.HasPrefix(base, whiteoutPrefix) {
			victim := path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))
			if p, err := resolveParent(destAbs, victim); err == nil {
				_ = os.RemoveAll(p)
			}
			continue
		}

		// Resolve the parent chain but not the final component, so an entry
		// replaces an existing symlink rather than writing through it.
		target, err := resolveParent(destAbs, name)
		if err != nil {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := makeDir(target); err != nil {
				continue
			}
		case tar.TypeReg:
			if err := writeFile(tr, target, os.FileMode(hdr.Mode)); err != nil {
				continue
			}
		case tar.TypeSymlink:
			if err := writeSymlink(hdr.Linkname, target); err != nil {
				continue
			}
		case tar.TypeLink:
			if err := writeHardlink(destAbs, hdr.Linkname, target); err != nil {
				continue
			}
		default:
			// Devices, FIFOs and sockets carry no code; skip them.
			continue
		}
	}
	return nil
}

// decompress sniffs the leading magic bytes and wraps f accordingly.
func decompress(f *os.File) (io.Reader, error) {
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		// Too short to be compressed; rewind and read as a plain tar.
		if _, serr := f.Seek(0, io.SeekStart); serr != nil {
			return nil, serr
		}
		return f, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	switch {
	case magic[0] == 0x1f && magic[1] == 0x8b:
		return gzip.NewReader(f)
	case magic[0] == 'B' && magic[1] == 'Z':
		return bzip2.NewReader(f), nil
	}
	return f, nil
}

// resolve maps an image-absolute path to a host path inside root, following
// symlinks that already exist in the extracted tree but never escaping root.
// Absolute link targets are re-rooted, exactly as they would resolve inside the
// running container, and ".." is clamped at root. This is what makes extraction
// safe against a layer that symlinks a directory onto the host filesystem.
func resolve(root, name string) (string, error) {
	rest := strings.Split(path.Clean("/"+name), "/")
	var resolved []string
	hops := 0

	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]

		switch comp {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}

		candidate := filepath.Join(root, filepath.Join(resolved...), comp)
		fi, err := os.Lstat(candidate)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, comp)
			continue
		}

		hops++
		if hops > maxSymlinkHops {
			return "", fmt.Errorf("symlink loop resolving %q", name)
		}
		link, err := os.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if path.IsAbs(link) {
			resolved = resolved[:0]
		}
		rest = append(strings.Split(path.Clean(link), "/"), rest...)
	}
	return filepath.Join(root, filepath.Join(resolved...)), nil
}

// resolveParent resolves everything but the last component of name. Used for
// entry targets so that writing over an existing symlink replaces the link
// itself, matching overlay semantics.
func resolveParent(root, name string) (string, error) {
	clean := path.Clean("/" + name)
	dir, base := path.Split(clean)
	parent, err := resolve(root, dir)
	if err != nil {
		return "", err
	}
	if base == "" {
		return parent, nil
	}
	return filepath.Join(parent, base), nil
}

// clearDir removes everything inside dir, implementing an opaque whiteout.
func clearDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}

// makeDir creates target as a directory, replacing a non-directory of the same
// name left behind by a lower layer.
func makeDir(target string) error {
	if fi, err := os.Lstat(target); err == nil && !fi.IsDir() {
		_ = os.Remove(target)
	}
	return os.MkdirAll(target, 0o755)
}

// replaceExisting clears the way for a new entry at target.
func replaceExisting(target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(target); err == nil {
		if fi.IsDir() {
			return os.RemoveAll(target)
		}
		return os.Remove(target)
	}
	return nil
}

func writeFile(r io.Reader, target string, mode os.FileMode) error {
	if err := replaceExisting(target); err != nil {
		return err
	}
	// Force owner-write so a read-only mode in the layer doesn't stop a later
	// layer from replacing the file, or cleanup from removing it.
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm()|0o200)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}

// writeSymlink recreates a symlink verbatim. The raw target is preserved rather
// than resolved, because soname resolution needs to see what the link actually
// says (libssl.so.3 -> libssl.so.3.0.11).
func writeSymlink(linkname, target string) error {
	if err := replaceExisting(target); err != nil {
		return err
	}
	return os.Symlink(linkname, target)
}

// writeHardlink materializes a hardlink. It prefers a real link to avoid
// duplicating large binaries, and falls back to a copy when the filesystem
// refuses.
func writeHardlink(root, linkname, target string) error {
	src, err := resolveParent(root, linkname)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(src); err != nil {
		return err // link target never appeared; skip rather than invent a file
	}
	if err := replaceExisting(target); err != nil {
		return err
	}
	if err := os.Link(src, target); err == nil {
		return nil
	}
	return copyFile(src, target)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm()|0o200)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
