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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/cwayne18/vexscan/internal/target"
)

// Overlay whiteout markers. An opaque marker hides everything the lower layers
// put in its directory; a plain marker hides one named sibling.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// maxImageBytes caps the total uncompressed bytes written while flattening one
// image. Real images legitimately ship large layers -- a multi-GB base image
// with a language runtime and toolchain is unremarkable -- so the ceiling is
// deliberately high; no honest image comes close. Like maxBody in
// triage/cache.go it is a backstop against hostile input, here a decompression
// bomb: a crafted layer whose entries claim to inflate to far more than any
// real image, which io.Copy would otherwise write until the disk is exhausted.
// The budget is cumulative across every layer, because a flood of small files
// fills a disk just as well as one enormous one.
const maxImageBytes = 32 << 30

// errImageTooLarge means extraction hit maxImageBytes. It is a hard stop, not a
// skippable per-entry problem: silently truncating the file, or dropping the
// rest of the layer, would under-report what the image ships, which this tool
// must never do. The caller turns it into a failed run instead.
var errImageTooLarge = errors.New("image exceeds extraction size limit")

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

// Extract copies ref into a temporary OCI dir with skopeo and untars every
// layer, in order, into dest. Later layers overwrite earlier ones and their
// whiteouts delete from earlier ones, yielding the final image filesystem
// state. The returned Image owns no resources: dest stays the caller's to
// clean up.
func (e *Extractor) Extract(ctx context.Context, ref, dest string) (*target.Image, error) {
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
		"docker://"+ref, "dir:"+raw)
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

	// One byte budget for the whole image, shared across layers, so a bomb
	// split over many layers is caught just like a single fat one.
	remaining := int64(maxImageBytes)
	for _, layer := range m.Layers {
		blob := blobPath(raw, layer.Digest)
		if blob == "" {
			continue
		}
		if _, err := os.Stat(blob); err != nil {
			continue
		}
		if err := untar(blob, destAbs, &remaining); err != nil {
			return nil, fmt.Errorf("extract layer %s: %w", layer.Digest, err)
		}
	}

	// A missing or unparseable config is not fatal: the rest of the analysis
	// still works, callers just lose the closure roots and have to treat the
	// whole image as potentially reachable.
	return &target.Image{
		Ref:    ref,
		OS:     e.OS,
		Arch:   e.Arch,
		Config: readConfig(blobPath(raw, m.Config.Digest)),
		FS:     target.NewDirFS(destAbs),
	}, nil
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

// readConfig parses an image config blob, returning a zero ImageConfig when it
// is absent or malformed.
func readConfig(blob string) target.ImageConfig {
	if blob == "" {
		return target.ImageConfig{}
	}
	data, err := os.ReadFile(blob)
	if err != nil {
		return target.ImageConfig{}
	}
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return target.ImageConfig{}
	}
	return target.ImageConfig{
		Entrypoint: cf.Config.Entrypoint,
		Cmd:        cf.Config.Cmd,
		Env:        cf.Config.Env,
		WorkingDir: cf.Config.WorkingDir,
		User:       cf.Config.User,
	}
}

// untar extracts a (possibly gzip/bzip2-compressed) tar blob into destAbs,
// charging bytes written against budget. It tolerates individual unusable
// entries -- a single file it cannot place is skipped -- but a genuine
// mid-stream read error is fatal: the remaining entries are real packages, and
// abandoning them silently would under-report the image, so the error is
// returned for the caller to fail the run on.
func untar(blob, destAbs string, budget *int64) error {
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
			// A truncated or corrupt stream. Everything past this point is
			// unreadable, and pretending it was clean padding would hide real
			// entries, so surface it rather than break out silently.
			return fmt.Errorf("read tar: %w", err)
		}

		name := path.Clean("/" + hdr.Name)
		if name == "/" {
			continue
		}
		dir, base := path.Split(name)

		// Whiteouts delete from the layers below instead of adding anything.
		// Check the opaque marker first: it also carries the .wh. prefix.
		if base == whiteoutOpaque {
			if p, err := target.Resolve(destAbs, dir); err == nil {
				clearDir(p)
			}
			continue
		}
		if strings.HasPrefix(base, whiteoutPrefix) {
			victim := path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))
			if p, err := target.ResolveParent(destAbs, victim); err == nil {
				_ = os.RemoveAll(p)
			}
			continue
		}

		// Resolve the parent chain but not the final component, so an entry
		// replaces an existing symlink rather than writing through it.
		dst, err := target.ResolveParent(destAbs, name)
		if err != nil {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := makeDir(dst); err != nil {
				continue
			}
		case tar.TypeReg:
			if err := writeFile(tr, dst, os.FileMode(hdr.Mode), budget); err != nil {
				// A blown budget is a decompression bomb, not a merely awkward
				// file: stop the whole extraction instead of skipping ahead and
				// under-reporting the rest of the layer.
				if errors.Is(err, errImageTooLarge) {
					return err
				}
				continue
			}
		case tar.TypeSymlink:
			if err := writeSymlink(hdr.Linkname, dst); err != nil {
				continue
			}
		case tar.TypeLink:
			if err := writeHardlink(destAbs, hdr.Linkname, dst, budget); err != nil {
				// The copy fallback charges bytes like a regular file, so a
				// blown budget here is the same hard stop, not a skippable entry.
				if errors.Is(err, errImageTooLarge) {
					return err
				}
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

// makeDir creates dst as a directory, replacing a non-directory of the same
// name left behind by a lower layer.
func makeDir(dst string) error {
	if fi, err := os.Lstat(dst); err == nil && !fi.IsDir() {
		_ = os.Remove(dst)
	}
	return os.MkdirAll(dst, 0o755)
}

// replaceExisting clears the way for a new entry at dst.
func replaceExisting(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(dst); err == nil {
		if fi.IsDir() {
			return os.RemoveAll(dst)
		}
		return os.Remove(dst)
	}
	return nil
}

func writeFile(r io.Reader, dst string, mode os.FileMode, budget *int64) error {
	if err := replaceExisting(dst); err != nil {
		return err
	}
	// Force owner-write so a read-only mode in the layer doesn't stop a later
	// layer from replacing the file, or cleanup from removing it.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm()|0o200)
	if err != nil {
		return err
	}
	defer out.Close()
	// Read one byte past the remaining budget: if the copy actually delivers
	// it, the file alone would overrun the ceiling. The partially written file
	// is left for the caller to discard along with the whole extraction; we do
	// not truncate it and carry on, which would silently under-report contents.
	n, err := io.Copy(out, io.LimitReader(r, *budget+1))
	if err != nil {
		return err
	}
	if n > *budget {
		return errImageTooLarge
	}
	*budget -= n
	return nil
}

// writeSymlink recreates a symlink verbatim. The raw link target is preserved
// rather than resolved, because soname resolution needs to see what the link
// actually says (libssl.so.3 -> libssl.so.3.0.11).
func writeSymlink(linkname, dst string) error {
	if err := replaceExisting(dst); err != nil {
		return err
	}
	return os.Symlink(linkname, dst)
}

// writeHardlink materializes a hardlink. It prefers a real link to avoid
// duplicating large binaries, and falls back to a copy when the filesystem
// refuses. The real link duplicates no bytes so it is not charged; the copy
// fallback duplicates the file's contents and is charged against budget exactly
// like writeFile, so a layer full of hardlinks to one large file cannot exhaust
// the disk when os.Link fails (cross-device dest, or the per-inode link-count
// limit exceeded) and every entry falls back to a copy.
func writeHardlink(root, linkname, dst string, budget *int64) error {
	src, err := target.ResolveParent(root, linkname)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(src); err != nil {
		return err // link dst never appeared; skip rather than invent a file
	}
	if err := replaceExisting(dst); err != nil {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst, budget)
}

func copyFile(src, dst string, budget *int64) error {
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
	// Charge the copy against the image budget, one byte past the remainder so
	// an overrun is detectable. See writeFile: never silently truncate.
	n, err := io.Copy(out, io.LimitReader(in, *budget+1))
	if err != nil {
		return err
	}
	if n > *budget {
		return errImageTooLarge
	}
	*budget -= n
	return nil
}
