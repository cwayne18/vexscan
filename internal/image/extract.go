// Package image copies and flattens a container image's filesystem to a local
// directory using skopeo, mirroring the extract_image() helper in the
// rke2-toolbox vex_candidates.py script.
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
	"path/filepath"
	"strings"
)

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
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// Extract copies image into a temporary OCI dir with skopeo and untars every
// layer, in order, into dest. Later layers overwrite earlier ones, yielding the
// final image filesystem state.
func (e *Extractor) Extract(ctx context.Context, image, dest string) error {
	if _, err := exec.LookPath(e.SkopeoPath); err != nil {
		return fmt.Errorf("skopeo not found on PATH: %w", err)
	}

	raw, err := os.MkdirTemp("", "vexscan-oci-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(raw)

	cmd := exec.CommandContext(ctx, e.SkopeoPath, "copy", "-q",
		"--override-os", e.OS, "--override-arch", e.Arch,
		"docker://"+image, "dir:"+raw)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("skopeo copy failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	manifestBytes, err := os.ReadFile(filepath.Join(raw, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var m ociManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	for _, layer := range m.Layers {
		parts := strings.SplitN(layer.Digest, ":", 2)
		if len(parts) != 2 {
			continue
		}
		blob := filepath.Join(raw, parts[1])
		if _, err := os.Stat(blob); err != nil {
			continue
		}
		if err := untar(blob, dest); err != nil {
			return fmt.Errorf("extract layer %s: %w", parts[1], err)
		}
	}
	return nil
}

// untar extracts a (possibly gzip/bzip2-compressed) tar blob into dest. It is
// intentionally tolerant: individual bad entries are skipped rather than
// aborting the whole layer, matching the best-effort behaviour of the Python
// script's `tar -xf`.
func untar(blob, dest string) error {
	f, err := os.Open(blob)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	br := make([]byte, 2)
	if _, err := io.ReadFull(f, br); err == nil {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		switch {
		case br[0] == 0x1f && br[1] == 0x8b: // gzip
			gz, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer gz.Close()
			r = gz
		case br[0] == 'B' && br[1] == 'Z': // bzip2
			r = bzip2.NewReader(f)
		}
	} else {
		if _, serr := f.Seek(0, io.SeekStart); serr != nil {
			return serr
		}
	}

	tr := tar.NewReader(r)
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Corrupt trailing data: stop but don't fail the whole run.
			break
		}
		name := hdr.Name
		// Skip whiteout files produced by overlay diffs.
		base := filepath.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			continue
		}
		target := filepath.Join(destAbs, filepath.Clean("/"+name))
		if !strings.HasPrefix(target, destAbs+string(os.PathSeparator)) && target != destAbs {
			continue // path traversal guard
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			if err := writeFile(tr, target, os.FileMode(hdr.Mode)); err != nil {
				continue
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Ignore links: we only need regular files to inspect binaries and
			// following links across a flattened FS is unsafe.
			continue
		}
	}
	return nil
}

func writeFile(r io.Reader, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	// Remove any pre-existing entry so a later layer overwrites an earlier one.
	_ = os.Remove(target)
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode|0o200)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}
