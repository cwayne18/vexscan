package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Hauler manifests as an --images-from list.
//
// A haul is the bundle; a hauler manifest is the declaration that produced it.
// The manifest is checked into a repository next to the pipeline that builds
// the bundle, which makes it the natural thing to point a scan at before the
// bundle exists -- "what are we about to ship" rather than "what did we ship".
//
// It is read here and not in internal/haul because it is not a haul: it names
// images to pull from registries, which is exactly what --images-from already
// does with a text file. The only new thing is the parsing.
//
// The manifest is intent, and the gap between it and a haul is the reason the
// warnings below exist. A Charts entry with add-images resolves, at build
// time, into images that appear in the store and are named nowhere in the
// manifest, so a scan driven from the manifest is a strict subset of a scan
// driven from the haul. That is fine as long as it is said out loud, and a
// silent subset is the one thing it must not be.

// haulerGroup is the API group hauler's content manifests live in. The version
// is not matched: v1alpha1 and v1 differ in ways that do not touch the two
// fields read here, and refusing a manifest for its version suffix would break
// on the next one for no reason.
const haulerGroup = "content.hauler.cattle.io"

// haulerCollectionGroup is the other group hauler defines. Nothing in it is a
// list of images, so it is recognised only in order to say so.
const haulerCollectionGroup = "collection.hauler.cattle.io"

// haulerDoc is one YAML document of a hauler manifest, reduced to what this
// needs: what kind it is, and the image names if it is the kind that has any.
type haulerDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Spec       struct {
		Images []struct {
			Name string `yaml:"name"`
		} `yaml:"images"`
		Charts []struct {
			Name      string `yaml:"name"`
			AddImages bool   `yaml:"add-images"`
		} `yaml:"charts"`
		Files []struct {
			Path string `yaml:"path"`
		} `yaml:"files"`
	} `yaml:"spec"`
}

// looksLikeHaulerManifest reports whether the bytes are a hauler manifest
// rather than a list of references.
//
// It tests for the API group rather than for YAML in general, and it tests the
// text rather than trying a parse, because the two formats overlap: a list of
// image references is also, technically, a valid YAML document (a string).
// Deciding on the group means a file has to say it is a hauler manifest before
// it is read as one, and anything else keeps the behaviour it had.
func looksLikeHaulerManifest(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "apiVersion:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "apiVersion:"))
		v = strings.Trim(v, `"'`)
		if strings.HasPrefix(v, haulerGroup+"/") || strings.HasPrefix(v, haulerCollectionGroup+"/") {
			return true
		}
	}
	return false
}

// parseHaulerManifest reads every Images document in a hauler manifest.
//
// Every document is parsed, not just the first: a manifest file conventionally
// holds an Images, a Charts and a Files document separated by "---", and
// stopping at the first would scan whatever happened to be at the top.
//
// A document that cannot be parsed is an error and not a skip. The purpose of
// this function is to produce the complete list of images a manifest names,
// and a version of it that quietly drops the document it could not read would
// return a shorter list with no indication that it had.
func parseHaulerManifest(s string) ([]string, error) {
	dec := yaml.NewDecoder(strings.NewReader(s))

	var (
		images      []string
		seen        = map[string]bool{}
		chartImages []string // charts whose images the manifest does not name
		charts      int
		files       int
		other       []string
		docs        int
	)
	for {
		var doc haulerDoc
		err := dec.Decode(&doc)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("document %d: %w", docs+1, err)
		}
		docs++
		if doc.Kind == "" && doc.APIVersion == "" {
			continue // an empty document, which a trailing "---" produces
		}

		switch doc.Kind {
		case "Images":
			for _, img := range doc.Spec.Images {
				name := strings.TrimSpace(img.Name)
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				images = append(images, name)
			}
		case "Charts", "ThickCharts":
			charts += len(doc.Spec.Charts)
			for _, c := range doc.Spec.Charts {
				if c.AddImages {
					chartImages = append(chartImages, c.Name)
				}
			}
		case "Files":
			files += len(doc.Spec.Files)
		default:
			other = append(other, doc.Kind)
		}
	}

	warnManifestGaps(charts, files, chartImages, other)
	return images, nil
}

// warnManifestGaps says what the manifest declared that this scan will not
// cover. See the package comment above for why a silent subset is not an
// option.
func warnManifestGaps(charts, files int, chartImages, other []string) {
	if len(chartImages) > 0 {
		// The important one. add-images means hauler resolved these charts'
		// images into the store when it built the bundle, so the haul has
		// images this manifest does not name -- and scanning the manifest
		// misses exactly those.
		fmt.Fprintf(os.Stderr,
			"warning: %s in this manifest set add-images, so the haul built from it contains images this\n"+
				"         manifest does not name, and this scan does not cover them. Scan the haul itself\n"+
				"         with --haul to include them:\n",
			tally(len(chartImages), "chart"))
		for _, c := range chartImages {
			fmt.Fprintf(os.Stderr, "         %s\n", c)
		}
	}
	if n := charts - len(chartImages); n > 0 {
		fmt.Fprintf(os.Stderr, "warning: %s in this manifest %s not scanned; vexscan has no chart target.\n",
			tally(n, "chart"), isAre(n))
	}
	if files > 0 {
		fmt.Fprintf(os.Stderr, "warning: %s in this manifest %s not scanned; vexscan has no file target.\n",
			tally(files, "file"), isAre(files))
	}
	for _, kind := range dedupe(other) {
		fmt.Fprintf(os.Stderr, "warning: this manifest declares a %s document, which vexscan does not read.\n", kind)
	}
}
