package ospkg

import (
	"fmt"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
)

// suggestRoots logs a one-time hint when the closure was defeated by the image
// having no entrypoint to start from and the user named none with --roots. It
// changes no verdict -- it points at the flag that could change several.
func (p *Plugin) suggestRoots(g *elfgraph.Graph, findings []ecosystem.Finding) {
	if g == nil {
		return
	}
	for _, line := range rootsHint(g.Taints(), p.Roots, findings) {
		p.Logf("  %s", line)
	}
}

// rootsHint returns the advisory lines for suggestRoots, or nil when the
// situation does not call for one. It is pure so the decision can be exercised
// without building an image.
//
// The case it speaks to is the one the known limits call out: an image whose
// Cmd is a shell, or that declares no entrypoint at all, has every executable
// rooted, so almost everything comes back `linked` -- the honest answer for a
// general-purpose base image, but a wall of noise on a purpose-built one whose
// real entrypoint would close a precise graph. When the user has already named
// roots there is nothing to suggest; when the entrypoint taint was discharged
// (roots plus --exec-policy=assume-none) the closure is already precise; and
// when nothing came back `linked` the hint would point at a problem the scan
// does not have.
func rootsHint(taints []elfgraph.Taint, roots []string, findings []ecosystem.Finding) []string {
	if len(roots) > 0 {
		return nil
	}
	var cause string
	for _, t := range taints {
		if t.Discharged {
			continue
		}
		switch t.Kind {
		case elfgraph.TaintShellEntrypoint:
			cause = "its entrypoint is a shell, so every executable is treated as a root"
		case elfgraph.TaintNoEntrypoint:
			cause = "it declares no usable entrypoint, so every executable is treated as a root"
		}
		if cause != "" {
			break
		}
	}
	if cause == "" {
		return nil
	}
	linked := 0
	for _, f := range findings {
		if f.Status == ecosystem.StatusLinked {
			linked++
		}
	}
	if linked == 0 {
		return nil
	}
	return []string{
		fmt.Sprintf("hint: %d OS finding(s) are reported %q because %s", linked, ecosystem.StatusLinked, cause),
		"      if this image has a real entrypoint, name it with --roots <path> (and --exec-policy=assume-none) so the closure can rule more out",
	}
}
