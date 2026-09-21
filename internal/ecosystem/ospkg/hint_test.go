package ospkg

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/ecosystem"
	"github.com/cwayne18/vexscan/internal/elfgraph"
)

func TestRootsHintFiresOnShellEntrypointWithLinkedFindings(t *testing.T) {
	taints := []elfgraph.Taint{{Kind: elfgraph.TaintShellEntrypoint}}
	findings := []ecosystem.Finding{
		{Status: ecosystem.StatusLinked},
		{Status: ecosystem.StatusNotPresent},
		{Status: ecosystem.StatusLinked},
	}
	lines := rootsHint(taints, nil, findings)
	if len(lines) == 0 {
		t.Fatal("expected a hint, got none")
	}
	if !strings.Contains(lines[0], "2 OS finding") || !strings.Contains(lines[0], "shell") {
		t.Errorf("hint does not name the count and cause: %q", lines[0])
	}
	if !strings.Contains(lines[1], "--roots") {
		t.Errorf("hint does not point at --roots: %q", lines[1])
	}
}

func TestRootsHintFiresOnNoEntrypoint(t *testing.T) {
	taints := []elfgraph.Taint{{Kind: elfgraph.TaintNoEntrypoint}}
	findings := []ecosystem.Finding{{Status: ecosystem.StatusLinked}}
	if lines := rootsHint(taints, nil, findings); len(lines) == 0 {
		t.Fatal("expected a hint for a no-entrypoint image, got none")
	}
}

func TestRootsHintSilentWhenRootsGiven(t *testing.T) {
	taints := []elfgraph.Taint{{Kind: elfgraph.TaintShellEntrypoint}}
	findings := []ecosystem.Finding{{Status: ecosystem.StatusLinked}}
	if lines := rootsHint(taints, []string{"/app/server"}, findings); lines != nil {
		t.Errorf("expected no hint when --roots already names an entrypoint, got %v", lines)
	}
}

func TestRootsHintSilentWhenTaintDischarged(t *testing.T) {
	taints := []elfgraph.Taint{{Kind: elfgraph.TaintShellEntrypoint, Discharged: true}}
	findings := []ecosystem.Finding{{Status: ecosystem.StatusLinked}}
	if lines := rootsHint(taints, nil, findings); lines != nil {
		t.Errorf("expected no hint once the entrypoint taint is discharged, got %v", lines)
	}
}

func TestRootsHintSilentWhenNothingLinked(t *testing.T) {
	taints := []elfgraph.Taint{{Kind: elfgraph.TaintShellEntrypoint}}
	findings := []ecosystem.Finding{{Status: ecosystem.StatusNotPresent}}
	if lines := rootsHint(taints, nil, findings); lines != nil {
		t.Errorf("expected no hint when no finding came back linked, got %v", lines)
	}
}

func TestRootsHintSilentWithoutEntrypointTaint(t *testing.T) {
	taints := []elfgraph.Taint{{Kind: elfgraph.TaintStaticELF}}
	findings := []ecosystem.Finding{{Status: ecosystem.StatusLinked}}
	if lines := rootsHint(taints, nil, findings); lines != nil {
		t.Errorf("expected no hint absent an entrypoint taint, got %v", lines)
	}
}
