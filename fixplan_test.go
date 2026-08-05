package main

import (
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/analyze"
	"github.com/cwayne18/vexscan/internal/ecosystem"
)

// fixplan renders a fix plan from a set of findings, telling the renderer which
// analyzer produced which OSV ecosystems so the Debian-only collapse logic has
// something to dispatch on.
func fixplan(t *testing.T, ecosystems map[string][]string, findings ...analyze.Finding) string {
	t.Helper()
	var ecos []ecosystem.EcosystemResult
	for id, names := range ecosystems {
		ecos = append(ecos, ecosystem.EcosystemResult{ID: id, Ecosystems: names, Components: 1})
	}
	return renderFixPlan(&analyze.Result{
		SchemaVersion: analyze.SchemaVersion,
		Target:        "debian:12",
		Mode:          "image",
		Ecosystems:    ecos,
		Findings:      findings,
	})
}

func linked(cve, pkg, version, fixed, severity string) analyze.Finding {
	return analyze.Finding{
		Ecosystem: "os", CVE: cve, ID: cve,
		Package: pkg, Module: pkg, Version: version,
		FixedVersion: fixed,
		Status:       analyze.StatusLinked,
		Method:       "elf-needed-closure",
		Severity:     severity,
	}
}

// TestFixPlanCollapsesToNewestFix is the reason debver exists: a package with
// several advisories fixed in different point releases must appear once, with
// the newest of those versions as the target, because installing it clears them
// all.
func TestFixPlanCollapsesToNewestFix(t *testing.T) {
	out := fixplan(t, map[string][]string{"os": {"Debian:12"}},
		linked("CVE-2023-0001", "libc6", "2.36-9+deb12u1", "2.36-9+deb12u3", "HIGH"),
		linked("CVE-2023-0002", "libc6", "2.36-9+deb12u1", "2.36-9+deb12u14", "HIGH"),
		linked("CVE-2023-0003", "libc6", "2.36-9+deb12u1", "2.36-9+deb12u7", "MEDIUM"),
	)
	rows := sectionOf(t, out, "UPGRADE")
	// One data row under the header.
	data := 0
	for _, l := range rows {
		if strings.Contains(l, "libc6") {
			data++
		}
	}
	if data != 1 {
		t.Fatalf("want libc6 collapsed to one row, got %d:\n%s", data, out)
	}
	line := lineWith(t, out, "libc6")
	if !strings.Contains(line, "2.36-9+deb12u14") {
		t.Errorf("want newest fix 2.36-9+deb12u14 as target, got:\n%s", line)
	}
	if !strings.Contains(line, " 3 ") {
		t.Errorf("want CLEARS 3, got:\n%s", line)
	}
}

// TestFixPlanSeparatesNoFix keeps the plan honest: a finding no patch clears is
// not dropped, it moves to its own section so the reader sees what the upgrades
// leave behind.
func TestFixPlanSeparatesNoFix(t *testing.T) {
	out := fixplan(t, map[string][]string{"os": {"Debian:12"}},
		linked("CVE-2023-0001", "libc6", "2.36-9+deb12u1", "2.36-9+deb12u3", "HIGH"),
		linked("CVE-2023-9999", "zlib1g", "1.2.13", "", "UNKNOWN"),
	)
	if u := sectionOf(t, out, "UPGRADE"); !containsRow(u, "libc6") || containsRow(u, "zlib1g") {
		t.Errorf("UPGRADE should hold libc6 only:\n%s", out)
	}
	if n := sectionOf(t, out, "NO FIX YET"); !containsRow(n, "zlib1g") || containsRow(n, "libc6") {
		t.Errorf("NO FIX YET should hold zlib1g only:\n%s", out)
	}
	lineWith(t, out, "1 of 2 affected findings have a fix.")
	lineWith(t, out, "upgrading 1 package clears 1 advisory; 1 with no fix yet.")
}

// TestFixPlanDoesNotCollapseUnorderableEcosystem is the safety rule: where the
// tool cannot prove a version order, it does not guess one. Two npm fixes stay
// two rows rather than risk naming the wrong target as "newest".
func TestFixPlanDoesNotCollapseUnorderableEcosystem(t *testing.T) {
	a := analyze.Finding{
		Ecosystem: "npm", CVE: "CVE-2023-0001", ID: "CVE-2023-0001",
		Package: "lodash", Module: "lodash", Version: "4.17.20",
		FixedVersion: "4.17.21", Status: analyze.StatusReachable, Method: "call-reachable", Severity: "HIGH",
	}
	b := a
	b.CVE, b.ID, b.FixedVersion = "CVE-2023-0002", "CVE-2023-0002", "4.17.19"
	out := fixplan(t, map[string][]string{"npm": {"npm"}}, a, b)
	rows := sectionOf(t, out, "UPGRADE")
	data := 0
	for _, l := range rows {
		if strings.Contains(l, "lodash") {
			data++
		}
	}
	if data != 2 {
		t.Fatalf("want two un-collapsed lodash rows, got %d:\n%s", data, out)
	}
}

// TestFixPlanNothingFixable still renders honestly rather than an empty page.
func TestFixPlanNothingFixable(t *testing.T) {
	out := fixplan(t, map[string][]string{"os": {"Debian:12"}},
		linked("CVE-2023-9999", "zlib1g", "1.2.13", "", "UNKNOWN"),
	)
	lineWith(t, out, "no published fixes yet for any of the 1 affected findings.")
	if strings.Contains(out, "UPGRADE (") {
		t.Errorf("no UPGRADE section expected when nothing is fixable:\n%s", out)
	}
}

func containsRow(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}
