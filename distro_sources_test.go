package main

import "testing"

// handles reports whether any resolved feed provider speaks for the given
// os-release ID. It is the observable behaviour that matters: a SUSE image must
// find a provider that Handles it by default, a Debian image must not until
// --distro-feeds is passed, and --distro-feeds=false must leave neither with one.
func handles(t *testing.T, feedsOn, suseByDefault bool, osID string) bool {
	t.Helper()
	feeds, _ := distroSources(feedsOn, suseByDefault, nil)
	for _, p := range feeds {
		if p.Handles(osID) {
			return true
		}
	}
	return false
}

// The default run: SUSE's feed is consulted for a SUSE image and Debian's is
// not, because SUSE is safe to run unasked and Debian is still opt-in.
func TestDistroSourcesSUSEOnByDefault(t *testing.T) {
	if !handles(t, false, true, "sles") {
		t.Error("a default run has no feed for a SUSE image; SUSE's CSAF-VEX should be on by default")
	}
	if handles(t, false, true, "debian") {
		t.Error("a default run consults Debian's tracker; it should stay behind --distro-feeds")
	}
}

// --distro-feeds turns on the opt-in feeds without disturbing the default one.
func TestDistroSourcesFlagAddsDebianKeepsSUSE(t *testing.T) {
	if !handles(t, true, true, "debian") {
		t.Error("--distro-feeds did not turn on Debian's tracker")
	}
	if !handles(t, true, true, "sles") {
		t.Error("--distro-feeds dropped SUSE's feed; it should still run")
	}
}

// --distro-feeds=false (feedsOn=false, suseByDefault=false) silences every feed,
// which is the air-gapped escape hatch.
func TestDistroSourcesExplicitOffSilencesAll(t *testing.T) {
	feeds, _ := distroSources(false, false, nil)
	if len(feeds) != 0 {
		t.Errorf("--distro-feeds=false left %d feed(s) enabled; want none", len(feeds))
	}
}
