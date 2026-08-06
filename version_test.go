package main

import "testing"

// The whole point of the shim: one token, two meanings, told apart by whether
// a value came with it.
func TestVersionFlagTellsTheTwoMeaningsApart(t *testing.T) {
	cases := []struct {
		name     string
		set      string
		print    bool
		override string
	}{
		{"bare --version", "true", true, ""},
		{"the deprecated override", "1.2.3", false, "1.2.3"},
		{"a v-prefixed override", "v1.2.3", false, "v1.2.3"},
		{"an override that is not a version at all", "(devel)", false, "(devel)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v versionFlag
			if err := v.Set(tc.set); err != nil {
				t.Fatalf("Set(%q) = %v", tc.set, err)
			}
			if v.print != tc.print || v.override != tc.override {
				t.Errorf("Set(%q) -> print=%v override=%q, want print=%v override=%q",
					tc.set, v.print, v.override, tc.print, tc.override)
			}
		})
	}
}

// IsBoolFlag is load-bearing, not decoration: without it the flag package
// consumes the next argument and a bare --version fails the way it does today.
func TestVersionFlagIsABoolFlag(t *testing.T) {
	var v versionFlag
	if !v.IsBoolFlag() {
		t.Error("IsBoolFlag() = false; a bare --version would consume the next argument")
	}
}

func TestLooksLikeVersion(t *testing.T) {
	yes := []string{"1", "1.2.3", "v1.2.3", "0.0.1-rc1", "v0"}
	no := []string{"", "debian:12", "--all", "v", "stray", "golang:stdlib"}
	for _, s := range yes {
		if !looksLikeVersion(s) {
			t.Errorf("looksLikeVersion(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeVersion(s) {
			t.Errorf("looksLikeVersion(%q) = true, want false", s)
		}
	}
}
