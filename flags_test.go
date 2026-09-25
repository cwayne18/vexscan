package main

import "testing"

// The entrypoint override says which program a container is actually started
// with, and the graph roots that program instead of the one the image config
// declares. Everything in this file is about the two distinctions that decision
// rests on: whether the flag was given at all, and where one argv token ends.

// TestArgvFlagKeepsUnsetAndEmptyApart is the distinction the whole override
// turns on. Nil leaves the image's own half of the command line running; empty
// replaces it with nothing. A flag type that collapsed them would read `--cmd=`
// as "no opinion" and keep running arguments the user said were gone.
func TestArgvFlagKeepsUnsetAndEmptyApart(t *testing.T) {
	var unset argvFlag
	if got := unset.value(); got != nil {
		t.Errorf("a flag never given = %#v, want nil so the image's own is kept", got)
	}

	var empty argvFlag
	if err := empty.Set(""); err != nil {
		t.Fatal(err)
	}
	got := empty.value()
	if got == nil {
		t.Fatal("--cmd= read as though the flag were never given, so the image's arguments still run")
	}
	if len(got) != 0 {
		t.Errorf("--cmd= produced the argv %#v, want an empty command line", got)
	}
}

// TestArgvFlagDoesNotSplitOnCommas is why this is not a stringList. A path
// cannot contain a comma and an argument routinely can, so the rule that is
// right for --roots would cut one argument into two here -- and argv[0] of the
// wreckage is what the closure gets rooted at.
func TestArgvFlagDoesNotSplitOnCommas(t *testing.T) {
	var a argvFlag
	if err := a.Set("--listen=1.2.3.4,5.6.7.8"); err != nil {
		t.Fatal(err)
	}
	if got := a.value(); len(got) != 1 || got[0] != "--listen=1.2.3.4,5.6.7.8" {
		t.Errorf("value = %#v, want one token", got)
	}
}

// TestArgvFlagKeepsTokenOrder. A command line is ordered, and the order is what
// decides which token a wrapper entrypoint forwards to: `tini -- server` and
// `server -- tini` name different programs.
func TestArgvFlagKeepsTokenOrder(t *testing.T) {
	var a argvFlag
	for _, tok := range []string{"/usr/bin/tini", "--", "/usr/bin/server"} {
		if err := a.Set(tok); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"/usr/bin/tini", "--", "/usr/bin/server"}
	got := a.value()
	if len(got) != len(want) {
		t.Fatalf("value = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("value = %#v, want %#v", got, want)
		}
	}
}

// TestFlagSourceNamesTheFlagsGiven. The source is the clause a reviewer is meant
// to disagree with, so it has to name the argument they would go and look at --
// and it has to be empty when no claim was made, or every run that asserted
// nothing grows a sentence about an override.
func TestFlagSourceNamesTheFlagsGiven(t *testing.T) {
	for _, tc := range []struct {
		name            string
		entrypoint, cmd bool
		want            string
	}{
		{"neither", false, false, ""},
		{"entrypoint alone", true, false, "--entrypoint"},
		{"cmd alone", false, true, "--cmd"},
		{"both", true, true, "--entrypoint and --cmd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := flagSource(tc.entrypoint, tc.cmd); got != tc.want {
				t.Errorf("flagSource = %q, want %q", got, tc.want)
			}
		})
	}
}
