package main

import "testing"

// TestVexPRActivation pins which flags may start a pull request.
//
// This is the one place vexscan writes to a repository it does not own, and the
// statements it publishes there are what make a vulnerability stop being
// reported for everyone downstream. --vexhub-pr-repo and --vex-author are
// modifiers of that action, not requests for it, so neither may imply it -- a
// --vex-author left behind from an earlier command line must be an error the
// user sees, not a pull request they did not ask for.
func TestVexPRActivation(t *testing.T) {
	cases := []struct {
		name             string
		pr, dry          bool
		pushRepo, author string
		wantOn, wantErr  bool
	}{
		{name: "nothing set", wantOn: false},
		{name: "explicit", pr: true, wantOn: true},
		{name: "dry run alone writes nothing, so it may imply", dry: true, wantOn: true},
		{name: "push repo alone", pushRepo: "me/hub-fork", wantErr: true},
		{name: "author alone", author: "Acme Security", wantErr: true},
		{name: "push repo with the flag", pr: true, pushRepo: "me/hub-fork", wantOn: true},
		{name: "author with the flag", pr: true, author: "Acme Security", wantOn: true},
		{name: "author with dry run", dry: true, author: "Acme Security", wantOn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			on, err := vexPRActivation(tc.pr, tc.dry, tc.pushRepo, tc.author)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if on != tc.wantOn {
				t.Errorf("on = %v, want %v", on, tc.wantOn)
			}
		})
	}
}
