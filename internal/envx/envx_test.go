package envx

import "testing"

func TestGet(t *testing.T) {
	tests := []struct {
		name    string
		vexscan string // "" means leave unset
		legacy  string
		want    string
	}{
		{name: "neither set", want: ""},
		{name: "new name only", vexscan: "5s", want: "5s"},
		{name: "legacy name only", legacy: "7s", want: "7s"},
		{name: "new name wins over legacy", vexscan: "5s", legacy: "7s", want: "5s"},
		{name: "whitespace trimmed", vexscan: "  5s\n", want: "5s"},
		// A variable set to whitespace only is treated as unset, so it falls
		// through to the legacy name rather than masking it with "".
		{name: "blank new name falls through", vexscan: "   ", legacy: "7s", want: "7s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.vexscan != "" {
				t.Setenv("VEXSCAN_TEST_VAR", tt.vexscan)
			}
			if tt.legacy != "" {
				t.Setenv("GOMODVEX_TEST_VAR", tt.legacy)
			}
			if got := Get("TEST_VAR"); got != tt.want {
				t.Errorf("Get(TEST_VAR) = %q, want %q", got, tt.want)
			}
		})
	}
}
