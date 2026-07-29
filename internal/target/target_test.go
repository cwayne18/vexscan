package target

import (
	"reflect"
	"testing"
)

func TestImageConfigArgv(t *testing.T) {
	tests := []struct {
		name       string
		entrypoint []string
		cmd        []string
		want       []string
	}{
		{"entrypoint plus cmd", []string{"/app"}, []string{"--serve"}, []string{"/app", "--serve"}},
		{"cmd only", nil, []string{"/bin/sh", "-c", "x"}, []string{"/bin/sh", "-c", "x"}},
		{"entrypoint only", []string{"/app"}, nil, []string{"/app"}},
		{"neither", nil, nil, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ImageConfig{Entrypoint: tt.entrypoint, Cmd: tt.cmd}
			if got := c.Argv(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Argv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImageConfigLookupEnv(t *testing.T) {
	c := ImageConfig{Env: []string{"A=1", "B=", "A=2", "malformed"}}

	tests := []struct {
		key      string
		want     string
		wantOK   bool
		whyMatch string
	}{
		{"A", "2", true, "later entries win, as when a runtime builds the environment"},
		{"B", "", true, "an explicitly empty value is set, not absent"},
		{"malformed", "", false, "an entry with no = is not a variable"},
		{"C", "", false, ""},
	}
	for _, tt := range tests {
		got, ok := c.LookupEnv(tt.key)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("LookupEnv(%q) = (%q, %v), want (%q, %v) %s",
				tt.key, got, ok, tt.want, tt.wantOK, tt.whyMatch)
		}
	}
}

func TestImageConfigPathDirs(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		want []string
	}{
		{
			"from config",
			[]string{"PATH=/opt/bin:/usr/bin"},
			[]string{"/opt/bin", "/usr/bin"},
		},
		{
			// Distroless and scratch images often set no PATH at all; a bare
			// argv[0] still has to resolve somewhere.
			"unset falls back to the runtime default",
			nil,
			[]string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"},
		},
		{
			"empty falls back too",
			[]string{"PATH="},
			[]string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"},
		},
		{
			"empty and relative entries are dropped or made absolute",
			[]string{"PATH=/usr/bin::bin/:/usr/bin/"},
			[]string{"/usr/bin", "/bin", "/usr/bin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImageConfig{Env: tt.env}.PathDirs()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PathDirs() = %v, want %v", got, tt.want)
			}
		})
	}
}
