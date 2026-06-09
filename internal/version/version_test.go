/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package version

import "testing"

func TestResolveLdflag(t *testing.T) {
	tests := []struct {
		name   string
		ldflag string
		want   string
	}{
		{"tag with v", "v2026.6.7", "2026.6.7"},
		{"tag without v", "2026.6.7", "2026.6.7"},
		{"pseudo version", "2026.2.17-57-geb33321", "2026.2.17-57-geb33321"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.ldflag); got != tt.want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.ldflag, got, tt.want)
			}
		})
	}
}

// with no ldflag, Resolve falls back to build info; in a test binary that's
// non-deterministic, so just assert it never returns an empty string.
func TestResolveFallbackNonEmpty(t *testing.T) {
	if Resolve("dev") == "" {
		t.Error("Resolve fallback should never be empty")
	}
}
