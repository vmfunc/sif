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

package frameworks

import "testing"

func TestVersionAffected(t *testing.T) {
	tests := []struct {
		version  string
		affected string
		want     bool
	}{
		{"4.2", "4.2", true},
		{"4.2.1", "4.2", true},
		{"4.2.13", "4.2", true},
		{"4.20", "4.2", false},   // the boundary bug: 4.20 is not a 4.2.x release
		{"4.20.0", "4.2", false},
		{"5.0", "4.2", false},
	}

	for _, tt := range tests {
		if got := versionAffected(tt.version, tt.affected); got != tt.want {
			t.Errorf("versionAffected(%q, %q) = %v, want %v", tt.version, tt.affected, got, tt.want)
		}
	}
}
