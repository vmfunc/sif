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

package modules

import (
	"strings"
	"testing"
)

func TestDSLCompile(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"valid comparison", "status_code == 200", false},
		{"valid helper", `contains(body, "admin")`, false},
		{"bad syntax", "status_code ==", true},
		{"non-allowlisted side-effect helper", "wait_for(1)", true},
		{"non-allowlisted network helper", "public_ip()", true},
		{"non-allowlisted alloc helper", `repeat("A", 1000000)`, true},
		{"over-length expression", strings.Repeat("a", maxDSLExprLen+1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dslCompile(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("dslCompile(%q) err = %v, wantErr %v", tt.expr, err, tt.wantErr)
			}
		})
	}
}
