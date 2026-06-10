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

package finding

import "testing"

// Line is the -silent wire format; its shape is frozen, so pin it.
func TestFindingLine(t *testing.T) {
	tests := []struct {
		name string
		f    Finding
		want string
	}{
		{
			name: "high severity",
			f:    Finding{Target: "https://x.com", Module: "sql", Severity: SeverityHigh, Title: "admin panel"},
			want: "[high] https://x.com sql admin panel",
		},
		{
			name: "info recon",
			f:    Finding{Target: "https://y.com", Module: "headers", Severity: SeverityInfo, Title: "Server"},
			want: "[info] https://y.com headers Server",
		},
		{
			name: "unknown severity",
			f:    Finding{Target: "z.com", Module: "mystery", Severity: SeverityUnknown, Title: "?"},
			want: "[unknown] z.com mystery ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Line(); got != tt.want {
				t.Errorf("Line() = %q, want %q", got, tt.want)
			}
		})
	}
}
