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

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"  high  ", SeverityHigh},
		{"medium", SeverityMedium},
		{"moderate", SeverityMedium},
		{"warning", SeverityMedium},
		{"low", SeverityLow},
		{"info", SeverityInfo},
		{"informational", SeverityInfo},
		{"none", SeverityInfo},
		{"", SeverityUnknown},
		{"bogus", SeverityUnknown},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.in); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	// the ladder must be strictly increasing for AtLeast/sort to behave.
	ordered := []Severity{
		SeverityUnknown, SeverityInfo, SeverityLow,
		SeverityMedium, SeverityHigh, SeverityCritical,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Errorf("severity ladder not increasing at %d: %v !< %v", i, ordered[i-1], ordered[i])
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		sev       Severity
		threshold Severity
		want      bool
	}{
		{SeverityHigh, SeverityMedium, true},
		{SeverityMedium, SeverityMedium, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityCritical, SeverityInfo, true},
		{SeverityUnknown, SeverityInfo, false},
	}
	for _, tt := range tests {
		if got := tt.sev.AtLeast(tt.threshold); got != tt.want {
			t.Errorf("%v.AtLeast(%v) = %v, want %v", tt.sev, tt.threshold, got, tt.want)
		}
	}
}

func TestSeverityStringRoundTrip(t *testing.T) {
	// every named rank renders to a string ParseSeverity maps back to the same
	// rank, so the wire format is lossless for known severities.
	for _, sev := range []Severity{
		SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
	} {
		if got := ParseSeverity(sev.String()); got != sev {
			t.Errorf("round-trip %v -> %q -> %v", sev, sev.String(), got)
		}
	}
}
