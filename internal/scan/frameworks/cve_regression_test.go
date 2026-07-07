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

// bare-major boundary matrix: a coarse detected major ("7") must cover its own
// dotted sub-versions but never a version that merely shares the same leading
// digits ("70.0", "17.0", "7000.0"). this is the off-by-one guard for the
// bare-major fix in versionAffected - it pins the exact boundary, not just one
// example of it.
func TestVersionAffected_BareMajorBoundary(t *testing.T) {
	tests := []struct {
		version  string
		affected string
		want     bool
	}{
		{"7", "7.0", true},
		{"7", "7.4", true},
		{"7", "7.9", true},
		{"7", "70.0", false},
		{"7", "17.0", false},
		{"7", "7000.0", false},
		{"7", "6.9", false},
		{"4.20", "4.2", false},
		{"4.1", "4.10", false},
		{"4.10", "4.1", false},
	}

	for _, tt := range tests {
		if got := versionAffected(tt.version, tt.affected); got != tt.want {
			t.Errorf("versionAffected(%q, %q) = %v, want %v", tt.version, tt.affected, got, tt.want)
		}
	}
}

// every CVE entry must carry at least one reference, and that reference must
// be exactly the NVD detail link derived from the entry's own CVE ID - no
// stale/typo'd/borrowed reference from a neighboring entry.
func TestKnownCVEs_ReferencesMatchOwnCVEID(t *testing.T) {
	for framework, entries := range knownCVEs {
		for _, entry := range entries {
			if len(entry.References) == 0 {
				t.Errorf("%s %s: no references", framework, entry.CVE)
				continue
			}
			want := "https://nvd.nist.gov/vuln/detail/" + entry.CVE
			for _, ref := range entry.References {
				if ref != want {
					t.Errorf("%s %s: reference %q, want %q", framework, entry.CVE, ref, want)
				}
			}
		}
	}
}
