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

// the detector usually reports "unknown"; the version dug out of the body must
// win so the cve lookup runs against a concrete version instead of "unknown".
func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name      string
		detector  string
		extracted string
		want      string
	}{
		{"detector concrete wins", "9.0.0", "8.4.1", "9.0.0"},
		{"unknown detector falls back to extracted", "unknown", "8.4.1", "8.4.1"},
		{"empty detector falls back to extracted", "", "8.4.1", "8.4.1"},
		{"both unknown stays unknown", "unknown", "unknown", "unknown"},
		{"both empty/unknown stays unknown", "", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.detector, tt.extracted); got != tt.want {
				t.Errorf("resolveVersion(%q, %q) = %q, want %q", tt.detector, tt.extracted, got, tt.want)
			}
		})
	}
}

// the regression itself: with the detector reporting "unknown" but a real
// version extractable from the body, the cve lookup must use the extracted
// version and surface the matching CVE - the old path looked up "unknown" and
// missed it.
func TestResolveVersionFeedsCVELookup(t *testing.T) {
	const body = "Laravel 8.4.1"

	// extractor pulls the concrete version out of the body...
	extracted := ExtractVersionOptimized(body, "Laravel").Version
	if extracted != "8.4.1" {
		t.Fatalf("expected extracted version 8.4.1, got %q", extracted)
	}

	// ...and looking "unknown" up finds nothing, proving the old behavior missed it.
	if cves, _ := getVulnerabilities("Laravel", "unknown"); len(cves) != 0 {
		t.Fatalf("expected no CVEs for unknown version, got %v", cves)
	}

	// the reconciled version feeds the lookup and the CVE shows up.
	version := resolveVersion("unknown", extracted)
	cves, _ := getVulnerabilities("Laravel", version)
	if len(cves) == 0 {
		t.Errorf("expected Laravel %s to surface a CVE, got none", version)
	}
}

func TestVersionAffected(t *testing.T) {
	tests := []struct {
		version  string
		affected string
		want     bool
	}{
		{"4.2", "4.2", true},
		{"4.2.1", "4.2", true},
		{"4.2.13", "4.2", true},
		{"4.20", "4.2", false}, // the boundary bug: 4.20 is not a 4.2.x release
		{"4.20.0", "4.2", false},
		{"5.0", "4.2", false},
	}

	for _, tt := range tests {
		if got := versionAffected(tt.version, tt.affected); got != tt.want {
			t.Errorf("versionAffected(%q, %q) = %v, want %v", tt.version, tt.affected, got, tt.want)
		}
	}
}
