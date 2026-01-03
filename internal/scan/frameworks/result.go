/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

/*

   BSD 3-Clause License
   (c) 2022-2025 vmfunc, xyzeva & contributors

*/

package frameworks

// FrameworkResult represents the result of framework detection.
type FrameworkResult struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Confidence        float32  `json:"confidence"`
	VersionConfidence float32  `json:"version_confidence"`
	CVEs              []string `json:"cves,omitempty"`
	Suggestions       []string `json:"suggestions,omitempty"`
	RiskLevel         string   `json:"risk_level,omitempty"`
}

// ResultType implements the ScanResult interface.
func (r *FrameworkResult) ResultType() string { return "framework" }

// NewFrameworkResult creates a new FrameworkResult with the given parameters.
func NewFrameworkResult(name, version string, confidence, versionConfidence float32) *FrameworkResult {
	return &FrameworkResult{
		Name:              name,
		Version:           version,
		Confidence:        confidence,
		VersionConfidence: versionConfidence,
	}
}

// WithVulnerabilities adds CVE information to the result.
func (r *FrameworkResult) WithVulnerabilities(cves, suggestions []string) *FrameworkResult {
	r.CVEs = cves
	r.Suggestions = suggestions
	r.RiskLevel = determineRiskLevel(cves)
	return r
}

// determineRiskLevel calculates the risk level based on CVE severities.
func determineRiskLevel(cves []string) string {
	if len(cves) == 0 {
		return "low"
	}

	for _, cve := range cves {
		if containsSeverity(cve, "critical") {
			return "critical"
		}
	}

	for _, cve := range cves {
		if containsSeverity(cve, "high") {
			return "high"
		}
	}

	return "medium"
}

func containsSeverity(cve, severity string) bool {
	// Simple substring match for now - could be more sophisticated
	for i := 0; i+len(severity) <= len(cve); i++ {
		match := true
		for j := 0; j < len(severity); j++ {
			c := cve[i+j]
			// Case-insensitive comparison
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != severity[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
