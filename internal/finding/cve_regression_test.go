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

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// a cve-enriched framework result must still collapse to the frozen
// "[severity] target module title" line - version, cves and references stay
// out of Line() even once cve enrichment is populated, so downstream
// notify/grep/awk consumers never see the line shape shift under them.
func TestFlattenFramework_LineFrozenWithCVEEnrichment(t *testing.T) {
	fw := &frameworks.FrameworkResult{
		Name:        "Drupal",
		Version:     "10",
		Confidence:  0.9,
		CVEs:        []string{"CVE-2023-44487 (high)"},
		Suggestions: []string{"Update to Drupal 10.1.4 or later"},
		RiskLevel:   "high",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-44487"},
	}

	findings := Flatten(target, "framework", fw)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	want := fmt.Sprintf("[%s] %s %s %s", f.Severity, target, "framework", "Drupal detected")
	if got := f.Line(); got != want {
		t.Errorf("Line() = %q, want %q", got, want)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %v, want %v (from RiskLevel=high)", f.Severity, SeverityHigh)
	}
	for _, leak := range []string{"CVE-2023-44487", "nvd.nist.gov"} {
		if strings.Contains(f.Line(), leak) {
			t.Errorf("Line() leaked enrichment detail %q: %q", leak, f.Line())
		}
	}
}
