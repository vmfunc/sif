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

package builtin

import (
	"context"
	"fmt"
	"github.com/dropalldatabases/sif/internal/modules"
	"github.com/dropalldatabases/sif/internal/scan/frameworks"
	"strings"
)

type FrameworksModule struct{}

func (m *FrameworksModule) Info() modules.Info {
	return modules.Info{
		ID:          "framework-detection",
		Name:        "Web Framework Detection",
		Author:      "sif",
		Severity:    "info",
		Description: "Detects web frameworks with version and CVE mapping",
		Tags:        []string{"recon", "framework", "cve"},
	}
}

func (m *FrameworksModule) Type() modules.ModuleType {
	return modules.TypeHTTP
}

func (m *FrameworksModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	// Call existing legacy frameworks.DetectFramework function
	frameworkResult, err := frameworks.DetectFramework(target, opts.Timeout, opts.LogDir)

	if err != nil {
		return nil, err
	}

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: []modules.Finding{},
	}

	// Return empty if no framework detected
	if frameworkResult == nil {
		return result, nil
	}

	// Construct finding
	evidence := fmt.Sprintf("Detected %s framework (version: %s, confidence: %.2f)",
		frameworkResult.Name, frameworkResult.Version, frameworkResult.Confidence)

	severity := "info"
	if frameworkResult.RiskLevel != "" && frameworkResult.RiskLevel != "low" {
		severity = frameworkResult.RiskLevel
	}

	finding := modules.Finding{
		URL:      target,
		Severity: severity,
		Evidence: evidence,
		Extracted: map[string]string{
			"framework":          frameworkResult.Name,
			"version":            frameworkResult.Version,
			"confidence":         fmt.Sprintf("%.2f", frameworkResult.Confidence),
			"version_confidence": fmt.Sprintf("%.2f", frameworkResult.VersionConfidence),
		},
	}

	// Add CVE information
	if len(frameworkResult.CVEs) > 0 {
		finding.Extracted["cves"] = strings.Join(frameworkResult.CVEs, ", ")
		finding.Extracted["risk_level"] = frameworkResult.RiskLevel
	}

	// Add recommendations
	if len(frameworkResult.Suggestions) > 0 {
		finding.Extracted["recommendations"] = strings.Join(frameworkResult.Suggestions, "; ")
	}

	result.Findings = append(result.Findings, finding)

	return result, nil
}
