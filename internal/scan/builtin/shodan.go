/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package builtin

import (
	"context"
	"fmt"
	"github.com/dropalldatabases/sif/internal/modules"
	"github.com/dropalldatabases/sif/internal/scan"
	"strings"
)

type ShodanModule struct{}

func (m *ShodanModule) Info() modules.Info {
	return modules.Info{
		ID:          "shodan-lookup",
		Name:        "Shodan Host Intelligence",
		Author:      "sif",
		Severity:    "info",
		Description: "Queries Shodan API for host information, open ports, and vulnerabilities (requires SHODAN_API_KEY)",
		Tags:        []string{"recon", "osint", "shodan", "infrastructure", "vulns"},
	}
}

func (m *ShodanModule) Type() modules.ModuleType {
	return modules.TypeScript
}

func (m *ShodanModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	// Call existing legacy scan.Shodan function
	shodanResult, err := scan.Shodan(target, opts.Timeout, opts.LogDir)

	if err != nil {
		return nil, err
	}

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: []modules.Finding{},
	}

	// If nothing returned, return empty result
	if shodanResult == nil || shodanResult.IP == "" {
		return result, nil
	}

	// Create main finding
	evidence := fmt.Sprintf("Shodan data found for %s", shodanResult.IP)

	severity := "info"
	if len(shodanResult.Vulns) > 0 {
		severity = "high"
		evidence = fmt.Sprintf("Host %s has %d known vulnerabilities", shodanResult.IP, len(shodanResult.Vulns))
	}

	finding := modules.Finding{
		URL:      target,
		Severity: severity,
		Evidence: evidence,
		Extracted: map[string]string{
			"ip": shodanResult.IP,
		},
	}

	// Add hostnames
	if len(shodanResult.Hostnames) > 0 {
		finding.Extracted["hostnames"] = strings.Join(shodanResult.Hostnames, ", ")
	}

	// Add organization info
	if shodanResult.Organization != "" {
		finding.Extracted["organization"] = shodanResult.Organization
	}

	// Add ISP info
	if shodanResult.ISP != "" {
		finding.Extracted["isp"] = shodanResult.ISP
	}

	// Add ASN
	if shodanResult.ASN != "" {
		finding.Extracted["asn"] = shodanResult.ASN
	}

	// Add location
	if shodanResult.Country != "" {
		location := shodanResult.Country
		if shodanResult.City != "" {
			location = shodanResult.City + ", " + shodanResult.Country
		}

		finding.Extracted["location"] = location
	}

	// Add OS
	if shodanResult.OS != "" {
		finding.Extracted["os"] = shodanResult.OS
	}

	// Add open ports
	if len(shodanResult.Ports) > 0 {
		portStrs := make([]string, len(shodanResult.Ports))
		for i, port := range shodanResult.Ports {
			portStrs[i] = fmt.Sprintf("%d", port)
		}

		finding.Extracted["open_ports"] = strings.Join(portStrs, ", ")
		finding.Extracted["port_count"] = fmt.Sprintf("%d", len(shodanResult.Ports))
	}

	// Add vulnerabilities
	if len(shodanResult.Vulns) > 0 {
		finding.Extracted["vulnerabilities"] = strings.Join(shodanResult.Vulns, ", ")
		finding.Extracted["vuln_count"] = fmt.Sprintf("%d", len(shodanResult.Vulns))
	}

	// Add last update
	if shodanResult.LastUpdate != "" {
		finding.Extracted["last_update"] = shodanResult.LastUpdate
	}

	// Add service count
	if len(shodanResult.Services) > 0 {
		finding.Extracted["service_count"] = fmt.Sprintf("%d", len(shodanResult.Services))

		// Add service details
		serviceDetails := make([]string, 0, len(shodanResult.Services))
		for _, service := range shodanResult.Services {
			detail := fmt.Sprintf("%d/%s", service.Port, service.Protocol)
			if service.Product != "" {
				detail += " " + service.Product

				if service.Version != "" {
					detail += " " + service.Version
				}
			}
			serviceDetails = append(serviceDetails, detail)
		}
		finding.Extracted["services"] = strings.Join(serviceDetails, "; ")
	}

	result.Findings = append(result.Findings, finding)

	return result, nil
}
