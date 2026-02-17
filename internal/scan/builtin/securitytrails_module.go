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
	"strings"

	"github.com/dropalldatabases/sif/internal/modules"
	"github.com/dropalldatabases/sif/internal/scan"
)

type SecurityTrailsModule struct{}

func (m *SecurityTrailsModule) Info() modules.Info {
	return modules.Info{
		ID:          "securitytrails-lookup",
		Name:        "SecurityTrails Domain Discovery",
		Author:      "sif",
		Severity:    "info",
		Description: "Queries SecurityTrails API for subdomains and associated domains (requires SECURITYTRAILS_API_KEY)",
		Tags:        []string{"recon", "osint", "dns", "subdomains"},
	}
}

func (m *SecurityTrailsModule) Type() modules.ModuleType {
	return modules.TypeScript
}

func (m *SecurityTrailsModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	stResult, err := scan.SecurityTrails(target, opts.Timeout, opts.LogDir)
	if err != nil {
		return nil, err
	}

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: []modules.Finding{},
	}

	if stResult == nil {
		return result, nil
	}

	finding := modules.Finding{
		URL:      target,
		Severity: "info",
		Evidence: fmt.Sprintf("discovered %d subdomains and %d associated domains",
			len(stResult.Subdomains), len(stResult.AssociatedDomains)),
		Extracted: map[string]string{
			"domain":           stResult.Domain,
			"subdomain_count":  fmt.Sprintf("%d", len(stResult.Subdomains)),
			"associated_count": fmt.Sprintf("%d", len(stResult.AssociatedDomains)),
		},
	}

	if len(stResult.Subdomains) > 0 {
		finding.Extracted["subdomains"] = strings.Join(stResult.Subdomains, ", ")
	}

	if len(stResult.AssociatedDomains) > 0 {
		finding.Extracted["associated_domains"] = strings.Join(stResult.AssociatedDomains, ", ")
	}

	result.Findings = append(result.Findings, finding)
	return result, nil
}
