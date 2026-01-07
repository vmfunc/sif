/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package builtin

import (
	"context"
	"github.com/dropalldatabases/sif/internal/modules"
	"github.com/dropalldatabases/sif/internal/scan"
)

type WhoisModule struct{}

func (m *WhoisModule) Info() modules.Info {
	return modules.Info{
		ID:          "whois-lookup",
		Name:        "WHOIS Domain Information",
		Author:      "sif",
		Severity:    "info",
		Description: "Performs WHOIS lookup for domain registration information",
		Tags:        []string{"recon", "whois", "osint"},
	}
}

func (m *WhoisModule) Type() modules.ModuleType {
	return modules.TypeScript
}

func (m *WhoisModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	// Call existing legacy scan.Whois function
	scan.Whois(target, opts.LogDir)

	// Return that scan was executed, since no data is returned from scan.Whois
	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: []modules.Finding{
			{
				URL:      target,
				Severity: "info",
				Evidence: "WHOIS lookup completed",
			},
		},
	}

	return result, nil
}
