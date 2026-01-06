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
)

type PortsModule struct {
	Scope string // "common" or "full"
}

func (m *PortsModule) Info() modules.Info {
	name := fmt.Sprintf("Port Scanner (%s)", m.Scope)
	desc := fmt.Sprintf("TCP port scanning with %s scope", m.Scope)
	id := fmt.Sprintf("port-scan-%s", m.Scope)

	return modules.Info{
		ID:          id,
		Name:        name,
		Author:      "sif",
		Severity:    "info",
		Description: desc,
		Tags:        []string{"recon", "ports", "tcp", m.Scope},
	}
}

func (m *PortsModule) Type() modules.ModuleType {
	return modules.TypeTCP
}

func (m *PortsModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	// Call existing legacy scan.Ports function
	openPorts, err := scan.Ports(m.Scope, target, opts.Timeout, opts.Threads, opts.LogDir)

	if err != nil {
		return nil, err
	}

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: make([]modules.Finding, 0, len(openPorts)),
	}

	// Create a finding for each open port
	for _, port := range openPorts {
		result.Findings = append(result.Findings, modules.Finding{
			URL:      fmt.Sprintf("%s:%s", target, port),
			Severity: "info",
			Evidence: fmt.Sprintf("Port %s is open [tcp]", port),
		})
	}

	return result, nil
}
