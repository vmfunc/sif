/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package builtin

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/modules"
	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// cdnMaxBodySize caps the response body read, mirroring frameworks.maxBodySize.
const cdnMaxBodySize = 5 * 1024 * 1024

type CDNModule struct{}

func (m *CDNModule) Info() modules.Info {
	return modules.Info{
		ID:          "cdn-detection",
		Name:        "CDN/Hosting Provider Detection",
		Author:      "sif",
		Severity:    "info",
		Description: "Fingerprints the cdn/edge/hosting provider fronting a target from response headers",
		Tags:        []string{"recon", "cdn", "hosting", "fingerprint"},
	}
}

func (m *CDNModule) Type() modules.ModuleType {
	return modules.TypeHTTP
}

// Execute fetches the target and runs the CDN detector pool over the response,
// independent of framework detection (see cdnRegistry in
// internal/scan/frameworks/cdn.go).
func (m *CDNModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	client := opts.Client
	if client == nil {
		client = httpx.Client(opts.Timeout)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, cdnMaxBodySize))
	if err != nil {
		return nil, err
	}

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: []modules.Finding{},
	}

	cdn := frameworks.DetectCDN(string(body), resp.Header)
	if cdn == nil {
		return result, nil
	}

	result.Findings = append(result.Findings, modules.Finding{
		URL:      target,
		Severity: "info",
		Evidence: fmt.Sprintf("Fronted by %s (confidence: %.2f)", cdn.Name, cdn.Confidence),
		Extracted: map[string]string{
			"cdn":        cdn.Name,
			"confidence": fmt.Sprintf("%.2f", cdn.Confidence),
		},
	})

	return result, nil
}
