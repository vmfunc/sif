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
	"net/http"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/modules"
	"github.com/vmfunc/sif/internal/scan/frameworks"
)

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
	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		return nil, err
	}
	// every CDN signature is HeaderOnly, so the body is never inspected; drain
	// and close it (no per-target body allocation) and detect on headers alone.
	defer httpx.DrainClose(resp)

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: []modules.Finding{},
	}

	cdn := frameworks.DetectCDN("", resp.Header)
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
