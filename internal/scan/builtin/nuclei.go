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

type NucleiModule struct{}

func (m *NucleiModule) Info() modules.Info {
	return modules.Info{
		ID:          "nuclei-scan",
		Name:        "Nuclei Vulnerability Scanner",
		Author:      "sif",
		Severity:    "high",
		Description: "Runs Nuclei vulnerability scanning templates against target",
		Tags:        []string{"vuln", "nuclei", "cve"},
	}
}

func (m *NucleiModule) Type() modules.ModuleType {
	return modules.TypeScript
}

func (m *NucleiModule) Execute(ctx context.Context, target string, opts modules.Options) (*modules.Result, error) {
	// Call existing legacy scan.Nuclei function
	nucleiResults, err := scan.Nuclei(target, opts.Timeout, opts.Threads, opts.LogDir)

	if err != nil {
		return nil, err
	}

	result := &modules.Result{
		ModuleID: m.Info().ID,
		Target:   target,
		Findings: make([]modules.Finding, 0, len(nucleiResults)),
	}

	// Process nuclei results into module findings
	for _, event := range nucleiResults {
		severity := "info"

		switch event.Info.SeverityHolder.Severity.String() {
		case "critical":
			severity = "critical"
		case "high":
			severity = "high"
		case "medium":
			severity = "medium"
		case "low":
			severity = "low"
		}

		evidence := fmt.Sprintf("[%s] %s", event.TemplateID, event.Info.Name)
		if event.Matched != "" {
			evidence = fmt.Sprintf("[%s] %s - matched: %s", event.TemplateID, event.Info.Name, event.Matched)
		}

		finding := modules.Finding{
			URL:      event.Host,
			Severity: severity,
			Evidence: evidence,
			Extracted: map[string]string{
				"template_id":   event.TemplateID,
				"template_name": event.Info.Name,
				"severity":      event.Info.SeverityHolder.Severity.String(),
			},
		}

		// Template info
		if event.Type != "" {
			finding.Extracted["type"] = event.Type
		}

		// Matcher name
		if event.MatcherName != "" {
			finding.Extracted["matcher_name"] = event.MatcherName
		}

		// Extractor name
		if event.ExtractorName != "" {
			finding.Extracted["extractor_name"] = event.ExtractorName
		}

		// Matched line/data
		if event.Matched != "" {
			finding.Extracted["matched"] = event.Matched
		}

		// Metadata
		if len(event.Info.Metadata) > 0 {
			for key, value := range event.Info.Metadata {
				finding.Extracted[fmt.Sprintf("metadata_%s", key)] = fmt.Sprintf("%v", value)
			}
		}

		// Tags
		if !event.Info.Tags.IsEmpty() {
			tagStr := ""
			for _, tag := range event.Info.Tags.ToSlice() {
				if tagStr != "" {
					tagStr += ", "
				}
				tagStr += tag
			}

			finding.Extracted["tags"] = tagStr
		}

		// Reference
		if event.Info.Reference != nil && !event.Info.Reference.IsEmpty() {
			refStr := ""
			for _, ref := range event.Info.Reference.ToSlice() {
				if refStr != "" {
					refStr += "; "
				}
				refStr += ref
			}

			finding.Extracted["references"] = refStr
		}

		result.Findings = append(result.Findings, finding)
	}

	return result, nil
}
