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

package format

import (
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func FormatLine(event *output.ResultEvent) string {
	output := event.TemplateID

	if event.MatcherName != "" {
		output += ":" + styles.Highlight.Render(event.MatcherName)
	} else if event.ExtractorName != "" {
		output += ":" + styles.Highlight.Render(event.ExtractorName)
	}

	output += " [" + event.Type + "]"
	output += " [" + formatSeverity(event.Info.SeverityHolder.Severity.String()) + "]"

	return output
}

func formatSeverity(severity string) string {
	switch severity {
	case "low":
		return styles.SeverityLow.Render(severity)
	case "medium":
		return styles.SeverityMedium.Render(severity)
	case "high":
		return styles.SeverityHigh.Render(severity)
	case "critical":
		return styles.SeverityCritical.Render(severity)
	default:
		return severity
	}
}
