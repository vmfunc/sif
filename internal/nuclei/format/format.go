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

package format

import (
	"github.com/dropalldatabases/sif/internal/styles"
	nucleiout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func FormatLine(event *nucleiout.ResultEvent) string {
	line := event.TemplateID

	if event.MatcherName != "" {
		line += ":" + styles.Highlight.Render(event.MatcherName)
	} else if event.ExtractorName != "" {
		line += ":" + styles.Highlight.Render(event.ExtractorName)
	}

	line += " [" + event.Type + "]"
	line += " [" + formatSeverity(event.Info.SeverityHolder.Severity.String()) + "]"

	return line
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
