/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                                  SIF                                         ║
║                                                                              ║
║        Blazing-fast pentesting suite written in Go                           ║
║                                                                              ║
║        Copyright (c) 2023-2024 vmfunc, xyzeva, lunchcat contributors         ║
║                    and other sif contributors.                               ║
║                                                                              ║
║                                                                              ║
║        Use of this tool is restricted to research and educational            ║
║        purposes only. Usage in a production environment outside              ║
║        of these categories is strictly prohibited.                           ║
║                                                                              ║
║        Any person or entity wishing to use this tool outside of              ║
║        research or educational purposes must purchase a license              ║
║        from https://lunchcat.dev                                             ║
║                                                                              ║
║        For more information, visit: https://github.com/lunchcat/sif          ║ 
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

package format

import (
	"fmt"

	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

func FormatLine(event *output.ResultEvent) string {
	output := event.TemplateID

	if event.MatcherName != "" {
		output += ":" + styles.Highlight.Render(event.MatcherName)
	} else if event.ExtractorName != "" {
		output += ":" + styles.Highlight.Render(event.ExtractorName)
	}

	output += " [" + event.Type + "]"
	output += " [" + formatSeverity(fmt.Sprintf("%s", event.Info.SeverityHolder.Severity)) + "]"

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
