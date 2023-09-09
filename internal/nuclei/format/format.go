package format

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/pushfs/sif/internal/styles"
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
