package styles

import "github.com/charmbracelet/lipgloss"

var (
	Separator = lipgloss.NewStyle().
			Border(lipgloss.ThickBorder(), true, false).
			Bold(true)

	Status = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00ff1a"))

	Highlight = lipgloss.NewStyle().
			Bold(true).
			Underline(true)

	Box = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#fafafa")).
		BorderStyle(lipgloss.RoundedBorder()).
		Align(lipgloss.Center).
		PaddingRight(15).
		PaddingLeft(15).
		Width(60)

	Subheading = lipgloss.NewStyle().
			Bold(true).
			Align(lipgloss.Center).
			PaddingRight(15).
			PaddingLeft(15).
			Width(60)
)

var (
	SeverityLow = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00ff00"))

	SeverityMedium = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffff00"))

	SeverityHigh = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff8800"))

	SeverityCritical = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ff0000"))
)
