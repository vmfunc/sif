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

// Package styles provides custom styling options for the SIF tool's console output.
// It uses the lipgloss library to create visually appealing and consistent text styles.

package styles

import "github.com/charmbracelet/lipgloss"

var (
	// Separator style for creating visual breaks in the output
	Separator = lipgloss.NewStyle().
			Border(lipgloss.ThickBorder(), true, false).
			Bold(true)

	// Status style for highlighting important status messages
	Status = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00ff1a"))

	// Highlight style for emphasizing specific text
	Highlight = lipgloss.NewStyle().
			Bold(true).
			Underline(true)

	// Box style for creating bordered content boxes
	Box = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#fafafa")).
		BorderStyle(lipgloss.RoundedBorder()).
		Align(lipgloss.Center).
		PaddingRight(15).
		PaddingLeft(15).
		Width(60)

	// Subheading style for secondary titles or headers
	Subheading = lipgloss.NewStyle().
			Bold(true).
			Align(lipgloss.Center).
			PaddingRight(15).
			PaddingLeft(15).
			Width(60)
)

// Severity level styles for color-coding vulnerability severities
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
