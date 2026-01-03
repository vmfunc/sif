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
