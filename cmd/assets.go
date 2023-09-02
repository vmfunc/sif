package cmd

import "github.com/charmbracelet/lipgloss"

var separator = lipgloss.NewStyle().
	Border(lipgloss.ThickBorder(), true, false).
	Bold(true)

var statusstyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#00ff1a"))

var directorystyle = lipgloss.NewStyle().
	Bold(true).
	Underline(true)

var dnsstyle = lipgloss.NewStyle().
	Bold(true).
	Underline(true)

var portstyle = lipgloss.NewStyle().
	Bold(true).
	Underline(true)
