/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package tui

import "github.com/charmbracelet/lipgloss"

// the tui palette. kept here (not reusing internal/output's banner styles, which
// are fixed-width centered blocks meant for the splash) so every screen shares
// one cohesive, left-aligned look that lipgloss degrades cleanly under NO_COLOR.
var (
	colorAccent    = lipgloss.Color("#a78bfa") // violet — headers, carets, cursor
	colorAccentDim = lipgloss.Color("#7c6fb0") // muted violet
	colorText      = lipgloss.Color("#f3f4f6") // bright text
	colorMuted     = lipgloss.Color("#8b90a0") // descriptions, hints
	colorFaint     = lipgloss.Color("#5b6070") // flags, separators
	colorOn        = lipgloss.Color("#34d399") // enabled checkbox
	colorFlag      = lipgloss.Color("#60a5fa") // flag names
	colorBarBg     = lipgloss.Color("#4c3f82") // header bar background
	colorSelBg     = lipgloss.Color("#2d2a44") // selected row background
)

// shared styles.
var (
	styleTitle = lipgloss.NewStyle().Foreground(colorText).Bold(true)

	styleGroup = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)

	styleLabel = lipgloss.NewStyle().Foreground(colorText)

	styleFlag = lipgloss.NewStyle().Foreground(colorFlag)

	styleDesc = lipgloss.NewStyle().Foreground(colorMuted)

	styleMuted = lipgloss.NewStyle().Foreground(colorMuted)

	styleFaint = lipgloss.NewStyle().Foreground(colorFaint)

	styleOn = lipgloss.NewStyle().Foreground(colorOn).Bold(true)

	styleCursor = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)

	styleSelected = lipgloss.NewStyle().Background(colorSelBg)

	styleCmd = lipgloss.NewStyle().Foreground(colorAccentDim)

	styleKey = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)

	stylePill = lipgloss.NewStyle().Foreground(lipgloss.Color("#0b0b12")).Background(colorOn).Bold(true).Padding(0, 1)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorFaint).
			Padding(0, 1)
)

// keyHint renders a "key action" hint with the key emphasized.
func keyHint(k, action string) string {
	return styleKey.Render(k) + " " + styleMuted.Render(action)
}

// padRight pads s with spaces to width w (visible width), truncating with an
// ellipsis when it is longer, so columns stay aligned regardless of content.
func padRight(s string, w int) string {
	r := []rune(s)
	if len(r) == w {
		return s
	}
	if len(r) > w {
		if w <= 1 {
			return string(r[:w])
		}
		return string(r[:w-1]) + "…"
	}
	return s + spaces(w-len(r))
}

func spaces(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}
