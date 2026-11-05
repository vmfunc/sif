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

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/output"
)

// layout constants: the left target pane takes ~35% of the width, the right
// findings pane the rest, matching the roadmap split.
const (
	leftPaneFrac = 35
	minLeftWidth = 18
	headerLines  = 1
	footerLines  = 2
)

// resize recomputes pane geometry on a window-size change (and when help
// toggles, since the full help grid is taller).
func (m *Model) resize(w, h int) {
	m.width, m.height = w, h
	if w <= 0 || h <= 0 {
		return
	}
	m.help.Width = w

	footer := footerLines
	if m.help.ShowAll {
		footer = footerLines + 3
	}
	bodyH := h - headerLines - footer
	if bodyH < 3 {
		bodyH = 3
	}
	left := w * leftPaneFrac / 100
	if left < minLeftWidth {
		left = minLeftWidth
	}
	rightW := w - left - 1
	if rightW < 10 {
		rightW = 10
	}

	if !m.ready {
		m.vp = viewport.New(rightW, bodyH)
		m.ready = true
	} else {
		m.vp.Width = rightW
		m.vp.Height = bodyH
	}
	m.refreshFindings()
}

// refreshFindings rebuilds the findings viewport content from the filtered,
// severity-floored view, keeping the bottom pinned when follow mode is on.
func (m *Model) refreshFindings() {
	if !m.ready {
		return
	}
	vis := m.visibleFindings()
	if m.selFinding >= len(vis) {
		m.selFinding = len(vis) - 1
	}
	if m.selFinding < 0 {
		m.selFinding = 0
	}

	var b strings.Builder
	for i, f := range vis {
		line := fmt.Sprintf("[%s] %s · %s · %s", f.Severity, f.Target, f.Module, f.Title)
		line = sevRender(f.Severity, line)
		if m.focus == focusFindings && i == m.selFinding {
			line = "▸ " + line
		} else {
			line = "  " + line
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if len(vis) == 0 {
		b.WriteString(styleMuted.Render("  no findings yet"))
	}
	m.vp.SetContent(b.String())
	if m.follow {
		m.vp.GotoBottom()
	}
}

// View renders the current screen: the summary once the run is done, otherwise
// the live dashboard (or the expanded-finding overlay).
func (m *Model) View() string {
	if !m.ready {
		return "initializing sif dashboard…"
	}
	if m.done && m.summary != nil {
		return m.summaryView()
	}
	if m.expanded {
		return m.header() + "\n\n" + stylePanel.Width(m.width-2).Render(m.expandView()) + "\n" + m.footer()
	}
	left := lipgloss.NewStyle().Width(m.leftWidth()).Render(m.targetPane())
	right := lipgloss.NewStyle().Width(m.vp.Width).Render(
		styleGroup.Render("FINDINGS") + "\n" + m.vp.View())
	sep := styleFaint.Render(strings.Repeat("│\n", m.vp.Height+1))
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", sep, " ", right)
	return m.header() + "\n" + body + "\n" + m.footer()
}

// leftWidth is the target-pane content width.
func (m *Model) leftWidth() int {
	left := m.width * leftPaneFrac / 100
	if left < minLeftWidth {
		left = minLeftWidth
	}
	return left
}

// header is the top status bar: a colored strip with the product and live run
// counters.
func (m *Model) header() string {
	done := 0
	for _, t := range m.targets {
		if t.done {
			done++
		}
	}
	onBar := lipgloss.NewStyle().Background(colorBarBg)
	state := "scanning"
	if m.done {
		state = "done"
	}
	left := onBar.Foreground(colorText).Bold(true).Render(" sif " + m.version + " ")
	stats := onBar.Foreground(colorText).Render(fmt.Sprintf(
		" %d/%d targets · %d findings · %d scanners · %s ",
		done, len(m.targets), len(m.findings), m.scannersRun, state))
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(stats)
	if gap < 0 {
		gap = 0
	}
	return left + onBar.Render(spaces(gap)) + stats
}

// targetPane renders the left target list with a running spinner or a done
// glyph and a severity-colored finding-count badge.
func (m *Model) targetPane() string {
	width := m.leftWidth()
	var b strings.Builder
	b.WriteString(styleGroup.Render("TARGETS") + "\n")
	for i, t := range m.targets {
		glyph := m.spin.View()
		if t.done {
			glyph = styleOn.Render("✓")
		}
		cursor := "  "
		name := styleLabel.Render(truncate(t.url, width-10))
		if m.focus == focusTargets && i == m.selTarget {
			cursor = styleCursor.Render("▸ ")
			name = styleTitle.Render(truncate(t.url, width-10))
		}
		badge := severityBadge(t.bySev, t.findings)
		b.WriteString(fmt.Sprintf("%s%s %s %s\n", cursor, glyph, name, badge))
	}
	return b.String()
}

// footer renders the live filter/severity/follow state plus a key-hint line.
func (m *Model) footer() string {
	var state []string
	if m.sevFloor > finding.SeverityUnknown {
		state = append(state, styleKey.Render("floor:")+styleTitle.Render(m.sevFloor.String()))
	}
	if m.follow {
		state = append(state, styleOn.Render("● follow"))
	}
	if m.onlyHits {
		state = append(state, styleKey.Render("hits-only"))
	}
	if m.filtering {
		state = append(state, styleKey.Render("filter ")+styleTitle.Render(m.filter+"▏"))
	} else if m.filter != "" {
		state = append(state, styleMuted.Render("filter:"+m.filter))
	}
	if m.status != "" {
		state = append(state, styleMuted.Render(m.status))
	}

	hints := []string{
		keyHint("j/k", "move"), keyHint("tab", "pane"), keyHint("/", "filter"),
		keyHint("s", "sev"), keyHint("p", "follow"), keyHint("enter", "expand"),
		keyHint("?", "help"), keyHint("q", "quit"),
	}
	line := strings.Join(hints, styleFaint.Render("  ·  "))
	if len(state) > 0 {
		line = strings.Join(state, styleFaint.Render("   ")) + "\n" + line
	}
	return line
}

// expandView shows the selected finding's detail.
func (m *Model) expandView() string {
	vis := m.visibleFindings()
	if m.selFinding < 0 || m.selFinding >= len(vis) {
		return styleMuted.Render("no finding selected")
	}
	f := vis[m.selFinding]
	row := func(k, v string) string {
		return styleFaint.Render(padRight(k, 10)) + v + "\n"
	}
	var b strings.Builder
	b.WriteString(styleGroup.Render("FINDING") + "\n\n")
	b.WriteString(row("severity", sevRender(f.Severity, f.Severity.String())))
	b.WriteString(row("target", styleLabel.Render(output.Sanitize(f.Target))))
	b.WriteString(row("module", styleFlag.Render(output.Sanitize(f.Module))))
	b.WriteString(row("title", styleTitle.Render(output.Sanitize(f.Title))))
	if f.Raw != "" {
		b.WriteString(row("evidence", styleMuted.Render(output.Sanitize(f.Raw))))
	}
	b.WriteString("\n" + styleFaint.Render("enter to close"))
	return b.String()
}

// summaryView is screen 3: totals by severity and the scanners that ran. It
// does not auto-exit; the footer tells the user to quit or write a report.
func (m *Model) summaryView() string {
	s := m.summary
	w := m.width
	if w <= 0 || w > 80 {
		w = 80
	}
	var b strings.Builder
	onBar := lipgloss.NewStyle().Background(colorBarBg).Foreground(colorText).Bold(true)
	b.WriteString(onBar.Width(w).Render(fmt.Sprintf(" sif %s · scan complete", m.version)) + "\n\n")
	b.WriteString(styleTitle.Render(fmt.Sprintf("%d findings", s.Findings)) +
		styleMuted.Render(fmt.Sprintf(" across %d targets", s.Targets)) + "\n\n")

	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if n := s.BySeverity[sev.String()]; n > 0 {
			bar := strings.Repeat("█", minInt(n, w-20))
			b.WriteString("  " + sevRender(sev, padRight(sev.String(), 9)) + " " +
				sevRender(sev, bar) + " " + styleMuted.Render(fmt.Sprintf("%d", n)) + "\n")
		}
	}
	b.WriteString("\n" + styleFaint.Render("scanners  ") + styleMuted.Render(strings.Join(s.ScansRun, ", ")) + "\n")
	b.WriteString("\n" + keyHint("w", "write report") + styleFaint.Render("  ·  ") + keyHint("q", "quit"))
	return b.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// severityBadge renders a compact count badge colored by the highest severity
// present for a target.
func severityBadge(bySev map[string]int, total int) string {
	if total == 0 {
		return styleFaint.Render("·")
	}
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow} {
		if bySev[sev.String()] > 0 {
			return sevRender(sev, fmt.Sprintf("%d", total))
		}
	}
	return styleMuted.Render(fmt.Sprintf("%d", total))
}

// sevRender colors text by severity, routing through output.Style.Render so
// untrusted finding text (titles, evidence) is sanitized of control bytes.
func sevRender(s finding.Severity, text string) string {
	switch s {
	case finding.SeverityCritical:
		return output.SeverityCritical.Render(text)
	case finding.SeverityHigh:
		return output.SeverityHigh.Render(text)
	case finding.SeverityMedium:
		return output.SeverityMedium.Render(text)
	case finding.SeverityLow:
		return output.SeverityLow.Render(text)
	default:
		return output.Sanitize(text)
	}
}

// truncate shortens s to n runes with an ellipsis, for the fixed-width target
// column.
func truncate(s string, n int) string {
	if n < 1 {
		n = 1
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
