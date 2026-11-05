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
		b.WriteString(output.Subheading.Render("  no findings yet"))
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
		return m.header() + "\n" + m.expandView() + "\n" + m.footer()
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.targetPane(), " ", m.vp.View())
	return m.header() + "\n" + body + "\n" + m.footer()
}

// header is the top status line.
func (m *Model) header() string {
	done := 0
	for _, t := range m.targets {
		if t.done {
			done++
		}
	}
	title := output.Highlight.Render(fmt.Sprintf("sif %s", m.version))
	state := "scanning"
	if m.done {
		state = "done"
	}
	return fmt.Sprintf("%s · %d/%d targets · %d findings · %d scanners · %s",
		title, done, len(m.targets), len(m.findings), m.scannersRun, state)
}

// targetPane renders the left target list with a running spinner or a done
// glyph and a finding-count badge.
func (m *Model) targetPane() string {
	left := m.width * leftPaneFrac / 100
	if left < minLeftWidth {
		left = minLeftWidth
	}
	var b strings.Builder
	for i, t := range m.targets {
		glyph := m.spin.View()
		if t.done {
			glyph = output.Status.Render("✓")
		}
		cursor := "  "
		if m.focus == focusTargets && i == m.selTarget {
			cursor = "▸ "
		}
		badge := severityBadge(t.bySev, t.findings)
		name := truncate(t.url, left-6)
		b.WriteString(fmt.Sprintf("%s%s %s %s\n", cursor, glyph, name, badge))
	}
	return lipgloss.NewStyle().Width(left).Render(b.String())
}

// footer renders the help line plus the live filter/severity/follow state.
func (m *Model) footer() string {
	status := []string{}
	if m.sevFloor > finding.SeverityUnknown {
		status = append(status, "floor:"+m.sevFloor.String())
	}
	if m.follow {
		status = append(status, "follow")
	}
	if m.onlyHits {
		status = append(status, "hits-only")
	}
	if m.filtering {
		status = append(status, "filter: "+m.filter+"▏")
	} else if m.filter != "" {
		status = append(status, "filter:"+m.filter)
	}
	if m.status != "" {
		status = append(status, m.status)
	}
	line := m.help.View(&m.keys)
	if len(status) > 0 {
		line = strings.Join(status, "  ") + "\n" + line
	}
	return line
}

// expandView shows the selected finding's detail.
func (m *Model) expandView() string {
	vis := m.visibleFindings()
	if m.selFinding < 0 || m.selFinding >= len(vis) {
		return output.Subheading.Render("no finding selected")
	}
	f := vis[m.selFinding]
	var b strings.Builder
	b.WriteString(output.Subheading.Render("finding detail") + "\n\n")
	b.WriteString("severity : " + sevRender(f.Severity, f.Severity.String()) + "\n")
	b.WriteString("target   : " + output.Sanitize(f.Target) + "\n")
	b.WriteString("module   : " + output.Sanitize(f.Module) + "\n")
	b.WriteString("title    : " + output.Sanitize(f.Title) + "\n")
	if f.Raw != "" {
		b.WriteString("evidence : " + output.Sanitize(f.Raw) + "\n")
	}
	b.WriteString("\n" + output.Subheading.Render("enter to close"))
	return b.String()
}

// summaryView is screen 3: totals by severity and the scanners that ran. It
// does not auto-exit; the footer tells the user to quit or write a report.
func (m *Model) summaryView() string {
	s := m.summary
	var b strings.Builder
	b.WriteString(output.Highlight.Render(fmt.Sprintf("sif %s · scan complete", m.version)) + "\n\n")
	b.WriteString(fmt.Sprintf("%d findings across %d targets\n\n", s.Findings, s.Targets))

	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if n := s.BySeverity[sev.String()]; n > 0 {
			b.WriteString("  " + sevRender(sev, fmt.Sprintf("%-9s %d", sev.String(), n)) + "\n")
		}
	}
	b.WriteString("\n" + output.Subheading.Render("scanners: "+strings.Join(s.ScansRun, ", ")) + "\n")
	b.WriteString("\n" + output.Subheading.Render("w write report · q quit"))
	return b.String()
}

// severityBadge renders a compact count badge colored by the highest severity
// present for a target.
func severityBadge(bySev map[string]int, total int) string {
	if total == 0 {
		return output.Subheading.Render("·")
	}
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow} {
		if bySev[sev.String()] > 0 {
			return sevRender(sev, fmt.Sprintf("[%d]", total))
		}
	}
	return output.Subheading.Render(fmt.Sprintf("[%d]", total))
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
