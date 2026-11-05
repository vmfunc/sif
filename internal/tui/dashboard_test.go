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
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmfunc/sif/internal/event"
	"github.com/vmfunc/sif/internal/finding"
)

// newTestModel builds a sized model with no live channel, for driving Update
// directly. wait is nil: Update returns it after an eventMsg, which is a no-op
// when we call Update by hand.
func newTestModel(targets ...string) *Model {
	m := newModel("test", targets, nil)
	m.resize(100, 24)
	return m
}

func find(sev finding.Severity, target, module, title string) *finding.Finding {
	return &finding.Finding{Target: target, Module: module, Severity: sev, Title: title}
}

func send(m *Model, msg tea.Msg) {
	model, _ := m.Update(msg)
	_ = model // Update mutates *Model in place; returned model is the same pointer
}

func keyRunes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestDashboardAccumulatesFindings(t *testing.T) {
	m := newTestModel("https://a.com", "https://b.com")

	send(m, eventMsg{Kind: event.TargetStarted, Target: "https://a.com"})
	send(m, eventMsg{Kind: event.ScannerStarted, Target: "https://a.com", Scanner: "cors"})
	send(m, eventMsg{Kind: event.FindingFound, Target: "https://a.com", Scanner: "cors", Finding: find(finding.SeverityHigh, "https://a.com", "cors", "permissive cors")})
	send(m, eventMsg{Kind: event.ScannerDone, Target: "https://a.com", Scanner: "cors", Count: 1})
	send(m, eventMsg{Kind: event.TargetDone, Target: "https://a.com"})

	if len(m.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(m.findings))
	}
	if m.targets[0].findings != 1 || !m.targets[0].done {
		t.Errorf("target a state wrong: %+v", m.targets[0])
	}
	if m.scannersRun != 1 {
		t.Errorf("scannersRun = %d, want 1", m.scannersRun)
	}
	if got := m.View(); !strings.Contains(got, "permissive cors") {
		t.Errorf("view missing finding title:\n%s", got)
	}
}

func TestDashboardSeverityFloorCycles(t *testing.T) {
	m := newTestModel("t")
	send(m, eventMsg{Kind: event.FindingFound, Target: "t", Finding: find(finding.SeverityLow, "t", "m", "low one")})
	send(m, eventMsg{Kind: event.FindingFound, Target: "t", Finding: find(finding.SeverityHigh, "t", "m", "high one")})

	if got := len(m.visibleFindings()); got != 2 {
		t.Fatalf("all floor: visible = %d, want 2", got)
	}
	send(m, keyRunes("s")) // → medium
	if got := len(m.visibleFindings()); got != 1 {
		t.Fatalf("medium floor: visible = %d, want 1 (only high)", got)
	}
	if m.sevFloor != finding.SeverityMedium {
		t.Errorf("floor = %v, want medium", m.sevFloor)
	}
	send(m, keyRunes("s")) // high
	send(m, keyRunes("s")) // critical
	if got := len(m.visibleFindings()); got != 0 {
		t.Fatalf("critical floor: visible = %d, want 0", got)
	}
	send(m, keyRunes("s")) // back to all
	if m.sevFloor != finding.SeverityUnknown {
		t.Errorf("floor did not cycle back to all, got %v", m.sevFloor)
	}
}

func TestDashboardFocusSwitch(t *testing.T) {
	m := newTestModel("t")
	if m.focus != focusTargets {
		t.Fatalf("initial focus = %v, want targets", m.focus)
	}
	send(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != focusFindings {
		t.Errorf("after tab focus = %v, want findings", m.focus)
	}
	send(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != focusTargets {
		t.Errorf("after second tab focus = %v, want targets", m.focus)
	}
}

func TestDashboardFollowAutoPauseOnScrollUp(t *testing.T) {
	m := newTestModel("t")
	m.focus = focusFindings
	for i := 0; i < 5; i++ {
		send(m, eventMsg{Kind: event.FindingFound, Target: "t", Finding: find(finding.SeverityHigh, "t", "m", "f")})
	}
	if !m.follow {
		t.Fatal("follow should start on")
	}
	send(m, tea.KeyMsg{Type: tea.KeyUp}) // scroll up in findings pane
	if m.follow {
		t.Error("scrolling up should auto-pause follow mode")
	}
	send(m, keyRunes("p")) // resume
	if !m.follow {
		t.Error("p should resume follow mode")
	}
}

func TestDashboardFilterCapture(t *testing.T) {
	m := newTestModel("t")
	send(m, eventMsg{Kind: event.FindingFound, Target: "t", Finding: find(finding.SeverityHigh, "t", "cors", "permissive cors")})
	send(m, eventMsg{Kind: event.FindingFound, Target: "t", Finding: find(finding.SeverityHigh, "t", "xss", "reflected xss")})

	send(m, keyRunes("/")) // enter filter mode
	if !m.filtering {
		t.Fatal("expected filtering mode after /")
	}
	send(m, keyRunes("xss"))
	if got := len(m.visibleFindings()); got != 1 {
		t.Fatalf("filtered visible = %d, want 1", got)
	}
	send(m, tea.KeyMsg{Type: tea.KeyEnter}) // commit
	if m.filtering {
		t.Error("enter should exit filter capture")
	}
	if m.filter != "xss" {
		t.Errorf("filter = %q, want xss", m.filter)
	}
	// slash should not have leaked into the filter text.
	if strings.Contains(m.filter, "/") {
		t.Errorf("filter captured the '/' trigger: %q", m.filter)
	}
}

func TestDashboardSummaryScreenOnRunDone(t *testing.T) {
	m := newTestModel("t")
	send(m, eventMsg{Kind: event.FindingFound, Target: "t", Finding: find(finding.SeverityCritical, "t", "m", "rce")})
	send(m, eventMsg{
		Kind: event.RunDone,
		Summary: &event.Summary{
			Targets: 1, Findings: 1,
			BySeverity: map[string]int{"critical": 1},
			ScansRun:   []string{"cors", "xss"},
		},
	})
	if !m.done {
		t.Fatal("RunDone should mark the run done")
	}
	view := m.View()
	for _, want := range []string{"scan complete", "critical", "cors, xss"} {
		if !strings.Contains(view, want) {
			t.Errorf("summary view missing %q:\n%s", want, view)
		}
	}
}

func TestDashboardQuitKey(t *testing.T) {
	m := newTestModel("t")
	_, cmd := m.Update(keyRunes("q"))
	if cmd == nil {
		t.Fatal("q should return a command")
	}
	if msg := cmd(); msg == nil {
		t.Fatal("quit command produced no message")
	} else if _, ok := msg.(tea.QuitMsg); !ok {
		t.Errorf("q produced %T, want tea.QuitMsg", msg)
	}
}
