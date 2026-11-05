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
	"bytes"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/vmfunc/sif/internal/event"
	"github.com/vmfunc/sif/internal/finding"
)

// TestDashboardEndToEnd runs the model in a real bubbletea program fed by a live
// stream sink, exactly as Run wires it, then asserts the rendered frames reflect
// the scripted events and that quitting tears the program down. Frame assertions
// use substring matchers (not exact golden bytes) so the test stays stable
// across lipgloss/terminal versions and color profiles.
func TestDashboardEndToEnd(t *testing.T) {
	sink := newStreamSink()
	m := newModel("test", []string{"https://a.com"}, sink.waitForEvent())

	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 24))

	// feed a scripted scan through the sink the model drains.
	go func() {
		sink.Emit(event.Event{Kind: event.TargetStarted, Target: "https://a.com"})
		sink.Emit(event.Event{Kind: event.ScannerStarted, Target: "https://a.com", Scanner: "cors"})
		sink.Emit(event.Event{Kind: event.FindingFound, Target: "https://a.com", Scanner: "cors",
			Finding: &finding.Finding{Target: "https://a.com", Module: "cors", Severity: finding.SeverityHigh, Title: "permissive cors"}})
		sink.Emit(event.Event{Kind: event.ScannerDone, Target: "https://a.com", Scanner: "cors", Count: 1})
		sink.Emit(event.Event{Kind: event.TargetDone, Target: "https://a.com"})
		sink.Emit(event.Event{Kind: event.RunDone, Summary: &event.Summary{
			Targets: 1, Findings: 1, BySeverity: map[string]int{"high": 1}, ScansRun: []string{"cors"},
		}})
	}()

	// the run settles on the summary screen.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return bytes.Contains(b, []byte("scan complete")) && bytes.Contains(b, []byte("1 findings"))
	}, teatest.WithCheckInterval(20*time.Millisecond), teatest.WithDuration(5*time.Second))

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}
