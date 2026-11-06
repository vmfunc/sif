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
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmfunc/sif/internal/event"
	"github.com/vmfunc/sif/internal/finding"
)

// focus selects which pane the key bindings drive.
type focus int

const (
	focusTargets focus = iota
	focusFindings
)

// targetState tracks one target's progress for the left pane.
type targetState struct {
	url      string
	done     bool
	findings int
	bySev    map[string]int
}

// Model is the live scan dashboard. It is a pure event consumer: every change
// comes from an eventMsg off the scan stream or a key press, so the same model
// drives a real run and a scripted teatest run identically.
type Model struct {
	version string
	keys    keyMap
	help    help.Model
	spin    spinner.Model
	vp      viewport.Model

	width, height int
	ready         bool

	targets   []targetState
	targetIdx map[string]int
	findings  []finding.Finding
	inflight  map[string]bool // "scanner@target" currently running

	focus      focus
	sevFloor   finding.Severity
	follow     bool
	onlyHits   bool
	filter     string
	filtering  bool // capturing filter text
	selTarget  int
	selFinding int
	expanded   bool

	scannersRun int
	done        bool // RunDone seen
	summary     *event.Summary
	status      string // transient footer note (copy/write feedback)

	// wait re-arms the event-drain command after each event; set by Run.
	wait tea.Cmd

	// writeReport backs the `w` key; nil when the caller wired no writer.
	writeReport func([]finding.Finding) (string, error)
	writing     bool // a write is in flight; debounces repeated `w`
}

// reportWrittenMsg carries the outcome of an async `w` report write.
type reportWrittenMsg struct {
	path string
	err  error
}

// newModel builds an empty dashboard for the given targets.
func newModel(version string, targets []string, wait tea.Cmd) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot

	m := &Model{
		version:   version,
		keys:      defaultKeyMap(),
		help:      help.New(),
		spin:      sp,
		targetIdx: make(map[string]int),
		inflight:  make(map[string]bool),
		follow:    true,
		sevFloor:  finding.SeverityUnknown,
		wait:      wait,
	}
	for _, t := range targets {
		m.targetIdx[t] = len(m.targets)
		m.targets = append(m.targets, targetState{url: t, bySev: make(map[string]int)})
	}
	return m
}

// Init starts the spinner and the first event-drain.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, m.wait)
}

// Update is the single reducer: events mutate scan state, keys drive the view.
// It never blocks — the event drain happens in m.wait's command.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
		return m, nil

	case eventMsg:
		m.applyEvent(event.Event(msg))
		m.refreshFindings()
		// re-arm the drain for the next event.
		return m, m.wait

	case streamClosedMsg:
		m.done = true
		return m, nil

	case reportWrittenMsg:
		m.writing = false
		if msg.err != nil {
			m.status = "write failed: " + msg.err.Error()
		} else {
			m.status = "report written to " + msg.path
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// handleKey routes a key press, honoring filter-capture mode first.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.filtering {
		return m.handleFilterKey(msg)
	}

	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Help):
		m.help.ShowAll = !m.help.ShowAll
		m.resize(m.width, m.height)
	case key.Matches(msg, m.keys.Focus):
		if m.inSummary() {
			break // the summary has a single findings list
		}
		if m.focus == focusTargets {
			m.focus = focusFindings
		} else {
			m.focus = focusTargets
		}
	case key.Matches(msg, m.keys.Severity):
		m.cycleSeverity()
		m.refreshFindings()
	case key.Matches(msg, m.keys.Follow):
		m.follow = !m.follow
		if m.follow {
			m.vp.GotoBottom()
		}
	case key.Matches(msg, m.keys.OnlyHits):
		m.onlyHits = !m.onlyHits
	case key.Matches(msg, m.keys.Filter):
		m.filtering = true
	case key.Matches(msg, m.keys.Expand):
		m.expanded = !m.expanded
	case key.Matches(msg, m.keys.Copy):
		m.status = m.copySelectedURL()
	case key.Matches(msg, m.keys.Write):
		cmd := m.startWrite()
		return m, cmd
	case key.Matches(msg, m.keys.Top):
		m.vp.GotoTop()
		m.follow = false
		if m.inSummary() {
			m.selFinding = 0
		}
	case key.Matches(msg, m.keys.Bottom):
		m.vp.GotoBottom()
		if m.inSummary() {
			m.selFinding = len(m.visibleFindings()) - 1
			m.refreshFindings() // clamps an empty list back to 0
		}
	case key.Matches(msg, m.keys.Up):
		m.moveUp()
	case key.Matches(msg, m.keys.Down):
		m.moveDown()
	}
	return m, nil
}

// startWrite kicks off an async report write of every finding seen so far
// (unfiltered: the report is the run, not the current view).
func (m *Model) startWrite() tea.Cmd {
	if m.writeReport == nil {
		m.status = "report writing unavailable"
		return nil
	}
	if m.writing {
		return nil
	}
	m.writing = true
	m.status = "writing report…"
	fs := make([]finding.Finding, len(m.findings))
	copy(fs, m.findings)
	write := m.writeReport
	return func() tea.Msg {
		path, err := write(fs)
		return reportWrittenMsg{path: path, err: err}
	}
}

// inSummary reports whether the run is over and the summary screen is up.
func (m *Model) inSummary() bool {
	return m.done && m.summary != nil
}

// handleFilterKey captures text while the filter input is active.
func (m *Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filtering = false
	case tea.KeyEsc:
		m.filtering = false
		m.filter = ""
	case tea.KeyBackspace:
		if m.filter != "" {
			m.filter = m.filter[:len(m.filter)-1]
		}
	case tea.KeyRunes:
		m.filter += string(msg.Runes)
	case tea.KeySpace:
		m.filter += " "
	}
	m.refreshFindings()
	return m, nil
}

// moveUp/moveDown move the selection in the focused pane. Scrolling the
// findings pane up auto-pauses follow mode so the view stays put.
func (m *Model) moveUp() {
	if m.focus == focusTargets {
		if m.selTarget > 0 {
			m.selTarget--
		}
		return
	}
	if m.selFinding > 0 {
		m.selFinding--
	}
	m.follow = false
	m.vp.ScrollUp(1)
}

func (m *Model) moveDown() {
	if m.focus == focusTargets {
		if m.selTarget < len(m.targets)-1 {
			m.selTarget++
		}
		return
	}
	if m.selFinding < len(m.visibleFindings())-1 {
		m.selFinding++
	}
	m.vp.ScrollDown(1)
}

// cycleSeverity steps the floor all → medium → high → critical → all.
func (m *Model) cycleSeverity() {
	switch m.sevFloor {
	case finding.SeverityUnknown:
		m.sevFloor = finding.SeverityMedium
	case finding.SeverityMedium:
		m.sevFloor = finding.SeverityHigh
	case finding.SeverityHigh:
		m.sevFloor = finding.SeverityCritical
	default:
		m.sevFloor = finding.SeverityUnknown
	}
}

// copySelectedURL is a best-effort clipboard note; real clipboard access is a
// later addition, so for now it reports the url it would copy.
func (m *Model) copySelectedURL() string {
	vis := m.visibleFindings()
	if m.selFinding >= 0 && m.selFinding < len(vis) {
		return "url: " + vis[m.selFinding].Target
	}
	return "no finding selected"
}

// applyEvent folds one scan event into the model state.
func (m *Model) applyEvent(e event.Event) {
	switch e.Kind {
	case event.ScannerStarted:
		m.inflight[e.Scanner+"@"+e.Target] = true
	case event.FindingFound:
		if e.Finding != nil {
			m.findings = append(m.findings, *e.Finding)
			if idx, ok := m.targetIdx[e.Target]; ok {
				m.targets[idx].findings++
				m.targets[idx].bySev[e.Finding.Severity.String()]++
			}
		}
	case event.ScannerDone:
		delete(m.inflight, e.Scanner+"@"+e.Target)
		m.scannersRun++
	case event.TargetDone:
		if idx, ok := m.targetIdx[e.Target]; ok {
			m.targets[idx].done = true
		}
	case event.RunDone:
		m.summary = e.Summary
		m.done = true
		// the summary lists findings worst-first for review; arrival order only
		// matters while the scan is live.
		sort.SliceStable(m.findings, func(i, j int) bool {
			return m.findings[i].Severity > m.findings[j].Severity
		})
		m.focus = focusFindings
		m.follow = false
		m.selFinding = 0
	}
}

// visibleFindings applies the severity floor and text filter, in arrival order.
func (m *Model) visibleFindings() []finding.Finding {
	out := make([]finding.Finding, 0, len(m.findings))
	for _, f := range m.findings {
		if f.Severity < m.sevFloor {
			continue
		}
		if m.filter != "" && !matchesFilter(&f, m.filter) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func matchesFilter(f *finding.Finding, q string) bool {
	q = strings.ToLower(q)
	return strings.Contains(strings.ToLower(f.Title), q) ||
		strings.Contains(strings.ToLower(f.Module), q) ||
		strings.Contains(strings.ToLower(f.Target), q)
}
