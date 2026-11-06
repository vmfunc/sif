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
	"context"
	"errors"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmfunc/sif/internal/event"
	"github.com/vmfunc/sif/internal/finding"
)

// Config carries what the dashboard needs that it can't learn from the stream.
type Config struct {
	Version string
	Targets []string

	// WriteReport writes the given findings (everything seen so far) to a
	// report and returns where it went. Bound to the `w` key; it runs off the
	// ui goroutine. Nil leaves `w` reporting that writing is unavailable.
	WriteReport func([]finding.Finding) (string, error)
}

// Pick runs the interactive picker (screen 1) and returns the chosen selection
// and whether the user launched the scan (false means they quit). The selection
// is persisted on launch so the next session restores it.
func Pick(ctx context.Context, version string, spec PickerSpec) (Selection, bool, error) {
	m := newPickerModel(version, spec)
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen())
	fm, err := p.Run()
	if err != nil {
		return Selection{}, false, err
	}
	pm, ok := fm.(*pickerModel)
	if !ok {
		return Selection{}, false, nil
	}
	return pm.Selection(), pm.run, nil
}

// ScanFunc runs the scan, emitting its progress onto the given sink. It must
// honor ctx cancellation so quitting the dashboard stops the scan promptly.
type ScanFunc func(ctx context.Context, sink event.Sink) error

// ErrQuit is returned by Run when the user quit the dashboard before the scan
// finished. The scan context is cancelled; callers should treat the run as
// aborted rather than wait on (or report) a partial scan.
var ErrQuit = errors.New("dashboard quit before the scan finished")

// Run launches the live dashboard, runs scan in a background goroutine feeding
// the event stream, and blocks until the program exits. If the scan already
// finished, its error is returned. If the user quit mid-scan, the scan context
// is cancelled and Run returns ErrQuit straight away instead of blocking on
// scanners that may not observe ctx promptly.
func Run(ctx context.Context, cfg Config, scan ScanFunc) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sink := newStreamSink()
	m := newModel(cfg.Version, cfg.Targets, sink.waitForEvent())
	m.writeReport = cfg.WriteReport

	p := tea.NewProgram(m,
		tea.WithContext(ctx),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// buffered so the scan goroutine never blocks on send after an early quit.
	done := make(chan error, 1)
	go func() {
		err := scan(ctx, sink)
		// closing the stream lets the model learn the run is finished even if no
		// RunDone event was emitted (e.g. an early scan error).
		sink.close()
		done <- err
	}()

	if _, err := p.Run(); err != nil {
		return err
	}
	cancel()
	select {
	case err := <-done:
		return err
	default:
		return ErrQuit
	}
}
