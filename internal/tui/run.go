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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmfunc/sif/internal/event"
)

// Config carries what the dashboard needs that it can't learn from the stream.
type Config struct {
	Version string
	Targets []string
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

// Run launches the live dashboard, runs scan in a background goroutine feeding
// the event stream, and blocks until the program exits. Quitting cancels the
// scan context (the scan still gets to flush reports on its way out). The scan
// error, if any, is returned once the ui has torn down.
func Run(ctx context.Context, cfg Config, scan ScanFunc) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sink := newStreamSink()
	m := newModel(cfg.Version, cfg.Targets, sink.waitForEvent())

	p := tea.NewProgram(m,
		tea.WithContext(ctx),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	var scanErr error
	go func() {
		scanErr = scan(ctx, sink)
		// closing the stream lets the model learn the run is finished even if no
		// RunDone event was emitted (e.g. an early scan error).
		sink.close()
	}()

	if _, err := p.Run(); err != nil {
		return err
	}
	// the user quit (or the scan finished and they quit): stop any work still
	// in flight, then surface the scan's own error.
	cancel()
	return scanErr
}
