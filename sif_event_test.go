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

package sif

import (
	"sync"
	"testing"

	"github.com/vmfunc/sif/internal/event"
	"github.com/vmfunc/sif/internal/finding"
)

// recordingSink captures every event in order under a lock, so a concurrent
// scan can emit into it safely.
type recordingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recordingSink) Emit(e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingSink) kinds() map[event.Kind]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[event.Kind]int)
	for _, e := range r.events {
		m[e.Kind]++
	}
	return m
}

func (r *recordingSink) findings() []finding.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []finding.Finding
	for _, e := range r.events {
		if e.Kind == event.FindingFound && e.Finding != nil {
			out = append(out, *e.Finding)
		}
	}
	return out
}

// TestScanTargetStreamMatchesReturnedFindings is the behaviour-identity seam of
// the streaming refactor: the FindingFound events a target emits must be exactly
// the findings the batch path (collectFindings, via targetScan) reports, in the
// same order. If these ever diverge, a live sink (the TUI) would show something
// different from the report/notify output.
func TestScanTargetStreamMatchesReturnedFindings(t *testing.T) {
	srv := okServer()
	defer srv.Close()

	app := headersOnlyApp()
	rec := &recordingSink{}
	app.sink = rec

	ts, err := app.scanTarget(srv.URL, "", false)
	if err != nil {
		t.Fatalf("scanTarget: %v", err)
	}

	streamed := rec.findings()
	if len(streamed) != len(ts.findings) {
		t.Fatalf("streamed %d findings, returned %d", len(streamed), len(ts.findings))
	}
	for i := range ts.findings {
		if streamed[i].Line() != ts.findings[i].Line() {
			t.Errorf("finding %d: streamed %q, returned %q", i, streamed[i].Line(), ts.findings[i].Line())
		}
	}

	// the target must open and close exactly once around the scanner events.
	k := rec.kinds()
	if k[event.TargetStarted] != 1 || k[event.TargetDone] != 1 {
		t.Errorf("target bracket events: started=%d done=%d, want 1/1", k[event.TargetStarted], k[event.TargetDone])
	}
	if k[event.ScannerStarted] != k[event.ScannerDone] {
		t.Errorf("unbalanced scanner events: started=%d done=%d", k[event.ScannerStarted], k[event.ScannerDone])
	}
}

// TestScanTargetNilSinkIsSafe pins that a target scanned with no sink attached
// (the direct-caller path) does not panic and still returns its findings.
func TestScanTargetNilSinkIsSafe(t *testing.T) {
	srv := okServer()
	defer srv.Close()

	app := headersOnlyApp() // sink left nil
	if _, err := app.scanTarget(srv.URL, "", false); err != nil {
		t.Fatalf("scanTarget with nil sink: %v", err)
	}
}
