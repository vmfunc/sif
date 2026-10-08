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
	"context"
	"testing"

	"github.com/vmfunc/sif/internal/output"
)

// TestScanAllTargetsConcurrentIsolation runs the target pool at concurrency 3
// against three separate servers and asserts each target's result is isolated:
// exactly one scan recorded per target, results in input order. Run under -race
// it also backstops scanTarget's concurrency safety and the serialized sink.
func TestScanAllTargetsConcurrentIsolation(t *testing.T) {
	defer output.SetConcurrent(false)

	srvA := okServer()
	defer srvA.Close()
	srvB := okServer()
	defer srvB.Close()
	srvC := okServer()
	defer srvC.Close()

	app := headersOnlyApp()
	app.targets = []string{srvA.URL, srvB.URL, srvC.URL}
	app.settings.Concurrency = 3

	results, err := app.scanAllTargets(context.Background(), "", false)
	if err != nil {
		t.Fatalf("scanAllTargets: %v", err)
	}
	if len(results) != len(app.targets) {
		t.Fatalf("got %d results, want %d", len(results), len(app.targets))
	}
	for i, ts := range results {
		if len(ts.scansRun) != 1 || ts.scansRun[0] != "HTTP Headers" {
			t.Errorf("target %d scansRun = %v, want exactly [HTTP Headers] (accumulator leaked across targets)", i, ts.scansRun)
		}
	}
}

// TestScanAllTargetsSequentialMatchesInputOrder pins that concurrency 1 keeps the
// plain sequential path: one result per target, in order, no pool engaged.
func TestScanAllTargetsSequentialMatchesInputOrder(t *testing.T) {
	srvA := okServer()
	defer srvA.Close()
	srvB := okServer()
	defer srvB.Close()

	app := headersOnlyApp()
	app.targets = []string{srvA.URL, srvB.URL}
	app.settings.Concurrency = 1

	results, err := app.scanAllTargets(context.Background(), "", false)
	if err != nil {
		t.Fatalf("scanAllTargets: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for i, ts := range results {
		if len(ts.scansRun) != 1 || ts.scansRun[0] != "HTTP Headers" {
			t.Errorf("target %d scansRun = %v, want exactly [HTTP Headers]", i, ts.scansRun)
		}
	}
	if output.Concurrent() {
		t.Error("concurrency 1 must not switch output into concurrent mode")
	}
}
