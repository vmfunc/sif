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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/config"
)

// headersOnlyApp builds an App that runs only the HTTP headers scan against
// live servers, with every network-touching scanner gated off. it isolates the
// scanTarget path to a single deterministic scan.
func headersOnlyApp() *App {
	return &App{settings: &config.Settings{
		Headers: true,
		NoScan:  true,
		Dirlist: "none",
		Dnslist: "none",
		Ports:   "none",
		Timeout: 5 * time.Second,
	}}
}

func okServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sif-Test", "1")
		w.WriteHeader(http.StatusOK)
	}))
}

// TestScanTargetIsolatesPerTargetState is the accumulator seam the worker pool
// depends on: each scanTarget call must own its scansRun rather than share a
// run-wide slice. two sequential scans of different targets must each report a
// single scan, not a growing total; a shared accumulator would make the second
// call report two.
func TestScanTargetIsolatesPerTargetState(t *testing.T) {
	srvA := okServer()
	defer srvA.Close()
	srvB := okServer()
	defer srvB.Close()

	app := headersOnlyApp()

	tsA, err := app.scanTarget(srvA.URL, "", false)
	if err != nil {
		t.Fatalf("scanTarget(A): %v", err)
	}
	if len(tsA.scansRun) != 1 || tsA.scansRun[0] != "HTTP Headers" {
		t.Fatalf("target A scansRun = %v, want exactly [HTTP Headers]", tsA.scansRun)
	}

	tsB, err := app.scanTarget(srvB.URL, "", false)
	if err != nil {
		t.Fatalf("scanTarget(B): %v", err)
	}
	if len(tsB.scansRun) != 1 || tsB.scansRun[0] != "HTTP Headers" {
		t.Fatalf("target B scansRun = %v, want exactly [HTTP Headers] (accumulator leaked across targets)", tsB.scansRun)
	}

	// no log dir configured, so no per-target log file should be recorded.
	if len(tsA.logFiles) != 0 || len(tsB.logFiles) != 0 {
		t.Errorf("logFiles should be empty without a log dir, got A=%v B=%v", tsA.logFiles, tsB.logFiles)
	}
}
