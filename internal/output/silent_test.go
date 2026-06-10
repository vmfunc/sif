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

package output

import (
	"os"
	"strings"
	"testing"
)

// in silent mode chrome must land on stderr and leave stdout untouched, so a
// piped consumer downstream never sees a banner or log line.
func TestSetSilentRoutesChromeToStderr(t *testing.T) {
	defer SetSilent(false)

	outStr, errStr := captureStdoutStderr(t, func() {
		// SetSilent reads os.Stderr at call time, so swap then set.
		SetSilent(true)
		Info("scanning %s", "example.com")
		Success("done")
	})

	if outStr != "" {
		t.Errorf("silent mode wrote chrome to stdout: %q", outStr)
	}
	if !strings.Contains(errStr, "scanning example.com") {
		t.Errorf("silent chrome missing from stderr: %q", errStr)
	}
}

// the default (non-silent) sink is stdout; flipping silent off must restore it.
func TestSetSilentOffRoutesChromeToStdout(t *testing.T) {
	outStr, errStr := captureStdoutStderr(t, func() {
		SetSilent(false)
		Info("hello")
	})

	if !strings.Contains(outStr, "hello") {
		t.Errorf("non-silent chrome missing from stdout: %q", outStr)
	}
	if strings.Contains(errStr, "hello") {
		t.Errorf("non-silent chrome leaked to stderr: %q", errStr)
	}
}

// Silent() reflects the toggle so callers can gate interactive widgets.
func TestSilentToggle(t *testing.T) {
	defer SetSilent(false)
	SetSilent(true)
	if !Silent() {
		t.Error("Silent() = false after SetSilent(true)")
	}
	SetSilent(false)
	if Silent() {
		t.Error("Silent() = true after SetSilent(false)")
	}
}

// captureStdoutStderr swaps both real streams for pipes, runs fn, and returns
// what landed on each. SetSilent reads os.Stdout/os.Stderr at call time, so the
// swap has to happen before fn flips the sink - fn does that itself.
func captureStdoutStderr(t *testing.T, fn func()) (string, string) {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}

	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	outCh := drain(outR)
	errCh := drain(errR)

	fn()

	os.Stdout, os.Stderr = savedOut, savedErr
	outW.Close()
	errW.Close()
	return <-outCh, <-errCh
}

func drain(r *os.File) <-chan string {
	ch := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, rerr := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if rerr != nil {
				break
			}
		}
		ch <- string(buf)
	}()
	return ch
}
