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

package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPorts_CancelledContextAbortsListDownload proves the ports-list fetch
// honours the caller context. With a slow list endpoint and an already
// cancelled context, Ports must return promptly instead of blocking on the
// http client timeout.
func TestPorts_CancelledContextAbortsListDownload(t *testing.T) {
	release := make(chan struct{})

	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // block until the test releases the handler
		w.WriteHeader(http.StatusOK)
	}))
	// cleanups run LIFO: release the handler first so any in-flight request can
	// drain before Close waits on it, otherwise a request the ctx failed to
	// cancel would deadlock teardown.
	t.Cleanup(list.Close)
	t.Cleanup(func() { close(release) })

	orig := commonPorts
	commonPorts = list.URL
	defer func() { commonPorts = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call so only ctx-awareness can unblock it

	done := make(chan error, 1)
	go func() {
		// a generous client timeout so anything but ctx cancellation would hang
		_, err := Ports(ctx, "common", "tcp://127.0.0.1", 30*time.Second, 1, "")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from cancelled context, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Ports ignored the cancelled context and blocked on the list download")
	}
}
