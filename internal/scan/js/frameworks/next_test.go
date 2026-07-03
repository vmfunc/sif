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

package frameworks

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetPagesRouterScriptsReadsPastLongLine(t *testing.T) {
	// a manifest token past bufio's 64k cap must not truncate the read and
	// drop the script references that follow it.
	huge := strings.Repeat("x", bufio.MaxScanTokenSize+1)
	manifest := `["early.js"]` + "\n" + huge + "\n" + `["late.js"]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(manifest))
	}))
	defer srv.Close()

	scripts, err := GetPagesRouterScripts(srv.URL+"/_buildManifest.js", 5*time.Second)
	if err != nil {
		t.Fatalf("GetPagesRouterScripts: %v", err)
	}

	found := func(needle string) bool {
		for _, s := range scripts {
			if strings.Contains(s, needle) {
				return true
			}
		}
		return false
	}
	if !found("early.js") || !found("late.js") {
		t.Errorf("want both early.js and late.js, got %v", scripts)
	}
}

func TestGetPagesRouterScriptsHonorsTimeout(t *testing.T) {
	// a slow manifest host must not hang the scan: the fetch has to give up
	// once the caller's timeout elapses instead of reading with no deadline.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Write([]byte(`["late.js"]`))
	}))
	defer srv.Close()
	defer close(release)

	done := make(chan error, 1)
	go func() {
		_, err := GetPagesRouterScripts(srv.URL+"/_buildManifest.js", 100*time.Millisecond)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error from the slow manifest host, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetPagesRouterScripts did not honor the timeout and hung")
	}
}
