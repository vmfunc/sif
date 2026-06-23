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

	scripts, err := GetPagesRouterScripts(srv.URL + "/_buildManifest.js")
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
