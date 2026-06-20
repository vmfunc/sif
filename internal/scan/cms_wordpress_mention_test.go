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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// notFound serves 404 for every path so the file probe never fires; only the
// passed homepage body decides the result.
func notFound(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// a page that only mentions wordpress in prose (no asset paths) is not running it.
func TestDetectWordPress_BareMentionNotFlagged(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	body := "<html><body>we offer managed wordpress hosting</body></html>"
	if detectWordPress(notFound(t), client, body) {
		t.Error("a page merely mentioning wordpress was flagged as WordPress")
	}
}

// a real wordpress homepage references wp-content asset paths.
func TestDetectWordPress_AssetPathsDetected(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	body := `<link href="/wp-content/themes/x/style.css">`
	if !detectWordPress(notFound(t), client, body) {
		t.Error("wp-content asset path should be detected as WordPress")
	}
}
