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

// a soft-404 (200 for every path) is not wordpress; a bare 200 on the probe must
// not flag without a marker in the body.
func TestDetectWordPress_SoftFourOhFourNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>welcome to my static site</body></html>"))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	if detectWordPress(srv.URL, client, "<html><body>welcome to my static site</body></html>") {
		t.Error("soft-404 site (200 for every path, no wordpress markers) wrongly detected as WordPress")
	}
}

// a catch-all 302 is followed to a non-wordpress 200; without a marker it must
// not flag.
func TestDetectWordPress_CatchAllRedirectNotFlagged(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/home", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>landing page</body></html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	if detectWordPress(srv.URL, client, "<html><body>landing page</body></html>") {
		t.Error("catch-all 302 redirect to a non-wordpress homepage wrongly detected as WordPress")
	}
}

// a real wp-login.php response references wp-includes assets even when the
// homepage hides its wordpress markers, so the file probe should still detect it.
func TestDetectWordPress_LoginPageProbeDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			_, _ = w.Write([]byte(`<link rel="stylesheet" href="/wp-includes/css/dashicons.min.css">`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	if !detectWordPress(srv.URL, client, "<html><body>custom theme, no markers</body></html>") {
		t.Error("wp-login.php referencing wp-includes assets should be detected as WordPress")
	}
}

// end-to-end through CMS() with the real redirect-following client: a soft-404
// host must not be reported as a CMS.
func TestCMS_SoftFourOhFourNotWordPress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>welcome to my static site</body></html>"))
	}))
	defer srv.Close()

	result, err := CMS(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("CMS: %v", err)
	}
	if result != nil {
		t.Errorf("soft-404 host wrongly classified as CMS %q", result.Name)
	}
}

// a probe that hits a redirect loop errors out in the client; it must be skipped
// gracefully, never panicking or counting as a detection.
func TestDetectWordPress_RedirectLoopHandled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	if detectWordPress(srv.URL, client, "<html><body>no markers</body></html>") {
		t.Error("redirect loop wrongly detected as WordPress")
	}
}
