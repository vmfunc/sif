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

// header cases mirror live Drupal 8-11 (acquia, georgia, london): the X-Drupal-*
// and X-Generator headers tell even when the body has no marker.
func TestDetectDrupal_ModernSignals(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		body   string
		want   bool
	}{
		{"x-generator drupal 10", http.Header{"X-Generator": {"Drupal 10 (https://www.drupal.org)"}}, "", true},
		{"x-drupal-cache miss", http.Header{"X-Drupal-Cache": {"MISS"}}, "", true},
		{"x-drupal-dynamic-cache", http.Header{"X-Drupal-Dynamic-Cache": {"HIT"}}, "", true},
		{"drupalSettings body (8+)", http.Header{}, `<script>window.drupalSettings = {};</script>`, true},
		{"Drupal.settings body (7)", http.Header{}, `<script>Drupal.settings = {};</script>`, true},
		{"plain page", http.Header{"Server": {"nginx"}}, "<html><body>hello</body></html>", false},
		{"x-generator wordpress", http.Header{"X-Generator": {"WordPress 6.5"}}, "", false},
		{"bare drupal prose", http.Header{}, "we migrated off Drupal CMS last year", false},
	}
	for _, c := range cases {
		if got := detectDrupal(c.header, c.body); got != c.want {
			t.Errorf("%s: detectDrupal = %v, want %v", c.name, got, c.want)
		}
	}
}

// end-to-end: a modern Drupal whose only tell is X-Drupal-Dynamic-Cache (the live
// london.gov.uk case) must be detected.
func TestCMS_ModernDrupalDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// a real Drupal site has no wordpress paths; 404 them so the wordpress
		// probe does not claim the host before the Drupal check runs.
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Drupal-Dynamic-Cache", "MISS")
		_, _ = w.Write([]byte("<html><body>news and updates</body></html>"))
	}))
	defer srv.Close()

	result, err := CMS(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("CMS: %v", err)
	}
	if result == nil || result.Name != "Drupal" {
		t.Errorf("modern Drupal (X-Drupal-Dynamic-Cache) not detected, got %+v", result)
	}
}
