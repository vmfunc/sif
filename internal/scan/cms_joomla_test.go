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

// a bare "joomla" mention must not match; only the real signals do.
func TestDetectJoomla_Signals(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"generator", `<meta name="generator" content="Joomla! - Open Source Content Management" />`, true},
		{"vendor asset path", `<script src="/media/vendor/joomla-custom-elements/js/joomla-alert.min.js"></script>`, true},
		{"core.js path", `<script src="/media/system/js/core.js"></script>`, true},
		{"bare mention", "we offer managed joomla hosting", false},
		{"capital prose", "migrating from Joomla to something else", false},
		{"tagline prose", "the Joomla! - Open Source Content Management project", false},
		{"plain", "<html><body>hello</body></html>", false},
	}
	for _, c := range cases {
		if got := detectJoomla(c.body); got != c.want {
			t.Errorf("%s: detectJoomla = %v, want %v", c.name, got, c.want)
		}
	}
}

// joomlaServer serves homeBody at / and 404s elsewhere, so the wordpress probe
// cannot claim the host before the Joomla check.
func joomlaServer(t *testing.T, homeBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(homeBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// the capital-J Joomla! generator was missed by the old lowercase check.
func TestCMS_JoomlaGeneratorDetected(t *testing.T) {
	srv := joomlaServer(t, `<meta name="generator" content="Joomla! - Open Source Content Management" />`)
	result, err := CMS(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("CMS: %v", err)
	}
	if result == nil || result.Name != "Joomla" {
		t.Errorf("Joomla generator not detected, got %+v", result)
	}
}

func TestCMS_JoomlaBareMentionNotFlagged(t *testing.T) {
	srv := joomlaServer(t, "<html><body>we offer managed joomla hosting</body></html>")
	result, err := CMS(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("CMS: %v", err)
	}
	if result != nil && result.Name == "Joomla" {
		t.Error("a page merely mentioning joomla was flagged as Joomla")
	}
}
