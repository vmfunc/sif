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

package frameworks_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vmfunc/sif/internal/scan/frameworks"
	_ "github.com/vmfunc/sif/internal/scan/frameworks/detectors"
)

// DetectFramework reports a single argmax across one registry, so a detector
// that clears its own bar on one ubiquitous marker outranks a real framework
// that only landed its primary signal. these pin the two cases that bit.

// a real wordpress site behind cloudflare: the app framework must win, not the edge.
func TestHostingDoesNotShadowRealFramework(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("CF-RAY", "8a1b2c3d4e5f6789-LAX")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<script src="/wp-includes/js/jquery/jquery.min.js"></script>
<link rel="https://api.w.org/" href="/wp-json/">
</head><body>hello</body></html>`))
	}))
	defer srv.Close()

	res, err := frameworks.DetectFramework(srv.URL, 5e9, "")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if res == nil {
		t.Fatal("no framework detected")
	}
	t.Logf("winner=%q confidence=%.4f", res.Name, res.Confidence)
	if res.Name != "WordPress" {
		t.Errorf("edge/cdn shadowed the real framework: got %q (%.4f), want WordPress", res.Name, res.Confidence)
	}
}

// a django app that ships jquery, as a huge share of them do. jquery is a
// library on most of the web, so it must not outrank the app framework.
func TestJQueryDoesNotShadowRealFramework(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "csrftoken=abc123; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head>
<script src="/static/js/jquery.min.js"></script>
<script src="/static/js/jquery-3.6.0.js"></script>
</head><body><form><input name="csrfmiddlewaretoken" value="x"></form></body></html>`))
	}))
	defer srv.Close()

	res, err := frameworks.DetectFramework(srv.URL, 5e9, "")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if res == nil {
		t.Fatal("no framework detected")
	}
	t.Logf("winner=%q confidence=%.4f", res.Name, res.Confidence)
	if res.Name == "jQuery" {
		t.Errorf("jquery shadowed the real framework (%.4f)", res.Confidence)
	}
}
