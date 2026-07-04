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

package detectors

import (
	"net/http"
	"testing"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func accHeader(name, value string) http.Header {
	h := http.Header{}
	h.Set(name, value)
	return h
}

func TestDetectorAccuracy_FalsePositives(t *testing.T) {
	cases := []struct {
		name string
		det  fw.Detector
		body string
		h    http.Header
	}{
		{"Express checkout cookie", &expressDetector{}, "", accHeader("Set-Cookie", "express_checkout=1; path=/")},
		{"Flask werkzeug docs link", &flaskDetector{}, "", accHeader("Link", "<https://werkzeug.palletsprojects.com>; rel=help")},
		{"Symfony domain link", &symfonyDetector{}, "", accHeader("Link", "<https://symfony.com/x>; rel=help")},
		{"Shopify cdn link header", &shopifyDetector{}, "", accHeader("Link", "<https://cdn.shopify.com/s/x.js>; rel=preload")},
		{"Shopify cdn body only", &shopifyDetector{}, `<script src="https://cdn.shopify.com/s/buy-button.js"></script>`, http.Header{}},
		{"Spring Boot tutorial prose", &springBootDetector{}, `<article>To fix the Whitelabel Error Page in Spring Boot, add a controller.</article>`, http.Header{}},
		{"Remix audio asset", &remixDetector{}, `<audio src="/audio/track_remix.mp3"></audio>`, http.Header{}},
		{"Django settings tutorial", &djangoDetector{}, `<pre>INSTALLED_APPS = ['django.contrib.admin', 'django.contrib.auth']
from django.core.exceptions import ValidationError</pre>`, http.Header{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if conf, _ := c.det.Detect(c.body, c.h); conf > 0.5 {
				t.Errorf("false positive: confidence = %.3f, want <= 0.5", conf)
			}
		})
	}
}

func TestDetectorAccuracy_TruePositives(t *testing.T) {
	cases := []struct {
		name string
		det  fw.Detector
		body string
		h    http.Header
	}{
		{"Express powered-by", &expressDetector{}, "", accHeader("X-Powered-By", "Express")},
		{"Flask werkzeug server", &flaskDetector{}, "", accHeader("Server", "Werkzeug/2.3.0 Python/3.11")},
		{"Symfony debug token", &symfonyDetector{}, "", accHeader("X-Debug-Token", "a1b2c3")},
		{"Shopify storefront header", &shopifyDetector{}, "", accHeader("X-Shopify-Stage", "production")},
		{"Spring Boot whitelabel page", &springBootDetector{}, `<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p><div>There was an unexpected error (type=Not Found, status=404).</div></body></html>`, http.Header{}},
		{"Remix context", &remixDetector{}, `<script>window.__remixContext = {"state":{}};</script>`, http.Header{}},
		{"Django admin login form", &djangoDetector{}, `<html><head><link rel="stylesheet" href="/static/admin/css/login.css"></head><body><form><input type="hidden" name="csrfmiddlewaretoken" value="abc"></form></body></html>`, accHeader("Set-Cookie", "csrftoken=xyz; Path=/")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if conf, _ := c.det.Detect(c.body, c.h); conf <= 0.5 {
				t.Errorf("missed: confidence = %.3f, want > 0.5", conf)
			}
		})
	}
}

func TestDetectorAccuracy_RemovedDetectors(t *testing.T) {
	for _, name := range []string{"Gin", "FastAPI"} {
		if _, ok := fw.GetDetector(name); ok {
			t.Errorf("%s detector should have been removed (no clean passive signal)", name)
		}
	}
}
