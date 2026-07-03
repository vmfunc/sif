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
	"strings"
	"testing"
	"time"
)

// the ghost and pantheon unclaimed-domain pages, verified live against
// <random>.ghost.io and <random>.pantheonsite.io (both 404). the old fingerprints
// keyed on each platform's earlier takeover copy, so a real takeover went undetected.
func TestCheckSubdomainTakeover_CurrentUnclaimedPageDetected(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	cases := []struct{ service, body string }{
		{"Ghost", "<html><body>Failed to resolve DNS path for this host</body></html>"},
		{"Pantheon", "<html><head><title>404 - Unknown site</title></head><body>404 Unknown site</body></html>"},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(c.body))
		}))
		host := strings.TrimPrefix(srv.URL, "http://")
		vulnerable, service, _ := checkSubdomainTakeover(host, client)
		srv.Close()
		if !vulnerable || service != c.service {
			t.Errorf("%s unclaimed page not detected, got vulnerable=%v service=%q", c.service, vulnerable, service)
		}
	}
}

// the retired fingerprints were each platform's older takeover copy, gone from
// the live pages; a page still carrying them must no longer raise a takeover.
func TestCheckSubdomainTakeover_StaleFingerprintRetired(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	stale := []string{
		"The thing you were looking for is no longer here, or never was",
		"The gods are wise, but do not know of the site which you seek.",
	}
	for _, body := range stale {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
		}))
		host := strings.TrimPrefix(srv.URL, "http://")
		vulnerable, service, _ := checkSubdomainTakeover(host, client)
		srv.Close()
		if vulnerable || service != "" {
			t.Errorf("stale fingerprint still raised a takeover (service %q) for body %q", service, body)
		}
	}
}
