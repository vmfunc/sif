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

// serveFingerprint stands up a loopback server returning body at 200 OK and
// returns its host:port for checkSubdomainTakeover to treat as a live subdomain.
func serveFingerprint(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// removed fingerprints that matched generic content rather than a provider's
// unclaimed-domain page must not raise a takeover. the activecampaign string was
// the default lighttpd welcome page, and kajabi/thinkific/tave/teamwork were
// generic "page not found" prose absent from can-i-take-over-xyz.
func TestCheckSubdomainTakeover_GenericFingerprintNotFlagged(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	bogus := map[string]string{
		"lighttpd default page":   `<html><body><img alt="LIGHTTPD - fly light." src="light.png"></body></html>`,
		"generic 404 (kajabi)":    "<html><body>The page you were looking for doesn't exist.</body></html>",
		"generic 404 (thinkific)": "<html><body>You may have mistyped the address or the page may have moved.</body></html>",
		"generic 404 (tave)":      "<html><body>Sorry, this page is no longer available.</body></html>",
		"generic 404 (teamwork)":  "<html><body>Oops - We didn't find your site.</body></html>",
	}
	for name, body := range bogus {
		subdomain := serveFingerprint(t, body)
		vulnerable, service := checkSubdomainTakeover(subdomain, client)
		if vulnerable || service != "" {
			t.Errorf("%s raised a takeover (vulnerable=%v service=%q); it matches generic content, not an unclaimed-domain page", name, vulnerable, service)
		}
	}
}
