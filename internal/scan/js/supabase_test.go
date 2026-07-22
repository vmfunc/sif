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

package js

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// supabaseTestRoundTripper redirects *.supabase.co requests to a local
// httptest server, tagging the original host in a header so the fake handler
// can tell projects apart and ScanSupabase's real code path can be exercised.
type supabaseTestRoundTripper struct {
	orig   http.RoundTripper
	target *url.URL
}

func (rt *supabaseTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Host, ".supabase.co") {
		req = req.Clone(req.Context())
		req.Header.Set("X-Test-Orig-Host", req.URL.Host)
		req.URL.Scheme = rt.target.Scheme
		req.URL.Host = rt.target.Host
		req.Host = rt.target.Host
	}
	return rt.orig.RoundTrip(req)
}

// withFakeSupabase points every *.supabase.co request at handler for the
// duration of the test, restoring the real default transport after.
func withFakeSupabase(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	origTransport := http.DefaultTransport
	http.DefaultTransport = &supabaseTestRoundTripper{orig: origTransport, target: target}
	t.Cleanup(func() { http.DefaultTransport = origTransport })
}

// makeJWT builds a header.payload.sig token whose payload base64url-encodes
// refJSON, mirroring what supabase.go's jwtRegex and decode step expect.
func makeJWT(refJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(refJSON))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signaturesignature"))
	return header + "." + payload + "." + sig
}

// projectHandler dispatches requests for a single project. openAPIStatus lets
// a case force the openapi fetch to fail (simulating a 500 or bad upstream).
func projectHandler(openAPIStatus int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/v1/signup":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case "/rest/v1/":
			if openAPIStatus != http.StatusOK {
				w.WriteHeader(openAPIStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"paths":{"/items":{}}}`))
		case "/rest/v1/items":
			w.Header().Set("Content-Range", "0-1/2")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"a":1},{"a":2}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// regression: one project's openapi fetch failing must not discard findings
// already collected for another project in the same scan.
func TestScanSupabase_PartialFailureAccumulates(t *testing.T) {
	var mu sync.Mutex
	good := projectHandler(http.StatusOK)
	bad := projectHandler(http.StatusInternalServerError)

	withFakeSupabase(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Header.Get("X-Test-Orig-Host") {
		case "proja.supabase.co":
			good(w, r)
		case "projb.supabase.co":
			bad(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	jwtA := makeJWT(`{"ref":"proja","role":"anon"}`)
	jwtB := makeJWT(`{"ref":"projb","role":"anon"}`)
	content := `const A = "` + jwtA + `"; const B = "` + jwtB + `";`

	results, err := ScanSupabase(content, "https://example.com/app.js", 5*time.Second)
	if err != nil {
		t.Fatalf("ScanSupabase returned an error, should have skipped the bad project instead: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 surviving result (proja), got %d: %+v", len(results), results)
	}
	if results[0].ProjectId != "proja" {
		t.Fatalf("expected proja to survive, got %q", results[0].ProjectId)
	}
	if len(results[0].Collections) != 1 || results[0].Collections[0].Name != "items" {
		t.Fatalf("expected proja's items collection intact, got %+v", results[0].Collections)
	}
}
