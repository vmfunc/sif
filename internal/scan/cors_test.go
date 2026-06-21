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
	"sync/atomic"
	"testing"
	"time"
)

// reflectingCORS echoes the Origin into Access-Control-Allow-Origin and sets
// credentials, the exploitable misconfiguration.
func reflectingCORS() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCORS_ReflectsArbitraryOrigin(t *testing.T) {
	srv := reflectingCORS()
	defer srv.Close()

	result, err := CORS(srv.URL, 5*time.Second, 3, "")
	if err != nil {
		t.Fatalf("CORS: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected cors findings on reflecting server, got %+v", result)
	}

	// the reflecting server echoes every crafted origin with credentials,
	// so each finding should be high severity.
	var sawEvil bool
	for _, f := range result.Findings {
		if f.OriginTested == corsEvilOrigin {
			sawEvil = true
			if !f.AllowCredentials {
				t.Errorf("expected credentials flagged for evil origin, got %+v", f)
			}
			if f.Severity != "high" {
				t.Errorf("expected high severity for reflection+creds, got %s", f.Severity)
			}
		}
	}
	if !sawEvil {
		t.Errorf("expected the sentinel evil origin to be reflected, got %+v", result.Findings)
	}
}

func TestCORS_SeverityWithoutCredentials(t *testing.T) {
	// reflects the origin but never grants credentials - medium, not high.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := CORS(srv.URL, 5*time.Second, 3, "")
	if err != nil {
		t.Fatalf("CORS: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected reflection findings, got %+v", result)
	}
	for _, f := range result.Findings {
		if f.AllowCredentials {
			t.Errorf("did not expect credentials, got %+v", f)
		}
		if f.Severity != "medium" {
			t.Errorf("expected medium severity without creds, got %s", f.Severity)
		}
	}
}

func TestCORS_NoFalsePositiveOnSafeServer(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "ignores origin entirely",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name: "returns its own fixed origin",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name: "plain wildcard, no credentials",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.WriteHeader(http.StatusOK)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			result, err := CORS(srv.URL, 5*time.Second, 3, "")
			if err != nil {
				t.Fatalf("CORS: %v", err)
			}
			if result != nil && len(result.Findings) > 0 {
				t.Errorf("expected no findings on safe server, got %+v", result.Findings)
			}
		})
	}
}

// TestCORS_JudgesRequestedHostNotRedirectTarget pins the redirect behavior: the
// requested host bounces to a reflecting third party, so following the redirect would
// pin that party's misconfig on the target. the counter proves we never left the host.
func TestCORS_JudgesRequestedHostNotRedirectTarget(t *testing.T) {
	var destHits int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&destHits, 1)
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	defer redirector.Close()

	result, err := CORS(redirector.URL, 5*time.Second, 3, "")
	if err != nil {
		t.Fatalf("CORS: %v", err)
	}
	if n := atomic.LoadInt32(&destHits); n != 0 {
		t.Errorf("followed the redirect to the reflecting host %d time(s); cors must stay on the requested host", n)
	}
	if result != nil && len(result.Findings) > 0 {
		t.Errorf("expected no findings: the reflection is on the redirect target, not the requested host; got %+v", result.Findings)
	}
}

func TestCORSResult_ResultType(t *testing.T) {
	r := &CORSResult{}
	if r.ResultType() != "cors" {
		t.Errorf("expected result type 'cors', got %q", r.ResultType())
	}
}
