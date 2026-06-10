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

func TestRedirect_HeaderLocation(t *testing.T) {
	// echoes the "next" param straight into Location, the textbook open redirect.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := Redirect(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("Redirect: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected open redirect findings, got %+v", result)
	}

	var sawHeader bool
	for _, f := range result.Findings {
		if f.Parameter == "next" && f.Via == "header" {
			sawHeader = true
		}
	}
	if !sawHeader {
		t.Errorf("expected a header redirect via 'next', got %+v", result.Findings)
	}
}

func TestRedirect_MetaRefresh(t *testing.T) {
	// body-based redirect: a meta refresh pointing at the injected url.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if dest != "" {
			//nolint:gosec // deliberate open-redirect fixture for the probe under test
			w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0;url=` + dest + `"></head></html>`))
			return
		}
		w.Write([]byte("<html>home</html>"))
	}))
	defer srv.Close()

	result, err := Redirect(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("Redirect: %v", err)
	}
	if result == nil {
		t.Fatalf("expected meta-refresh findings, got nil")
	}
	var sawMeta bool
	for _, f := range result.Findings {
		if f.Via == "meta-refresh" {
			sawMeta = true
		}
	}
	if !sawMeta {
		t.Errorf("expected a meta-refresh redirect finding, got %+v", result.Findings)
	}
}

func TestRedirect_NoFalsePositive(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "never redirects",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html>home</html>"))
			},
		},
		{
			name: "only redirects to a fixed safe path",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				// ignores the param, always sends users to its own login page.
				w.Header().Set("Location", "/login")
				w.WriteHeader(http.StatusFound)
			},
		},
		{
			name: "reflects param into body but not as a redirect",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// the value lands in plain text, no meta/js redirect mechanism.
				//nolint:gosec // intentional reflection fixture; asserts no false positive
				w.Write([]byte("<p>you searched for " + r.URL.Query().Get("next") + "</p>"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			result, err := Redirect(srv.URL, 5*time.Second, 4, "")
			if err != nil {
				t.Fatalf("Redirect: %v", err)
			}
			if result != nil && len(result.Findings) > 0 {
				t.Errorf("expected no findings, got %+v", result.Findings)
			}
		})
	}
}

func TestPointsAtSentinel(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     bool
	}{
		{"absolute https", "https://" + redirectSentinel + "/path", true},
		{"scheme-relative", "//" + redirectSentinel, true},
		{"backslash trick", "/\\" + redirectSentinel, true},
		{"with port", "https://" + redirectSentinel + ":443/", true},
		{"empty", "", false},
		{"same-site path", "/dashboard", false},
		{"sentinel only in path", "https://safe.example.com/" + redirectSentinel, false},
		{"sentinel only in query", "https://safe.example.com/?to=" + redirectSentinel, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pointsAtSentinel(tt.location); got != tt.want {
				t.Errorf("pointsAtSentinel(%q) = %v, want %v", tt.location, got, tt.want)
			}
		})
	}
}

func TestRedirectResult_ResultType(t *testing.T) {
	r := &RedirectResult{}
	if r.ResultType() != "redirect" {
		t.Errorf("expected result type 'redirect', got %q", r.ResultType())
	}
}
