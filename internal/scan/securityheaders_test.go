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

func buildHeader(kv map[string]string) http.Header {
	h := http.Header{}
	for k, v := range kv {
		h.Set(k, v)
	}
	return h
}

func findFinding(results SecurityHeaderResults, name string) (SecurityHeaderResult, bool) {
	for _, r := range results {
		if r.Header == name {
			return r, true
		}
	}
	return SecurityHeaderResult{}, false
}

func TestGradeSecurityHeaders_MissingOverHTTPS(t *testing.T) {
	results := gradeSecurityHeaders(http.Header{}, true)

	for _, h := range recommendedHeaders {
		f, ok := findFinding(results, h.name)
		if !ok {
			t.Errorf("expected %s to be flagged", h.name)
			continue
		}
		if f.Present {
			t.Errorf("%s should not be marked present", h.name)
		}
		if f.Severity != h.severity {
			t.Errorf("%s severity = %q, want %q", h.name, f.Severity, h.severity)
		}
	}
}

func TestGradeSecurityHeaders_HSTSSkippedOverHTTP(t *testing.T) {
	results := gradeSecurityHeaders(http.Header{}, false)
	if _, ok := findFinding(results, "Strict-Transport-Security"); ok {
		t.Error("HSTS should only be graded for https targets")
	}
}

func TestGradeSecurityHeaders_AllPresent(t *testing.T) {
	h := buildHeader(map[string]string{
		"Strict-Transport-Security":  "max-age=63072000; includeSubDomains",
		"Content-Security-Policy":    "default-src 'self'",
		"X-Frame-Options":            "DENY",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Permissions-Policy":         "geolocation=()",
		"Cross-Origin-Opener-Policy": "same-origin",
	})

	if results := gradeSecurityHeaders(h, true); len(results) != 0 {
		t.Errorf("expected no findings, got %d: %+v", len(results), results)
	}
}

func TestGradeSecurityHeaders_ContentTypeNotNosniff(t *testing.T) {
	h := buildHeader(map[string]string{
		"Strict-Transport-Security":  "max-age=63072000",
		"Content-Security-Policy":    "default-src 'self'",
		"X-Frame-Options":            "DENY",
		"X-Content-Type-Options":     "sniff",
		"Referrer-Policy":            "no-referrer",
		"Permissions-Policy":         "geolocation=()",
		"Cross-Origin-Opener-Policy": "same-origin",
	})

	f, ok := findFinding(gradeSecurityHeaders(h, true), "X-Content-Type-Options")
	if !ok {
		t.Fatal("expected X-Content-Type-Options to be flagged when not nosniff")
	}
	if !f.Present || f.Value != "sniff" {
		t.Errorf("finding = %+v, want present with value sniff", f)
	}
}

func TestGradeSecurityHeaders_WeakHSTS(t *testing.T) {
	// max-age=0 actively disables hsts, so a present header still has to be flagged
	h := buildHeader(map[string]string{"Strict-Transport-Security": "max-age=0"})

	f, ok := findFinding(gradeSecurityHeaders(h, true), "Strict-Transport-Security")
	if !ok {
		t.Fatal("expected a short-lived hsts header to be flagged")
	}
	if !f.Present || f.Severity != "high" {
		t.Errorf("finding = %+v, want present high", f)
	}
}

func TestGradeSecurityHeaders_QuotedHSTS(t *testing.T) {
	// rfc 6797 allows a quoted value; strip the quotes before grading
	tests := []struct {
		name    string
		value   string
		flagged bool
	}{
		{"quoted strong", `max-age="63072000"; includeSubDomains`, false},
		{"quoted weak still flagged", `max-age="0"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := buildHeader(map[string]string{"Strict-Transport-Security": tt.value})
			_, flagged := findFinding(gradeSecurityHeaders(h, true), "Strict-Transport-Security")
			if flagged != tt.flagged {
				t.Errorf("value %q flagged=%v, want %v", tt.value, flagged, tt.flagged)
			}
		})
	}
}

func TestGradeSecurityHeaders_Disclosure(t *testing.T) {
	h := buildHeader(map[string]string{
		"Server":       "Apache/2.4.1 (Ubuntu)",
		"X-Powered-By": "PHP/8.1.2",
	})

	results := gradeSecurityHeaders(h, false)
	for _, name := range []string{"Server", "X-Powered-By"} {
		f, ok := findFinding(results, name)
		if !ok {
			t.Errorf("expected disclosure finding for %s", name)
			continue
		}
		if !f.Present || f.Severity != "low" {
			t.Errorf("%s finding = %+v, want present low", name, f)
		}
	}
}

func TestSecurityHeaders_LiveResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	results, err := SecurityHeaders(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("SecurityHeaders returned error: %v", err)
	}

	if _, ok := findFinding(results, "X-Frame-Options"); ok {
		t.Error("X-Frame-Options was set, should not be flagged")
	}
	if _, ok := findFinding(results, "Content-Security-Policy"); !ok {
		t.Error("expected missing Content-Security-Policy to be flagged")
	}
	if _, ok := findFinding(results, "Server"); !ok {
		t.Error("expected Server disclosure to be flagged")
	}
}
