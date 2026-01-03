/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package frameworks

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestContainsHeader_HeaderName(t *testing.T) {
	headers := http.Header{
		"X-Powered-By": []string{"Express"},
		"Content-Type": []string{"text/html"},
	}

	if !containsHeader(headers, "x-powered-by") {
		t.Error("expected to find x-powered-by in header names")
	}
	if !containsHeader(headers, "X-POWERED-BY") {
		t.Error("expected case-insensitive match for header names")
	}
}

func TestContainsHeader_HeaderValue(t *testing.T) {
	headers := http.Header{
		"X-Powered-By": []string{"Express"},
		"Set-Cookie":   []string{"laravel_session=abc123"},
	}

	if !containsHeader(headers, "express") {
		t.Error("expected to find 'express' in header values")
	}
	if !containsHeader(headers, "laravel_session") {
		t.Error("expected to find 'laravel_session' in header values")
	}
}

func TestContainsHeader_NotFound(t *testing.T) {
	headers := http.Header{
		"Content-Type": []string{"text/html"},
	}

	if containsHeader(headers, "django") {
		t.Error("expected not to find 'django' in headers")
	}
}

func TestExtractVersion_Laravel(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{"Laravel 8.0.0", "8.0.0"},
		{"Laravel v9.52.1", "9.52.1"},
		{"Laravel 10.0", "10.0"},
		{"no version here", "unknown"},
	}

	for _, tt := range tests {
		result := extractVersion(tt.body, "Laravel")
		if result != tt.expected {
			t.Errorf("extractVersion(%q, 'Laravel') = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestExtractVersion_Django(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{"Django 4.2.0", "4.2.0"},
		{"Django/3.2.1", "3.2.1"},
		{"no version", "unknown"},
	}

	for _, tt := range tests {
		result := extractVersion(tt.body, "Django")
		if result != tt.expected {
			t.Errorf("extractVersion(%q, 'Django') = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestExtractVersion_NextJS(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{"Next.js 13.4.0", "13.4.0"},
		{"Next.js/14.0.1", "14.0.1"},
		{"no version", "unknown"},
	}

	for _, tt := range tests {
		result := extractVersion(tt.body, "Next.js")
		if result != tt.expected {
			t.Errorf("extractVersion(%q, 'Next.js') = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestDetectFramework_NextJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Test</title></head>
			<body>
				<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
				<script src="/_next/static/chunks/main.js"></script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Next.js" {
		t.Errorf("expected framework 'Next.js', got '%s'", result.Name)
	}
	if result.Confidence <= 0 {
		t.Error("expected positive confidence")
	}
}

func TestDetectFramework_Express(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body>Hello</body></html>`))
	}))
	defer server.Close()

	result, err := DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Express.js" {
		t.Errorf("expected framework 'Express.js', got '%s'", result.Name)
	}
}

func TestDetectFramework_WordPress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head>
				<link rel="stylesheet" href="/wp-content/themes/theme/style.css">
				<script src="/wp-includes/js/jquery.js"></script>
			</head>
			<body></body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "WordPress" {
		t.Errorf("expected framework 'WordPress', got '%s'", result.Name)
	}
}

func TestDetectFramework_ASPNET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<body>
				<input type="hidden" name="__VIEWSTATE" value="abc123">
				<input type="hidden" name="__EVENTVALIDATION" value="xyz789">
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "ASP.NET" {
		t.Errorf("expected framework 'ASP.NET', got '%s'", result.Name)
	}
}

func TestDetectFramework_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body>Simple page</body></html>`))
	}))
	defer server.Close()

	result, err := DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// result can be nil or have low confidence for unrecognized frameworks
	if result != nil && result.Confidence > 0.6 {
		t.Errorf("expected low confidence or nil result for plain HTML, got %s with %.2f", result.Name, result.Confidence)
	}
}

func TestGetVulnerabilities_Laravel(t *testing.T) {
	cves, suggestions := getVulnerabilities("Laravel", "8.0.0")
	if len(cves) == 0 {
		t.Error("expected CVEs for Laravel 8.0.0")
	}
	if len(suggestions) == 0 {
		t.Error("expected suggestions for Laravel 8.0.0")
	}
}

func TestGetVulnerabilities_NoMatch(t *testing.T) {
	cves, suggestions := getVulnerabilities("Unknown", "1.0.0")
	if len(cves) != 0 {
		t.Error("expected no CVEs for unknown framework")
	}
	if len(suggestions) != 0 {
		t.Error("expected no suggestions for unknown framework")
	}
}

func TestFrameworkResult_Fields(t *testing.T) {
	result := FrameworkResult{
		Name:        "Laravel",
		Version:     "9.0.0",
		Confidence:  0.85,
		CVEs:        []string{"CVE-2021-3129"},
		Suggestions: []string{"Update to latest version"},
	}

	if result.Name != "Laravel" {
		t.Errorf("expected Name 'Laravel', got '%s'", result.Name)
	}
	if result.Version != "9.0.0" {
		t.Errorf("expected Version '9.0.0', got '%s'", result.Version)
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected Confidence 0.85, got %f", result.Confidence)
	}
	if len(result.CVEs) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(result.CVEs))
	}
	if len(result.Suggestions) != 1 {
		t.Errorf("expected 1 suggestion, got %d", len(result.Suggestions))
	}
}
