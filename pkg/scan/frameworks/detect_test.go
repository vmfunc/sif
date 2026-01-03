/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
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
		Name:              "Laravel",
		Version:           "9.0.0",
		Confidence:        0.85,
		VersionConfidence: 0.9,
		CVEs:              []string{"CVE-2021-3129"},
		Suggestions:       []string{"Update to latest version"},
		RiskLevel:         "critical",
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
	if result.VersionConfidence != 0.9 {
		t.Errorf("expected VersionConfidence 0.9, got %f", result.VersionConfidence)
	}
	if len(result.CVEs) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(result.CVEs))
	}
	if len(result.Suggestions) != 1 {
		t.Errorf("expected 1 suggestion, got %d", len(result.Suggestions))
	}
	if result.RiskLevel != "critical" {
		t.Errorf("expected RiskLevel 'critical', got '%s'", result.RiskLevel)
	}
}

func TestExtractVersionWithConfidence(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		framework string
		wantVer   string
		minConf   float32
	}{
		{"Laravel explicit", "Laravel 8.0.0", "Laravel", "8.0.0", 0.8},
		{"Angular ng-version", `<html ng-version="14.2.0">`, "Angular", "14.2.0", 0.9},
		{"WordPress generator", `<meta name="generator" content="WordPress 6.1.0">`, "WordPress", "6.1.0", 0.9},
		{"Vue CDN", "vue@3.2.0/dist", "Vue.js", "3.2.0", 0.7},
		{"No version", "Hello World", "Laravel", "unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVersionOptimized(tt.body, tt.framework)
			if result.Version != tt.wantVer {
				t.Errorf("extractVersionOptimized() version = %q, want %q", result.Version, tt.wantVer)
			}
			if result.Confidence < tt.minConf {
				t.Errorf("extractVersionOptimized() confidence = %f, want >= %f", result.Confidence, tt.minConf)
			}
		})
	}
}

func TestGetRiskLevel(t *testing.T) {
	tests := []struct {
		name     string
		cves     []string
		expected string
	}{
		{"no CVEs", []string{}, "low"},
		{"critical", []string{"CVE-2021-3129 (critical)"}, "critical"},
		{"high", []string{"CVE-2023-22795 (high)"}, "high"},
		{"medium", []string{"CVE-2023-46298 (medium)"}, "medium"},
		{"mixed - critical wins", []string{"CVE-2023-1 (medium)", "CVE-2021-3129 (critical)"}, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRiskLevel(tt.cves)
			if result != tt.expected {
				t.Errorf("getRiskLevel() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetVulnerabilities_Django(t *testing.T) {
	cves, suggestions := getVulnerabilities("Django", "3.2.0")
	if len(cves) == 0 {
		t.Error("expected CVEs for Django 3.2.0")
	}
	if len(suggestions) == 0 {
		t.Error("expected suggestions for Django 3.2.0")
	}
}

func TestGetVulnerabilities_Spring(t *testing.T) {
	cves, suggestions := getVulnerabilities("Spring", "5.3.0")
	if len(cves) == 0 {
		t.Error("expected CVEs for Spring 5.3.0 (Spring4Shell)")
	}
	found := false
	for _, cve := range cves {
		if cve == "CVE-2022-22965 (critical)" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Spring4Shell CVE-2022-22965")
	}
	if len(suggestions) == 0 {
		t.Error("expected suggestions for Spring 5.3.0")
	}
}

func TestDetectFramework_Vue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Vue App</title></head>
			<body>
				<div id="app" data-v-12345>
					<div v-cloak>Loading...</div>
				</div>
				<script src="https://unpkg.com/vue@3.2.0/dist/vue.global.js"></script>
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
	if result.Name != "Vue.js" {
		t.Errorf("expected framework 'Vue.js', got '%s'", result.Name)
	}
}

func TestDetectFramework_Angular(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html ng-version="15.0.0">
			<head><title>Angular App</title></head>
			<body>
				<app-root _nghost-abc-c123 _ngcontent-abc-c123></app-root>
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
	if result.Name != "Angular" {
		t.Errorf("expected framework 'Angular', got '%s'", result.Name)
	}
}

func TestDetectFramework_React(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>React App</title></head>
			<body>
				<div id="root" data-reactroot="">Content</div>
				<script src="/static/js/react-dom.production.min.js"></script>
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
	if result.Name != "React" {
		t.Errorf("expected framework 'React', got '%s'", result.Name)
	}
}

func TestDetectFramework_Svelte(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Svelte App</title></head>
			<body>
				<div id="app" class="__svelte-123">
					<span class="svelte-abc123">Content</span>
				</div>
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
	if result.Name != "Svelte" {
		t.Errorf("expected framework 'Svelte', got '%s'", result.Name)
	}
}

func TestDetectFramework_Joomla(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta name="generator" content="Joomla! - Open Source Content Management">
				<script src="/media/jui/js/jquery.js"></script>
			</head>
			<body>
				<div class="Joomla">Content</div>
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
	if result.Name != "Joomla" {
		t.Errorf("expected framework 'Joomla', got '%s'", result.Name)
	}
}

func TestCVEEntry_Fields(t *testing.T) {
	entry := CVEEntry{
		CVE:              "CVE-2021-3129",
		AffectedVersions: []string{"8.0.0", "8.0.1"},
		FixedVersion:     "8.4.2",
		Severity:         "critical",
		Description:      "RCE vulnerability",
		Recommendations:  []string{"Update immediately"},
	}

	if entry.CVE != "CVE-2021-3129" {
		t.Errorf("expected CVE 'CVE-2021-3129', got '%s'", entry.CVE)
	}
	if len(entry.AffectedVersions) != 2 {
		t.Errorf("expected 2 affected versions, got %d", len(entry.AffectedVersions))
	}
	if entry.Severity != "critical" {
		t.Errorf("expected Severity 'critical', got '%s'", entry.Severity)
	}
}
