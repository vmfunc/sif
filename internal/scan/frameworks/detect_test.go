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
	"time"

	"github.com/vmfunc/sif/internal/scan/frameworks"
	// Import detectors to register them via init()
	_ "github.com/vmfunc/sif/internal/scan/frameworks/detectors"
)

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
		result := frameworks.ExtractVersionOptimized(tt.body, "Laravel").Version
		if result != tt.expected {
			t.Errorf("ExtractVersionOptimized(%q, 'Laravel') = %q, want %q", tt.body, result, tt.expected)
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
		result := frameworks.ExtractVersionOptimized(tt.body, "Django").Version
		if result != tt.expected {
			t.Errorf("ExtractVersionOptimized(%q, 'Django') = %q, want %q", tt.body, result, tt.expected)
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
		result := frameworks.ExtractVersionOptimized(tt.body, "Next.js").Version
		if result != tt.expected {
			t.Errorf("ExtractVersionOptimized(%q, 'Next.js') = %q, want %q", tt.body, result, tt.expected)
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

func TestDetectFramework_ASPNETPoweredByHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-AspNetMvc-Version", "5.2")
		w.Header().Set("X-Powered-By", "ASP.NET")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><a href="/home/index.aspx">home</a></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// result can be nil or have low confidence for unrecognized frameworks
	if result != nil && result.Confidence > 0.6 {
		t.Errorf("expected low confidence or nil result for plain HTML, got %s with %.2f", result.Name, result.Confidence)
	}
}

func TestFrameworkResult_Fields(t *testing.T) {
	result := frameworks.NewFrameworkResult("Laravel", "9.0.0", 0.85, 0.9)
	result.WithVulnerabilities([]string{"CVE-2021-3129"}, []string{"Update to latest version"})

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
			result := frameworks.ExtractVersionOptimized(tt.body, tt.framework)
			if result.Version != tt.wantVer {
				t.Errorf("ExtractVersionOptimized() version = %q, want %q", result.Version, tt.wantVer)
			}
			if result.Confidence < tt.minConf {
				t.Errorf("ExtractVersionOptimized() confidence = %f, want >= %f", result.Confidence, tt.minConf)
			}
		})
	}
}

func TestDetermineRiskLevel(t *testing.T) {
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
			// Test via WithVulnerabilities which uses determineRiskLevel internally
			result := frameworks.NewFrameworkResult("Test", "1.0", 0.5, 0.5)
			result.WithVulnerabilities(tt.cves, nil)
			if result.RiskLevel != tt.expected {
				t.Errorf("determineRiskLevel() = %q, want %q", result.RiskLevel, tt.expected)
			}
		})
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
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

func TestDetectFramework_AdonisJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "adonis-session=s%3Aabc.def; Path=/; HttpOnly")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body>Welcome</body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "AdonisJS" {
		t.Errorf("expected framework 'AdonisJS', got '%s'", result.Name)
	}
}

func TestDetectFramework_AdonisFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head>
				<title>Adonis Cosmetics</title>
				<link rel="stylesheet" href="/assets/adonis-theme.css">
			</head>
			<body class="adonis-store">
				<h1>Adonis Cosmetics</h1>
				<a href="/adonis/collections">Shop the adonis collection</a>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "AdonisJS" {
		t.Errorf("false positive: plain page mentioning 'Adonis' detected as AdonisJS (%.2f)", result.Confidence)
	}
}

func TestDetectFramework_Phoenix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Phoenix App</title></head>
			<body>
				<div data-phx-main data-phx-session="abc" data-phx-static="def" id="phx-F1a2B3">
					<span>Content</span>
				</div>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Phoenix" {
		t.Errorf("expected framework 'Phoenix', got '%s'", result.Name)
	}
}

func TestDetectFramework_PhoenixFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Phoenix AZ Roofing</title></head>
			<body class="phx-page">
				<nav class="phx-nav"><a href="/">Phoenix Home</a></nav>
				<section class="phx-hero">Serving Phoenix, Arizona since 1998.</section>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Phoenix" {
		t.Errorf("false positive: phx- CSS class page detected as Phoenix (%.2f)", result.Confidence)
	}
}

func TestDetectFramework_Astro(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html data-astro-transition="forward">
			<head>
				<meta name="generator" content="Astro v5.16.6">
				<link rel="stylesheet" href="/_astro/index.abc123.css">
			</head>
			<body>
				<astro-island data-astro-cid-xyz789 data-astro-source-file="src/components/Counter.astro">
					<div>Content</div>
				</astro-island>
				<nav>
					<a href="/about" data-astro-history="push">About</a>
					<a href="/external" data-astro-reload>External</a>
				</nav>
				<script src="/_astro/hoisted.def456.js"></script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Astro" {
		t.Errorf("expected framework 'Astro', got '%s'", result.Name)
	}
}

func TestDetectFramework_Ghost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta name="generator" content="Ghost 6.46">
			</head>
			<body>Content</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Ghost" {
		t.Errorf("expected framework 'Ghost', got '%s'", result.Name)
	}
}

func TestDetectFramework_GhostButtonNoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<body>
				<a class="ghost-button" href="/signup">Sign up</a>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Ghost" {
		t.Errorf("expected no Ghost detection for a ghost-button page, got confidence %.2f", result.Confidence)
	}
}

func TestDetectFramework_GhostAPIPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<body>
				<script src="/ghost/api/content/posts/?key=abc"></script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Ghost" {
		t.Errorf("expected framework 'Ghost', got '%s'", result.Name)
	}
}

func TestExtractVersion_Astro(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{`<meta name="generator" content="Astro v4.2.0">`, "4.2.0"},
		{`<meta name="generator" content="Astro 3.5.1">`, "3.5.1"},
		{"Astro 4.0.0", "4.0.0"},
		{"Astro/3.2.1", "3.2.1"},
		{`"astro": "^4.1.0"`, "4.1.0"},
		{`"astro": "~3.0.5"`, "3.0.5"},
		{"no version", "unknown"},
	}

	for _, tt := range tests {
		result := frameworks.ExtractVersionOptimized(tt.body, "Astro").Version
		if result != tt.expected {
			t.Errorf("ExtractVersionOptimized(%q, 'Astro') = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestCVEEntry_Fields(t *testing.T) {
	entry := frameworks.CVEEntry{
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

func TestDetectorRegistry(t *testing.T) {
	detectors := frameworks.GetDetectors()
	if len(detectors) == 0 {
		t.Fatal("expected registered detectors, got none")
	}

	// Check that expected detectors are registered: a spot-check of the
	// originals plus every detector added to the backend, cms, and meta sets.
	expectedDetectors := []string{
		"Laravel", "Django", "React", "Vue.js", "Angular", "Next.js", "WordPress", "Astro",
		"Tornado", "CherryPy", "Play Framework", "Sails.js", "Beego",
		"JavaServer Faces", "Google Web Toolkit", "Vaadin", "ColdFusion",
		"TYPO3", "Contao", "Wix", "Webflow", "HubSpot", "PrestaShop",
		"Sitecore", "OpenCart", "DotNetNuke", "Liferay",
		"Hugo", "Jekyll", "Docusaurus", "MkDocs",
		"Alpine.js", "Qwik", "jQuery",
		"Squarespace", "WooCommerce", "Craft CMS", "Concrete CMS", "Bitrix", "Blogger",
		"Eleventy", "Hexo", "VuePress", "Sphinx",
		"MediaWiki", "Discourse", "XenForo", "Moodle", "Plone", "Grav",
		"Textpattern", "October CMS", "Statamic", "Livewire",
		"Stimulus", "Turbo", "Knockout.js", "Unpoly", "Flarum", "NodeBB",
		"XWiki", "Bolt CMS", "Nikola", "Publii", "ExpressionEngine",
		"Vercel", "Netlify", "GitHub Pages", "Cloudflare",
		"Amazon CloudFront", "Akamai", "Fly.io", "Amazon S3",
	}
	for _, name := range expectedDetectors {
		if _, ok := frameworks.GetDetector(name); !ok {
			t.Errorf("expected detector %q to be registered", name)
		}
	}
}

func TestExtractVersion_Htmx(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{`<script src="https://unpkg.com/htmx.org@1.9.10"></script>`, "1.9.10"},
		{`https://cdn.jsdelivr.net/npm/htmx@2.0.3/dist/htmx.min.js`, "2.0.3"},
		{`"htmx.org": "^1.9.12"`, "1.9.12"},
		{"no version", "unknown"},
	}

	for _, tt := range tests {
		result := frameworks.ExtractVersionOptimized(tt.body, "htmx").Version
		if result != tt.expected {
			t.Errorf("ExtractVersionOptimized(%q, 'htmx') = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestDetectFramework_Htmx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><script src="https://unpkg.com/htmx.org@1.9.10"></script></head>
			<body>
				<button hx-get="/clicked" hx-target="#out" hx-swap="outerHTML">Click</button>
				<form hx-post="/submit" hx-boost="true"></form>
				<div id="out"></div>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "htmx" {
		t.Errorf("expected framework 'htmx', got '%s'", result.Name)
	}
	if result.Version != "1.9.10" {
		t.Errorf("expected version '1.9.10', got '%s'", result.Version)
	}
}

func TestDetectFramework_MeteorFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>a meteor shower lit the sky while
		meteorology students tracked the meteorite.</p></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Meteor" {
		t.Errorf("false positive: detected Meteor (confidence %.2f) on prose about meteors", result.Confidence)
	}
}

func TestDetectFramework_Meteor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head>
		<script>__meteor_runtime_config__ = JSON.parse(decodeURIComponent("%7B%7D"));</script>
		</head><body><div id="app"></div></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Name != "Meteor" {
		t.Errorf("expected framework 'Meteor', got '%v'", result)
	}
}

func TestDetectFramework_BackboneFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>our team is the backbone of the
		company, the backbone network that keeps everything running.</p></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Backbone.js" {
		t.Errorf("false positive: detected Backbone.js (confidence %.2f) on prose about backbones", result.Confidence)
	}
}

func TestDetectFramework_Backbone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><script src="/js/backbone.js"></script></head>
		<body><script>var AppView = Backbone.View.extend({});</script></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Name != "Backbone.js" {
		t.Errorf("expected framework 'Backbone.js', got '%v'", result)
	}
}

func TestDetectFramework_CakePHPFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// a Q&A/listicle page that merely names the framework, as on the live
		// stackoverflow homepage that the bare body substring used to misfire on
		w.Write([]byte(`<!DOCTYPE html><html><body><a href="/questions/tagged/cakephp">cakephp</a></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "CakePHP" {
		t.Errorf("false positive: detected CakePHP (confidence %.2f) on prose naming cakephp", result.Confidence)
	}
}

func TestDetectFramework_CakePHP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "CAKEPHP=abc123; path=/")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body>Home</body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Name != "CakePHP" {
		t.Errorf("expected framework 'CakePHP', got '%v'", result)
	}
}

func TestDetectFramework_SvelteFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>the model cut a svelte figure on
		the runway.</p></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Svelte" {
		t.Errorf("false positive: detected Svelte (confidence %.2f) on prose with 'svelte'", result.Confidence)
	}
}

func TestDetectFramework_StrapiFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// prose naming the CMS plus a plain /api/ path: neither is the powered-by header
		w.Write([]byte(`<!DOCTYPE html><html><body><p>built with Strapi</p><script>fetch("/api/v1/users")</script></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Strapi" {
		t.Errorf("false positive: detected Strapi (confidence %.2f) on prose naming strapi", result.Confidence)
	}
}

func TestDetectFramework_Strapi(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the default poweredBy middleware sets this header on every response
		w.Header().Set("X-Powered-By", "Strapi <strapi.io>")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><div>welcome</div></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Name != "Strapi" {
		t.Errorf("expected framework 'Strapi', got '%v'", result)
	}
}

func TestDetectFramework_Ember(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Ember App</title></head>
		<body class="ember-application"><div id="ember123" class="ember-view">Content</div>
		<script src="/assets/vendor.js"></script></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Name != "Ember.js" {
		t.Errorf("expected framework 'Ember.js', got '%v'", result)
	}
}

func TestDetectFramework_EmberFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Day of the Dead</title></head>
		<body><p>a celebratory holiday to remember the dead; families remember departed
		members every November and September.</p></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Ember.js" {
		t.Errorf("false positive: detected Ember.js (confidence %.2f) on prose with 'remember'", result.Confidence)
	}
}

func TestDetectFramework_Shopify(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Powered-By", "Shopify")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><link rel="stylesheet" href="https://cdn.shopify.com/s/files/1/theme.css"></head>
			<body>
				<div id="shopify-section-header" class="shopify-section">Store</div>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Shopify" {
		t.Errorf("expected framework 'Shopify', got '%s'", result.Name)
	}
}

func TestDetectFramework_ShopifyFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>10 Best Shopify Alternatives in 2026</title></head>
			<body>
				<h1>Is Shopify Right For You?</h1>
				<p>We compare Shopify with other e-commerce platforms.</p>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Shopify" {
		t.Errorf("false positive: article mentioning Shopify detected as Shopify (%.2f)", result.Confidence)
	}
}

func TestDetectFramework_SpringBoot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><h1>Whitelabel Error Page</h1>` +
			`<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>` +
			`<div>There was an unexpected error (type=Internal Server Error, status=500).</div>` +
			`</body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "Spring Boot" {
		t.Errorf("expected framework 'Spring Boot', got '%s'", result.Name)
	}
}

func TestDetectFramework_SpringBootFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<body>
				<h1>Getting started with spring-boot</h1>
				<p>Add spring-boot-starter-web to your pom.xml and run the app.</p>
				<a href="https://spring.io/projects/spring-boot">spring.io</a>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "Spring Boot" {
		t.Errorf("expected no Spring Boot match for prose mentioning it, got %.2f confidence", result.Confidence)
	}
}

func TestDetectFramework_CodeIgniter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "ci_session=a1b2c3d4e5; path=/; HttpOnly")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><h1>My Shop</h1></body></html>`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Name != "CodeIgniter" {
		t.Errorf("expected framework 'CodeIgniter', got '%s'", result.Name)
	}
}

func TestDetectFramework_CodeIgniterFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<body>
				<h1>Best PHP frameworks in 2026</h1>
				<p>Laravel and codeigniter both ship a router and an ORM.</p>
				<a href="https://codeigniter.com">codeigniter.com</a>
				<pre>composer create-project codeigniter4/appstarter</pre>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	result, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil && result.Name == "CodeIgniter" {
		t.Errorf("expected no CodeIgniter match for prose mentioning it, got %.2f confidence", result.Confidence)
	}
}
