package scan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckSubdomainTakeover_GitHubPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	host := strings.TrimPrefix(server.URL, "http://")

	vulnerable, service := checkSubdomainTakeover(host, client)

	if !vulnerable {
		t.Error("expected subdomain to be vulnerable")
	}
	if service != "GitHub Pages" {
		t.Errorf("expected service 'GitHub Pages', got '%s'", service)
	}
}

func TestCheckSubdomainTakeover_NotVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Normal website content</body></html>"))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	host := strings.TrimPrefix(server.URL, "http://")

	vulnerable, service := checkSubdomainTakeover(host, client)

	if vulnerable {
		t.Error("expected subdomain to not be vulnerable")
	}
	if service != "" {
		t.Errorf("expected empty service, got '%s'", service)
	}
}

func TestCheckSubdomainTakeover_Heroku(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No such app"))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	host := strings.TrimPrefix(server.URL, "http://")

	vulnerable, service := checkSubdomainTakeover(host, client)

	if !vulnerable {
		t.Error("expected subdomain to be vulnerable")
	}
	if service != "Heroku" {
		t.Errorf("expected service 'Heroku', got '%s'", service)
	}
}

func TestCheckSubdomainTakeover_AmazonS3(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("The specified bucket does not exist"))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	host := strings.TrimPrefix(server.URL, "http://")

	vulnerable, service := checkSubdomainTakeover(host, client)

	if !vulnerable {
		t.Error("expected subdomain to be vulnerable")
	}
	if service != "Amazon S3" {
		t.Errorf("expected service 'Amazon S3', got '%s'", service)
	}
}

func TestCheckSubdomainTakeover_ConnectionError(t *testing.T) {
	client := &http.Client{Timeout: 1 * time.Second}

	// Use invalid host to simulate connection error
	vulnerable, service := checkSubdomainTakeover("invalid.host.that.does.not.exist.local", client)

	if vulnerable {
		t.Error("expected subdomain to not be vulnerable on connection error")
	}
	if service != "" {
		t.Errorf("expected empty service, got '%s'", service)
	}
}

func TestFetchRobotsTXT_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *\nDisallow: /admin"))
		}
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp := fetchRobotsTXT(server.URL+"/robots.txt", client)

	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFetchRobotsTXT_Redirect(t *testing.T) {
	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User-agent: *\nDisallow: /secret"))
	}))
	defer finalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", finalServer.URL+"/robots.txt")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer redirectServer.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp := fetchRobotsTXT(redirectServer.URL+"/robots.txt", client)

	if resp == nil {
		t.Fatal("expected response after redirect, got nil")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestSubdomainTakeoverResult(t *testing.T) {
	result := SubdomainTakeoverResult{
		Subdomain:  "test.example.com",
		Vulnerable: true,
		Service:    "GitHub Pages",
	}

	if result.Subdomain != "test.example.com" {
		t.Errorf("expected subdomain 'test.example.com', got '%s'", result.Subdomain)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable to be true")
	}
	if result.Service != "GitHub Pages" {
		t.Errorf("expected service 'GitHub Pages', got '%s'", result.Service)
	}
}

func TestDorkResult(t *testing.T) {
	result := DorkResult{
		Url:   "site:example.com filetype:pdf",
		Count: 42,
	}

	if result.Url != "site:example.com filetype:pdf" {
		t.Errorf("expected url 'site:example.com filetype:pdf', got '%s'", result.Url)
	}
	if result.Count != 42 {
		t.Errorf("expected count 42, got %d", result.Count)
	}
}

func TestHeaderResult(t *testing.T) {
	result := HeaderResult{
		Name:  "Content-Type",
		Value: "application/json",
	}

	if result.Name != "Content-Type" {
		t.Errorf("expected name 'Content-Type', got '%s'", result.Name)
	}
	if result.Value != "application/json" {
		t.Errorf("expected value 'application/json', got '%s'", result.Value)
	}
}
