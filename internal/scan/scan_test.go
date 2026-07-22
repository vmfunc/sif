package scan

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
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

	vulnerable, service, _ := checkSubdomainTakeover(host, client)

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

	vulnerable, service, _ := checkSubdomainTakeover(host, client)

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

	vulnerable, service, _ := checkSubdomainTakeover(host, client)

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

	vulnerable, service, _ := checkSubdomainTakeover(host, client)

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
	vulnerable, service, _ := checkSubdomainTakeover("invalid.host.that.does.not.exist.local", client)

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

// an A->B->A redirect loop must terminate (return nil) instead of recursing
// forever and blowing the stack.
func TestFetchRobotsTXT_RedirectLoop(t *testing.T) {
	var serverA, serverB *httptest.Server

	serverA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", serverB.URL+"/robots.txt")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer serverA.Close()

	serverB = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", serverA.URL+"/robots.txt")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer serverB.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// the hop cap + visited set guarantee termination; a regression that drops
	// either would spin forever and the test harness timeout would catch it.
	resp := fetchRobotsTXT(serverA.URL+"/robots.txt", client)
	if resp != nil {
		resp.Body.Close()
		t.Errorf("expected nil on redirect loop, got status %d", resp.StatusCode)
	}
}

// a redirect chain longer than the hop cap stops at the bound rather than
// following indefinitely.
func TestFetchRobotsTXT_DepthCap(t *testing.T) {
	var hops int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// each hop points at a fresh path so the visited set never trips; only
		// the depth cap can stop this.
		n := atomic.AddInt32(&hops, 1)
		w.Header().Set("Location", "/r"+strconv.Itoa(int(n)))
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp := fetchRobotsTXT(srv.URL+"/robots.txt", client)
	if resp != nil {
		resp.Body.Close()
		t.Errorf("expected nil once depth cap exceeded, got status %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&hops); got > maxRobotsRedirects {
		t.Errorf("followed %d hops, expected at most %d", got, maxRobotsRedirects)
	}
}

// the old code flagged a dangling cname on ANY cname, including LookupCNAME
// echoing the host back for a plain A record. only an off-host cname into a
// known takeoverable provider should count.
func TestDanglingProvider(t *testing.T) {
	tests := []struct {
		name        string
		subdomain   string
		cname       string
		wantService string
		wantOK      bool
	}{
		{"github pages dangling", "blog.example.com", "example.github.io.", "GitHub Pages", true},
		{"heroku dangling", "app.example.com", "example.herokuapp.com.", "Heroku", true},
		{"s3 dangling", "files.example.com", "bucket.s3.amazonaws.com.", "Amazon S3", true},
		{"self-reference is not dangling", "www.example.com", "www.example.com.", "", false},
		{"on-domain cname is not dangling", "www.example.com", "lb.example.com.", "", false},
		{"unknown provider is not dangling", "x.example.com", "host.notaprovider.net.", "", false},
		{"empty cname is not dangling", "x.example.com", "", "", false},
		{"case-insensitive match", "x.example.com", "X.GitHub.IO.", "GitHub Pages", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, ok := danglingProvider(tt.subdomain, tt.cname)
			if ok != tt.wantOK {
				t.Errorf("danglingProvider(%q, %q) ok = %v, want %v", tt.subdomain, tt.cname, ok, tt.wantOK)
			}
			if service != tt.wantService {
				t.Errorf("danglingProvider(%q, %q) service = %q, want %q", tt.subdomain, tt.cname, service, tt.wantService)
			}
		})
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

func TestStripScheme(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"https with path", "https://example.com/path", "example.com/path"},
		{"http", "http://example.com", "example.com"},
		{"no scheme stays put", "example.com", "example.com"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripScheme(tt.url); got != tt.want {
				t.Errorf("stripScheme(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
