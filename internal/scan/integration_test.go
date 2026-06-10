//go:build integration

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

// These tests run the real scanners against a local server standing in for a
// deliberately-vulnerable app, asserting the findings each one should produce.
// They're behind the `integration` build tag so the default `go test` stays
// network-free; run with `go test -tags=integration ./internal/scan/...`.
package scan

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newVulnApp serves the planted artifacts each scanner is meant to find, plus
// the wordlists the remote-list scanners fetch.
func newVulnApp() *httptest.Server {
	mux := http.NewServeMux()

	// wordlists the remote-list scanners download
	mux.HandleFunc("/git.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(".git/HEAD\n.git/config\n"))
	})
	mux.HandleFunc("/directory-list-2.3-small.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin\nlogin\nnope\n"))
	})
	mux.HandleFunc("/subdomains-100.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("dev\nstaging\n"))
	})

	// an exposed git repo: HEAD is a real find, config is html so it's excluded
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("ref: refs/heads/main\n"))
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>nope</html>"))
	})

	// live directories for dirlist
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// an exposed db admin panel for sql recon
	mux.HandleFunc("/phpmyadmin/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<title>phpMyAdmin</title>"))
	})

	// reflecting-origin endpoint for the cors probe
	mux.HandleFunc("/cors", func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	})

	// open-redirect endpoint: echoes the next param into Location
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// reflecting endpoint for the xss probe: echoes q raw into html text
	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		//nolint:gosec // deliberate reflected-xss fixture for the probe under test
		w.Write([]byte("<html><body><div>" + r.URL.Query().Get("q") + "</div></body></html>"))
	})

	// homepage doubles as the cms fingerprint and the lfi sink
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.RawQuery, "passwd") || strings.Contains(r.URL.RawQuery, "etc") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.Write([]byte(`<html><head><link href="/wp-content/themes/x/style.css"></head><body>hi</body></html>`))
	})

	return httptest.NewServer(mux)
}

func TestIntegrationGit(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()
	orig := gitURL
	gitURL = srv.URL + "/"
	defer func() { gitURL = orig }()

	found, err := Git(srv.URL, 5*time.Second, 2, "")
	if err != nil {
		t.Fatalf("Git: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 git find (HEAD, not the html config), got %d: %v", len(found), found)
	}
	if !strings.HasSuffix(found[0], ".git/HEAD") {
		t.Errorf("expected .git/HEAD, got %s", found[0])
	}
}

func TestIntegrationDirlist(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()
	orig := directoryURL
	directoryURL = srv.URL + "/"
	defer func() { directoryURL = orig }()

	results, err := Dirlist("small", srv.URL, 5*time.Second, 3, "")
	if err != nil {
		t.Fatalf("Dirlist: %v", err)
	}

	got := map[string]bool{}
	for _, r := range results {
		got[r.Url] = true
	}
	if !hasSuffixIn(got, "/admin") || !hasSuffixIn(got, "/login") {
		t.Errorf("expected admin and login to be found, got %v", results)
	}
	if hasSuffixIn(got, "/nope") {
		t.Errorf("404 path nope should not be reported, got %v", results)
	}
}

func TestIntegrationCMS(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	result, err := CMS(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("CMS: %v", err)
	}
	if result == nil || result.Name != "WordPress" {
		t.Errorf("expected WordPress, got %+v", result)
	}
}

func TestIntegrationHeaders(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	results, err := Headers(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least one header back")
	}
}

func TestIntegrationSQL(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 5, "")
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if result == nil || len(result.AdminPanels) == 0 {
		t.Fatalf("expected an admin panel finding, got %+v", result)
	}
	if result.AdminPanels[0].Type != "phpMyAdmin" {
		t.Errorf("expected phpMyAdmin, got %s", result.AdminPanels[0].Type)
	}
}

func TestIntegrationLFI(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	result, err := LFI(srv.URL, 5*time.Second, 5, "")
	if err != nil {
		t.Fatalf("LFI: %v", err)
	}
	if result == nil || len(result.Vulnerabilities) == 0 {
		t.Errorf("expected an lfi finding from the passwd sink, got %+v", result)
	}
}

func TestIntegrationCORS(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	result, err := CORS(srv.URL+"/cors", 5*time.Second, 3, "")
	if err != nil {
		t.Fatalf("CORS: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected a cors finding from the reflecting endpoint, got %+v", result)
	}
}

func TestIntegrationRedirect(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	result, err := Redirect(srv.URL+"/redirect", 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("Redirect: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected an open-redirect finding from the next sink, got %+v", result)
	}
}

func TestIntegrationXSS(t *testing.T) {
	srv := newVulnApp()
	defer srv.Close()

	result, err := XSS(srv.URL+"/xss", 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("XSS: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected a reflected-xss finding from the q sink, got %+v", result)
	}
}

func TestIntegrationPorts(t *testing.T) {
	// a real listener stands in for an open port; a tiny server hands its number
	// to Ports via the commonPorts wordlist.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strconv.Itoa(port) + "\n"))
	}))
	defer list.Close()
	orig := commonPorts
	commonPorts = list.URL
	defer func() { commonPorts = orig }()

	open, err := Ports(context.Background(), "common", "tcp://127.0.0.1", 2*time.Second, 1, "")
	if err != nil {
		t.Fatalf("Ports: %v", err)
	}
	found := false
	for _, p := range open {
		if p == strconv.Itoa(port) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected open port %d in %v", port, open)
	}
}

func TestIntegrationShodan(t *testing.T) {
	// a local server stands in for api.shodan.io; example.com resolves to a real
	// IP but the lookup never leaves the box.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(shodanHostResponse{
			IP:        "93.184.216.34",
			Hostnames: []string{"example.com"},
			Org:       "EDGECAST",
			Ports:     []int{80, 443},
			Data: []shodanData{
				{Port: 80, Transport: "tcp", Product: "nginx", Version: "1.18.0"},
			},
		})
	}))
	defer srv.Close()
	orig := shodanBaseURL
	shodanBaseURL = srv.URL
	defer func() { shodanBaseURL = orig }()

	t.Setenv("SHODAN_API_KEY", "test-key")

	result, err := Shodan("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("Shodan: %v", err)
	}
	if result == nil || result.IP != "93.184.216.34" {
		t.Fatalf("expected parsed shodan result, got %+v", result)
	}
	if len(result.Services) != 1 || result.Services[0].Product != "nginx" {
		t.Errorf("expected one nginx service, got %+v", result.Services)
	}
}

func TestIntegrationSecurityTrails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") != "test-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/subdomains"):
			json.NewEncoder(w).Encode(stSubdomainsResponse{Subdomains: []string{"www", "api"}})
		case strings.HasSuffix(r.URL.Path, "/associated"):
			json.NewEncoder(w).Encode(stAssociatedResponse{Records: []stAssociatedRecord{{Hostname: "example.org"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	orig := securityTrailsBaseURL
	securityTrailsBaseURL = srv.URL
	defer func() { securityTrailsBaseURL = orig }()

	t.Setenv("SECURITYTRAILS_API_KEY", "test-key")

	result, err := SecurityTrails("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("SecurityTrails: %v", err)
	}
	if len(result.Subdomains) != 2 {
		t.Errorf("expected 2 subdomains, got %v", result.Subdomains)
	}
	if len(result.AssociatedDomains) != 1 || result.AssociatedDomains[0] != "example.org" {
		t.Errorf("expected example.org associated, got %v", result.AssociatedDomains)
	}

	urls := result.DiscoveredURLs()
	if !contains(urls, "https://www.example.com") || !contains(urls, "https://example.org") {
		t.Errorf("expected discovered urls to expand subs and associated, got %v", urls)
	}
}

func TestIntegrationCloudStorage(t *testing.T) {
	// the fixture returns 200 only for the planted bucket, so any candidate that
	// matches it is reported public.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/example" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	orig := s3EndpointFmt
	s3EndpointFmt = srv.URL + "/%s"
	defer func() { s3EndpointFmt = orig }()

	results, err := CloudStorage("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("CloudStorage: %v", err)
	}

	var public bool
	for _, r := range results {
		if r.BucketName == "example" && r.IsPublic {
			public = true
		}
	}
	if !public {
		t.Errorf("expected the example bucket to be flagged public, got %+v", results)
	}
}

func TestIntegrationDnslist(t *testing.T) {
	// the probe server answers any host routed to it; dnsTransport pins every
	// dial here so no real DNS is touched.
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer probe.Close()
	probeAddr := strings.TrimPrefix(probe.URL, "http://")

	list := newVulnApp()
	defer list.Close()
	origURL := dnsURL
	dnsURL = list.URL + "/"
	defer func() { dnsURL = origURL }()

	origTr := dnsTransport
	dnsTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, probeAddr)
		},
	}
	defer func() { dnsTransport = origTr }()

	found, err := Dnslist("small", "http://example.com", 5*time.Second, 2, "")
	if err != nil {
		t.Fatalf("Dnslist: %v", err)
	}
	// http probes land on the plain-http probe server; https fails the tls
	// handshake and is dropped, which is fine - the planted sub still shows up.
	if !hasSuffixIn(sliceSet(found), "dev.example.com") {
		t.Errorf("expected dev.example.com among findings, got %v", found)
	}
}

func contains(s []string, v string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == v {
			return true
		}
	}
	return false
}

func sliceSet(s []string) map[string]bool {
	set := make(map[string]bool, len(s))
	for i := 0; i < len(s); i++ {
		set[s[i]] = true
	}
	return set
}

func hasSuffixIn(set map[string]bool, suffix string) bool {
	for k := range set {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}
