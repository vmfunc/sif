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

func hasSuffixIn(set map[string]bool, suffix string) bool {
	for k := range set {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}
