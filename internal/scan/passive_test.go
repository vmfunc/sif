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
	"strings"
	"testing"
	"time"
)

// sample feed payloads. crt.sh packs several names per name_value (newline
// separated) and emits wildcards; certspotter returns expanded dns_names.
const (
	crtshFixture = `[
		{"name_value": "www.example.com\n*.example.com"},
		{"name_value": "api.example.com"},
		{"name_value": "WWW.example.com"}
	]`
	certspotterFixture = `[
		{"dns_names": ["mail.example.com", "api.example.com"]},
		{"dns_names": ["*.example.com"]}
	]`
	waybackFixture = "http://example.com/\n" +
		"http://example.com/login\n" +
		"http://example.com/login\n" +
		"\n" +
		"http://example.com/admin\n"
)

// fixtureServer serves each passive source on its own path and repoints the
// package base-url vars at it. the vars are restored on cleanup.
func fixtureServer(t *testing.T, crtsh, certspotter, wayback string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/crtsh", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(crtsh))
	})
	mux.HandleFunc("/certspotter", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(certspotter))
	})
	mux.HandleFunc("/wayback", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(wayback))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origCrtsh, origCertspotter, origWayback := crtshBaseURL, certspotterBaseURL, waybackBaseURL
	// %s still consumes the domain so the production formatting path is exercised.
	crtshBaseURL = srv.URL + "/crtsh?q=%s"
	certspotterBaseURL = srv.URL + "/certspotter?domain=%s"
	waybackBaseURL = srv.URL + "/wayback?url=%s"
	t.Cleanup(func() {
		crtshBaseURL, certspotterBaseURL, waybackBaseURL = origCrtsh, origCertspotter, origWayback
	})

	return srv
}

func TestPassive_ParsesAndDedupes(t *testing.T) {
	fixtureServer(t, crtshFixture, certspotterFixture, waybackFixture)

	result, err := Passive("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("Passive: %v", err)
	}

	// wildcards stripped, case-folded, and merged across both ct feeds.
	wantSubs := map[string]bool{
		"www.example.com":  false,
		"api.example.com":  false,
		"mail.example.com": false,
		"example.com":      false, // from "*.example.com"
	}
	for _, s := range result.Subdomains {
		if _, ok := wantSubs[s]; !ok {
			t.Errorf("unexpected subdomain %q", s)
			continue
		}
		wantSubs[s] = true
	}
	for s, seen := range wantSubs {
		if !seen {
			t.Errorf("missing subdomain %q in %v", s, result.Subdomains)
		}
	}
	if len(result.Subdomains) != len(wantSubs) {
		t.Errorf("expected %d deduped subdomains, got %d: %v", len(wantSubs), len(result.Subdomains), result.Subdomains)
	}

	// wayback: blank line dropped, duplicate /login collapsed.
	wantURLs := map[string]bool{
		"http://example.com/":      false,
		"http://example.com/login": false,
		"http://example.com/admin": false,
	}
	for _, u := range result.URLs {
		if _, ok := wantURLs[u]; !ok {
			t.Errorf("unexpected url %q", u)
			continue
		}
		wantURLs[u] = true
	}
	if len(result.URLs) != len(wantURLs) {
		t.Errorf("expected %d deduped urls, got %d: %v", len(wantURLs), len(result.URLs), result.URLs)
	}
}

func TestPassive_SourceFailureIsIsolated(t *testing.T) {
	// crt.sh serves garbage that fails to parse; the other feeds must still
	// produce results.
	fixtureServer(t, "not json", certspotterFixture, waybackFixture)

	result, err := Passive("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("Passive should not fail when one source is down: %v", err)
	}

	if len(result.Subdomains) == 0 {
		t.Error("expected certspotter subdomains despite crt.sh failure")
	}
	if len(result.URLs) == 0 {
		t.Error("expected wayback urls despite crt.sh failure")
	}
	if urlsContain(result.Subdomains, "www.example.com") {
		t.Error("crt.sh-only subdomain leaked despite parse failure")
	}
}

func TestPassive_ResultType(t *testing.T) {
	r := &PassiveResult{}
	if r.ResultType() != "passive" {
		t.Errorf("ResultType = %q, want passive", r.ResultType())
	}
}

func TestPassive_ScopesSubdomainsToTarget(t *testing.T) {
	// notexample.com guards the suffix-match trap: not a subdomain of example.com.
	const sharedCert = `[
		{"name_value": "www.example.com\nshared.othersite.com"},
		{"name_value": "notexample.com\n*.example.com"}
	]`
	fixtureServer(t, sharedCert, "[]", "")

	result, err := Passive("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("Passive: %v", err)
	}

	for _, off := range []string{"shared.othersite.com", "notexample.com"} {
		if urlsContain(result.Subdomains, off) {
			t.Errorf("off-scope name %q leaked as a subdomain: %v", off, result.Subdomains)
		}
	}
	if !urlsContain(result.Subdomains, "www.example.com") {
		t.Errorf("expected the in-scope subdomain to remain: %v", result.Subdomains)
	}
}

func TestPassive_WaybackLongLineKeepsFeed(t *testing.T) {
	// a single archived url with a huge query string (data:/base64 blobs do
	// occur) must not discard every other harvested url.
	longURL := "http://example.com/?blob=" + strings.Repeat("a", 2*1024*1024)
	wayback := longURL + "\n" +
		"http://example.com/keep-one\n" +
		"http://example.com/keep-two\n"
	fixtureServer(t, "[]", "[]", wayback)

	result, err := Passive("https://example.com", 5*time.Second, "")
	if err != nil {
		t.Fatalf("Passive: %v", err)
	}

	for _, want := range []string{"http://example.com/keep-one", "http://example.com/keep-two"} {
		if !urlsContain(result.URLs, want) {
			t.Errorf("over-long wayback line dropped the feed; missing %q, got %d urls", want, len(result.URLs))
		}
	}
	if !urlsContain(result.URLs, longURL) {
		t.Errorf("the over-long url itself was dropped, got %d urls", len(result.URLs))
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"www.example.com", "www.example.com"},
		{"*.example.com", "example.com"},
		{"www.example.com.", "www.example.com"},
		{"  WWW.Example.COM  ", "www.example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeHost(tt.in); got != tt.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
