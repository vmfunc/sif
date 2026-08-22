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
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/fingerprint"
	"github.com/vmfunc/sif/internal/httpx"
)

// goldenFaviconBytes is a fixed payload long enough to span multiple base64
// lines, so the python-style 76-char chunking is actually exercised by the hash.
var goldenFaviconBytes = []byte(strings.Repeat("sif-favicon-golden-test-bytes-", 8))

// goldenFaviconHash is the shodan mmh3 hash of goldenFaviconBytes. it is pinned:
// the value comes from feeding the python base64.encodebytes byte stream (newline
// every 76 chars + trailing newline) through murmur3-32 and reinterpreting the
// result as a signed int32 - exactly what shodan stores. if the chunking or the
// signedness regress, this number changes and the test fails.
const goldenFaviconHash int32 = -1554620260

// fixtureFaviconServer serves the golden bytes at /favicon.ico.
func fixtureFaviconServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(goldenFaviconBytes)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestFavicon_FetchAndHash(t *testing.T) {
	srv := fixtureFaviconServer()
	defer srv.Close()

	result, err := Favicon(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Favicon: %v", err)
	}
	if result == nil {
		t.Fatal("expected a favicon result, got nil")
	}
	if result.Hash != goldenFaviconHash {
		t.Errorf("Hash = %d, want %d", result.Hash, goldenFaviconHash)
	}
	wantQ := "http.favicon.hash:-1554620260"
	if result.ShodanQ != wantQ {
		t.Errorf("ShodanQ = %q, want %q", result.ShodanQ, wantQ)
	}

	wantTech, _ := fingerprint.LookupFaviconTech(fingerprint.FaviconHash(goldenFaviconBytes))
	if result.Tech != wantTech {
		t.Errorf("Tech = %q, want %q", result.Tech, wantTech)
	}
}

// TestFavicon_LinkFallback covers the <link rel=icon> path when /favicon.ico is
// absent: the homepage points at /static/icon.png and that's what gets hashed.
func TestFavicon_LinkFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.WriteHeader(http.StatusNotFound)
		case "/static/icon.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(goldenFaviconBytes)
		default:
			_, _ = w.Write([]byte(`<html><head><link rel="icon" href="/static/icon.png"></head></html>`))
		}
	}))
	defer srv.Close()

	result, err := Favicon(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Favicon: %v", err)
	}
	if result == nil {
		t.Fatal("expected a favicon result via link fallback, got nil")
	}
	if !strings.HasSuffix(result.FaviconURL, "/static/icon.png") {
		t.Errorf("FaviconURL = %q, want it to end in /static/icon.png", result.FaviconURL)
	}
	if result.Hash != goldenFaviconHash {
		t.Errorf("Hash = %d, want %d", result.Hash, goldenFaviconHash)
	}
}

// TestFavicon_NoIcon confirms a target with no favicon at all yields no result
// and no error.
func TestFavicon_NoIcon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := Favicon(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Favicon: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for missing favicon, got %+v", result)
	}
}

func TestResolveFaviconURL(t *testing.T) {
	cases := []struct {
		name string
		base string
		href string
		want string
	}{
		// see resolveFaviconURL's doc comment (favicon.go) for the anchoring rule.
		{"root-relative against pathful base", "https://example.com/app", "/favicon.ico", "https://example.com/favicon.ico"},
		{"root-relative against bare base", "https://example.com", "/static/icon.png", "https://example.com/static/icon.png"},
		{"absolute href kept", "https://example.com", "https://cdn.example.net/f.ico", "https://cdn.example.net/f.ico"},
		{"scheme-relative inherits https", "https://example.com", "//cdn.example.net/f.ico", "https://cdn.example.net/f.ico"},
		{"scheme-relative inherits http", "http://example.com", "//cdn.example.net/f.ico", "http://cdn.example.net/f.ico"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveFaviconURL(tc.base, tc.href); got != tc.want {
				t.Errorf("resolveFaviconURL(%q, %q) = %q, want %q", tc.base, tc.href, got, tc.want)
			}
		})
	}
}

// TestFavicon_OversizedIconMatchesSharedCap proves scan.Favicon hashes an icon
// larger than 1MB (but within the shared 5MB module-path cap) over the exact
// same bytes the module matcher would see. before the fix, scan.Favicon read
// with its own 1MB cap while the module path reads via httpx.ReadCappedBody's
// 5MB cap, so a >1MB icon hashed to two different values through the same
// shared FaviconHash - the -favicon shodan pivot was wrong, and the two SSOT
// paths disagreed on tech.
func TestFavicon_OversizedIconMatchesSharedCap(t *testing.T) {
	// 1.5MB: bigger than the old 1MB scan cap, well under the 5MB module cap.
	big := bytes.Repeat([]byte("A"), (3<<20)/2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(big)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := Favicon(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Favicon: %v", err)
	}
	if result == nil {
		t.Fatal("expected a favicon result, got nil")
	}

	if len(big) >= httpx.MaxBodySize {
		t.Fatalf("fixture body (%d bytes) must be under httpx.MaxBodySize (%d) for this assertion to hold", len(big), httpx.MaxBodySize)
	}
	want := fingerprint.FaviconHash(big)
	if result.Hash != want {
		t.Errorf("Hash = %d, want %d (module-path hash over the same shared cap)", result.Hash, want)
	}
}

// TestFavicon_SoftLoggedInHTML404NotHashed proves a soft-404 (200 text/html,
// the common "not found" page many apps serve instead of a real 404) at
// /favicon.ico is not mistaken for an icon. the doc comment above
// getFaviconBytes used to claim this couldn't happen because a "non-200" was
// rejected - but soft-404s are 200s, so the html body was hashed as if it were
// the icon, producing a bogus hash and a wrong shodan pivot. with no
// <link rel=icon> on the homepage either, there is nothing to fall back to, so
// the scan should report no favicon at all.
func TestFavicon_SoftLoggedInHTML404NotHashed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Not Found</title></head><body>404 not found</body></html>"))
	}))
	defer srv.Close()

	result, err := Favicon(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Favicon: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for a soft-404 html body, got %+v", result)
	}
}

// TestFavicon_RealIconStillHashes proves the sniffing guard doesn't reject a
// real icon served with no Content-Type header at all.
func TestFavicon_RealIconStillHashes(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 'r', 'e', 's', 't'}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write(png)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := Favicon(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Favicon: %v", err)
	}
	if result == nil {
		t.Fatal("expected a favicon result for a real png icon, got nil")
	}
	want := fingerprint.FaviconHash(png)
	if result.Hash != want {
		t.Errorf("Hash = %d, want %d", result.Hash, want)
	}
}

func TestFaviconResult_ResultType(t *testing.T) {
	r := &FaviconResult{}
	if r.ResultType() != "favicon" {
		t.Errorf("expected result type 'favicon', got %q", r.ResultType())
	}
}
