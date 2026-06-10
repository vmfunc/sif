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

// goldenFaviconBytes is a fixed payload long enough to span multiple base64
// lines, so the python-style 76-char chunking is actually exercised by the hash.
var goldenFaviconBytes = []byte(strings.Repeat("sif-favicon-golden-test-bytes-", 8))

// goldenFaviconHash is the shodan mmh3 hash of goldenFaviconBytes. it is pinned:
// the value comes from feeding the python base64.encodebytes byte stream (newline
// every 76 chars + trailing newline) through murmur3-32 and reinterpreting the
// result as a signed int32 - exactly what shodan stores. if the chunking or the
// signedness regress, this number changes and the test fails.
const goldenFaviconHash int32 = -1554620260

// goldenHelloHash pins a short single-line case so a regression in the trailing
// newline (which the small case still has) is caught independently.
const goldenHelloHash int32 = 1155597304

func TestFaviconHash_Golden(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int32
	}{
		{name: "multi-line fixture", in: goldenFaviconBytes, want: goldenFaviconHash},
		{name: "single-line hello", in: []byte("hello"), want: goldenHelloHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FaviconHash(tt.in)
			if got != tt.want {
				t.Errorf("FaviconHash = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestFaviconBase64Chunking pins the encode step against python's
// base64.encodebytes: a 50-byte input encodes to >76 base64 chars, so it must
// wrap into two newline-terminated lines.
func TestFaviconBase64Chunking(t *testing.T) {
	in := []byte(strings.Repeat("A", 60)) // 60 bytes -> 80 base64 chars -> two lines
	got := string(encodeFaviconBase64(in))

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 wrapped lines, got %d: %q", len(lines), got)
	}
	if len(lines[0]) != b64LineLen {
		t.Errorf("first line = %d chars, want %d", len(lines[0]), b64LineLen)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("encoding must end in a trailing newline, got %q", got)
	}
}

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
}

// TestFavicon_LinkFallback covers the <link rel=icon> path when /favicon.ico is
// absent: the homepage points at /static/icon.png and that's what gets hashed.
func TestFavicon_LinkFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.WriteHeader(http.StatusNotFound)
		case "/static/icon.png":
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

func TestFaviconResult_ResultType(t *testing.T) {
	r := &FaviconResult{}
	if r.ResultType() != "favicon" {
		t.Errorf("expected result type 'favicon', got %q", r.ResultType())
	}
}
