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
	"sync/atomic"
	"testing"
	"time"
)

func TestMeaningfulStatus(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{"ok counts", http.StatusOK, true},
		{"204 counts", http.StatusNoContent, true},
		{"301 catch-all redirect dropped", http.StatusMovedPermanently, false},
		{"302 catch-all redirect dropped", http.StatusFound, false},
		{"404 dropped", http.StatusNotFound, false},
		{"500 dropped", http.StatusInternalServerError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := meaningfulStatus(tt.code); got != tt.want {
				t.Errorf("meaningfulStatus(%d) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// a host that answers 200 over http should count exactly once, not once per
// scheme - the old path appended on both http and https.
func TestProbeSubdomain_DedupesAcrossSchemes(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	client := &http.Client{Timeout: 5 * time.Second}

	url, scheme := probeSubdomain(client, host)
	if url == "" {
		t.Fatal("expected http probe to count the host")
	}
	if scheme != dnsSchemeHTTP {
		t.Errorf("expected http scheme to win, got %q", scheme)
	}
	// http already counted, so https must not be tried - one request total.
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly 1 probe request, got %d", got)
	}
}

// a wildcard catch-all that 404s (or 301s) every candidate must not be reported
// as found - that's the flood the gating closes.
func TestProbeSubdomain_WildcardCatchAllNotFound(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMovedPermanently} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if code == http.StatusMovedPermanently {
				w.Header().Set("Location", "https://catch-all.example/")
			}
			w.WriteHeader(code)
		}))

		host := strings.TrimPrefix(srv.URL, "http://")
		client := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		url, _ := probeSubdomain(client, host)
		if url != "" {
			t.Errorf("status %d should not count as found, got %q", code, url)
		}
		srv.Close()
	}
}
