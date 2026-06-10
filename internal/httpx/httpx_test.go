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

package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// resetConfig clears the package-level transport so each test starts clean.
func resetConfig(t *testing.T) {
	t.Helper()
	mu.Lock()
	configured = nil
	mu.Unlock()
}

// captureServer records the headers of the last request it served.
func captureServer(t *testing.T, seen *http.Header) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, client *http.Client, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()
}

func TestClientBeforeConfigure(t *testing.T) {
	resetConfig(t)

	var seen http.Header
	srv := captureServer(t, &seen)

	// a client must work with no Configure call so existing code is unaffected.
	get(t, Client(5*time.Second), srv.URL)

	if seen == nil {
		t.Fatal("request never reached the server")
	}
}

func TestConfigureHeadersAndCookie(t *testing.T) {
	tests := []struct {
		name      string
		opts      Options
		wantKey   string
		wantValue string
	}{
		{
			name:      "custom header injected",
			opts:      Options{Headers: []string{"X-Test: sif"}},
			wantKey:   "X-Test",
			wantValue: "sif",
		},
		{
			name:      "cookie injected",
			opts:      Options{Cookie: "session=abc"},
			wantKey:   "Cookie",
			wantValue: "session=abc",
		},
		{
			name:      "user agent injected",
			opts:      Options{UserAgent: "sif-scanner"},
			wantKey:   "User-Agent",
			wantValue: "sif-scanner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetConfig(t)

			if err := Configure(tt.opts); err != nil {
				t.Fatalf("Configure: %v", err)
			}

			var seen http.Header
			srv := captureServer(t, &seen)
			get(t, Client(5*time.Second), srv.URL)

			if got := seen.Get(tt.wantKey); got != tt.wantValue {
				t.Errorf("header %q = %q, want %q", tt.wantKey, got, tt.wantValue)
			}
		})
	}
}

func TestConfigureHeaderDoesNotOverride(t *testing.T) {
	resetConfig(t)

	if err := Configure(Options{Headers: []string{"X-Test: global"}}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	var seen http.Header
	srv := captureServer(t, &seen)

	// a caller that sets the header explicitly must win over the global default.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Test", "caller")
	resp, err := Client(5 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()

	if got := seen.Get("X-Test"); got != "caller" {
		t.Errorf("X-Test = %q, want caller (caller value must not be overridden)", got)
	}
}

func TestConfigureInvalidHeader(t *testing.T) {
	resetConfig(t)

	// a header without ": " should fail loud rather than silently dropping.
	if err := Configure(Options{Headers: []string{"missing-separator"}}); err == nil {
		t.Fatal("expected error for malformed header, got nil")
	}
}

func TestConfigureInvalidProxy(t *testing.T) {
	tests := []struct {
		name  string
		proxy string
	}{
		{name: "unsupported scheme", proxy: "ftp://localhost:1080"},
		{name: "malformed url", proxy: "://nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetConfig(t)
			if err := Configure(Options{Proxy: tt.proxy}); err == nil {
				t.Errorf("expected error for proxy %q, got nil", tt.proxy)
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	resetConfig(t)

	const ratePerSec = 5
	if err := Configure(Options{RateLimit: ratePerSec}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	var seen http.Header
	srv := captureServer(t, &seen)
	client := Client(5 * time.Second)

	// at 5 req/s the limiter starts with a full burst, so the first batch is
	// immediate and the next request must wait roughly one tick. fire burst+1
	// requests and assert the extra one forced a measurable delay.
	const requests = ratePerSec + 1
	start := time.Now()
	for i := 0; i < requests; i++ {
		get(t, client, srv.URL)
	}
	elapsed := time.Since(start)

	// one request beyond the burst should cost about 1/rate; allow slack but
	// require a non-trivial delay so an unthrottled client fails this.
	minDelay := time.Second / ratePerSec / 2
	if elapsed < minDelay {
		t.Errorf("expected rate limiting to add >= %v of delay, got %v", minDelay, elapsed)
	}
}

func TestRateLimitUnlimited(t *testing.T) {
	resetConfig(t)

	// RateLimit 0 means no limiter is installed; requests should fly through.
	if err := Configure(Options{RateLimit: 0}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	mu.RLock()
	rt, ok := configured.(*roundTripper)
	mu.RUnlock()
	if !ok {
		t.Fatal("configured transport is not *roundTripper")
	}
	if rt.limiter != nil {
		t.Error("expected no limiter when RateLimit is 0")
	}
}
