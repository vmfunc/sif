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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestIdlePerHost(t *testing.T) {
	tests := []struct {
		name    string
		threads int
		want    int
	}{
		{name: "below floor clamps up", threads: 1, want: minIdleConnsPerHost},
		{name: "zero clamps up", threads: 0, want: minIdleConnsPerHost},
		{name: "at floor", threads: minIdleConnsPerHost, want: minIdleConnsPerHost},
		{name: "above floor passes through", threads: 64, want: 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := idlePerHost(tt.threads); got != tt.want {
				t.Errorf("idlePerHost(%d) = %d, want %d", tt.threads, got, tt.want)
			}
		})
	}
}

func TestBuildTransportTuning(t *testing.T) {
	const threads = 32
	tr, err := buildTransport("", threads)
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}

	if tr.MaxIdleConns != maxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, maxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != threads {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, threads)
	}
	if tr.MaxConnsPerHost != 0 {
		t.Errorf("MaxConnsPerHost = %d, want 0 (unbounded)", tr.MaxConnsPerHost)
	}
	if tr.IdleConnTimeout != idleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", tr.IdleConnTimeout, idleConnTimeout)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
}

func TestDrainClose(t *testing.T) {
	resetConfig(t)

	// serve a body the caller never reads; DrainClose must drain it so the conn
	// is eligible for reuse rather than abandoned mid-stream.
	const body = "sif response body that the caller never reads"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := Client(5 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}

	DrainClose(resp)

	// after DrainClose the body is closed; a further read must fail.
	if _, err := resp.Body.Read(make([]byte, 1)); err == nil {
		t.Error("expected read after DrainClose to fail on a closed body")
	}
}

func TestDrainCloseNil(t *testing.T) {
	// a nil response (e.g. an errored request) must not panic.
	DrainClose(nil)
	DrainClose(&http.Response{})
}

// countConns wraps a test server with a ConnState hook that tallies how many
// distinct tcp conns the server saw. distinct conns == failed reuse.
func countConns(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()

	var (
		mu    sync.Mutex
		conns = make(map[net.Conn]struct{})
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// always write a body so reuse depends on the caller draining it.
		io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
	}
	srv.Start()
	t.Cleanup(srv.Close)

	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(conns)
	}
}

func TestTransportReusesConnections(t *testing.T) {
	resetConfig(t)

	const (
		threads  = 8
		requests = 30
	)
	if err := Configure(Options{Threads: threads}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	srv, distinct := countConns(t)

	// fire N sequential requests through the tuned client, draining each body so
	// the conn returns to the pool. a working pool serves all of them on one conn.
	client := Client(5 * time.Second)
	for i := 0; i < requests; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
		if err != nil {
			t.Fatalf("new request %d: %v", i, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request %d: %v", i, err)
		}
		DrainClose(resp)
	}

	// sequential reuse should land on exactly one conn; allow a tiny margin for
	// the rare race where a conn is reaped between requests.
	const maxReuseConns = 2
	if got := distinct(); got > maxReuseConns {
		t.Errorf("tuned client opened %d conns for %d requests, want <= %d (pool not reusing)",
			got, requests, maxReuseConns)
	}
}

func TestBareClientDoesNotReuse(t *testing.T) {
	srv, distinct := countConns(t)

	// the control: a bare DefaultTransport client whose caller closes but never
	// drains the body. go can't reuse a half-read conn, so each request dials
	// fresh - this is exactly the pre-tuning behavior we're fixing.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}

	const requests = 30
	for i := 0; i < requests; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
		if err != nil {
			t.Fatalf("new request %d: %v", i, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request %d: %v", i, err)
		}
		// close without draining - the leak that kills reuse.
		resp.Body.Close()
	}

	// most requests should have dialed a fresh conn. don't demand exactly N (the
	// scheduler occasionally reuses one), just that it's clearly not pooling.
	const minDistinct = requests / 2
	if got := distinct(); got < minDistinct {
		t.Errorf("bare client opened only %d conns for %d requests, want >= %d "+
			"(expected near-zero reuse without draining)", got, requests, minDistinct)
	}
}

// BenchmarkConnReuse contrasts the tuned, draining client against a bare client
// that closes without draining. the reported conns/op metric is the distinct
// tcp conns one pass of `requests` opened - tuned≈1, bare≈requests - so the
// README can quote real before/after reuse numbers. the conn map is reset per
// iteration so the metric stays a per-pass count and the bare path doesn't
// accumulate b.N*requests live sockets and exhaust the ephemeral port range.
//
// run the bare sub-bench with a bounded -benchtime (e.g. -benchtime 5x): its
// whole point is that it can't reuse, so a large b.N floods the local port
// space with TIME_WAIT sockets. the tuned sub-bench reuses and runs unbounded.
func BenchmarkConnReuse(b *testing.B) {
	const requests = 50

	run := func(b *testing.B, drain bool, client *http.Client) {
		b.Helper()
		var (
			mu    sync.Mutex
			conns = make(map[net.Conn]struct{})
		)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, strings.Repeat("x", 256))
		}))
		srv.Config.ConnState = func(c net.Conn, state http.ConnState) {
			if state != http.StateNew {
				return
			}
			mu.Lock()
			conns[c] = struct{}{}
			mu.Unlock()
		}
		srv.Start()
		defer srv.Close()

		var lastPass int
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			mu.Lock()
			conns = make(map[net.Conn]struct{})
			mu.Unlock()
			for i := 0; i < requests; i++ {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
				resp, err := client.Do(req)
				if err != nil {
					b.Fatalf("do: %v", err)
				}
				if drain {
					DrainClose(resp)
				} else {
					resp.Body.Close()
				}
			}
			// close idle conns between passes so the bare client's per-pass
			// sockets land in TIME_WAIT and free up before the next pass.
			client.CloseIdleConnections()
			mu.Lock()
			lastPass = len(conns)
			mu.Unlock()
		}
		b.StopTimer()

		// distinct conns for a single pass of `requests`.
		b.ReportMetric(float64(lastPass), "conns/op")
	}

	b.Run("tuned-drain", func(b *testing.B) {
		resetBench()
		tr, err := buildTransport("", 8)
		if err != nil {
			b.Fatalf("buildTransport: %v", err)
		}
		run(b, true, &http.Client{Timeout: 5 * time.Second, Transport: tr})
	})

	b.Run("bare-noDrain", func(b *testing.B) {
		run(b, false, &http.Client{
			Timeout:   5 * time.Second,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		})
	})
}

// resetBench clears the package transport without a *testing.T for benchmarks.
func resetBench() {
	mu.Lock()
	configured = nil
	mu.Unlock()
}

// retrySequenceServer serves codes[n] on the n-th hit, repeating the last once
// the slice runs out; retryable codes carry Retry-After: 0 to keep tests fast.
func retrySequenceServer(t *testing.T, hits *atomic.Int64, codes ...int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(hits.Add(1)) - 1
		code := codes[len(codes)-1]
		if n < len(codes) {
			code = codes[n]
		}
		if code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "0")
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// getStatus performs a GET and returns the final status code the caller sees.
func getStatus(t *testing.T, client *http.Client, url string) int {
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
	return resp.StatusCode
}

func TestRetryRecoversAfter429(t *testing.T) {
	resetConfig(t)

	var hits atomic.Int64
	srv := retrySequenceServer(t, &hits, http.StatusTooManyRequests, http.StatusOK)
	if err := Configure(Options{MaxRetries: 2}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if code := getStatus(t, Client(5*time.Second), srv.URL); code != http.StatusOK {
		t.Errorf("status = %d, want 200 after retry", code)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2 (initial + one retry)", got)
	}
}

func TestRetryRecoversAfter503(t *testing.T) {
	resetConfig(t)

	var hits atomic.Int64
	srv := retrySequenceServer(t, &hits, http.StatusServiceUnavailable, http.StatusOK)
	if err := Configure(Options{MaxRetries: 2}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if code := getStatus(t, Client(5*time.Second), srv.URL); code != http.StatusOK {
		t.Errorf("status = %d, want 200 after retry", code)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2", got)
	}
}

func TestRetryDisabled(t *testing.T) {
	resetConfig(t)

	var hits atomic.Int64
	srv := retrySequenceServer(t, &hits, http.StatusTooManyRequests, http.StatusOK)
	if err := Configure(Options{MaxRetries: 0}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if code := getStatus(t, Client(5*time.Second), srv.URL); code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 with retries off", code)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (no retry)", got)
	}
}

func TestRetryExhausted(t *testing.T) {
	resetConfig(t)

	var hits atomic.Int64
	srv := retrySequenceServer(t, &hits, http.StatusTooManyRequests) // always 429
	if err := Configure(Options{MaxRetries: 2}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if code := getStatus(t, Client(5*time.Second), srv.URL); code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 after exhausting retries", code)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("server hits = %d, want 3 (initial + 2 retries)", got)
	}
}

func TestRetryIgnoresNonRetryableStatus(t *testing.T) {
	resetConfig(t)

	var hits atomic.Int64
	srv := retrySequenceServer(t, &hits, http.StatusInternalServerError, http.StatusOK)
	if err := Configure(Options{MaxRetries: 2}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if code := getStatus(t, Client(5*time.Second), srv.URL); code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (not retried)", code)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (500 not retried)", got)
	}
}

func TestRetryReplaysRequestBody(t *testing.T) {
	resetConfig(t)

	var hits atomic.Int64
	var bmu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bmu.Lock()
		bodies = append(bodies, string(body))
		bmu.Unlock()
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	if err := Configure(Options{MaxRetries: 2}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := Client(5 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after body replay", resp.StatusCode)
	}

	bmu.Lock()
	defer bmu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(bodies))
	}
	for i, body := range bodies {
		if body != "payload" {
			t.Errorf("body[%d] = %q, want %q (rewind dropped the body)", i, body, "payload")
		}
	}
}

func TestRetryAfterHeader(t *testing.T) {
	noHeader := &http.Response{Header: http.Header{}}
	if got := retryAfter(noHeader, 0); got != retryBackoffBase {
		t.Errorf("missing header: attempt 0 = %v, want %v", got, retryBackoffBase)
	}
	if got := retryAfter(noHeader, 1); got != 2*retryBackoffBase {
		t.Errorf("missing header: attempt 1 = %v, want %v", got, 2*retryBackoffBase)
	}
	if got := retryAfter(noHeader, 1000); got != retryAfterCap {
		t.Errorf("missing header: attempt 1000 = %v, want cap %v", got, retryAfterCap)
	}

	withSeconds := func(v string) *http.Response {
		return &http.Response{Header: http.Header{"Retry-After": {v}}}
	}
	if got := retryAfter(withSeconds("3"), 0); got != 3*time.Second {
		t.Errorf("Retry-After 3 = %v, want 3s", got)
	}
	if got := retryAfter(withSeconds("0"), 5); got != 0 {
		t.Errorf("Retry-After 0 = %v, want 0", got)
	}
	if got := retryAfter(withSeconds("9999"), 0); got != retryAfterCap {
		t.Errorf("Retry-After 9999 = %v, want cap %v", got, retryAfterCap)
	}
	if got := retryAfter(withSeconds("soon"), 0); got != retryBackoffBase {
		t.Errorf("Retry-After junk = %v, want backoff %v", got, retryBackoffBase)
	}

	future := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfter(withSeconds(future), 0); got <= 0 || got > 5*time.Second {
		t.Errorf("Retry-After http-date = %v, want (0, 5s]", got)
	}
}

func TestCapDuration(t *testing.T) {
	cases := []struct{ in, want time.Duration }{
		{-time.Second, 0},
		{0, 0},
		{5 * time.Second, 5 * time.Second},
		{retryAfterCap, retryAfterCap},
		{retryAfterCap + time.Second, retryAfterCap},
	}
	for _, c := range cases {
		if got := capDuration(c.in); got != c.want {
			t.Errorf("capDuration(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSleepCtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Error("sleepCtx on a cancelled context should return its error, not block")
	}
}
