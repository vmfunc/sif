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

// Package httpx is the shared http layer every scanner talks through, so a
// single Configure call wires proxy, custom headers, cookies and rate limiting
// into every outbound request without touching scanner signatures.
package httpx

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// allowed proxy schemes
const (
	schemeHTTP   = "http"
	schemeHTTPS  = "https"
	schemeSOCKS5 = "socks5"
)

// a header is "Key: Value"; this is the separator between the two halves.
const headerSep = ": "

// burst lets the limiter absorb a small spike before pacing kicks in; a burst
// equal to the per-second rate keeps the cap honest over any one-second window.
const limiterBurstPerRate = 1

// transport pool tuning. go's default transport caps idle conns per host at 2
// and reuse only kicks in once a response body is fully drained, so without
// these a high thread count just thrashes the dialer instead of pooling.
const (
	// total idle conns kept warm across every host we hit in a run.
	maxIdleConns = 512
	// floor for per-host idle conns so a single-target run still pools even
	// when the thread count is tiny.
	minIdleConnsPerHost = 8
	// how long an idle conn lingers before the pool reaps it.
	idleConnTimeout = 90 * time.Second
	// keepalive probe interval for live conns; mirrors go's default dialer so
	// the socks5 branch doesn't silently lose os-level keepalive.
	dialKeepAlive = 30 * time.Second
	// dial timeout for the socks5 branch; matches go's default dialer.
	dialTimeout = 30 * time.Second
)

// drainCap bounds how much of an unread body DrainClose will copy before
// closing; a body larger than this isn't worth slurping just to reuse the
// conn, so we cap the read and let the conn be discarded instead.
const drainCap = 16 << 10

// Options carries the runtime knobs that apply to every outbound request.
// RateLimit is requests/sec (0 = unlimited); Headers are "Key: Value" strings.
type Options struct {
	Proxy     string
	Headers   []string
	Cookie    string
	UserAgent string
	RateLimit int
	// MaxRetries is how many 429/503 responses to retry with backoff (0 = off).
	MaxRetries int
	// Threads is the scan worker count; it sizes the per-host idle pool so
	// concurrent workers hitting one target reuse conns instead of dialing fresh.
	Threads int
}

// configured holds the package-level transport built once by Configure. nil
// means Configure was never called, so Client falls back to a plain client.
var (
	mu         sync.RWMutex
	configured http.RoundTripper
)

// Configure builds the shared transport once at startup from opts. Calling it
// again replaces the previous configuration.
//
//nolint:gocritic // signature is the package's stable startup api; called once.
func Configure(opts Options) error {
	base, err := buildTransport(opts.Proxy, opts.Threads)
	if err != nil {
		return err
	}

	headers, err := parseHeaders(opts.Headers)
	if err != nil {
		return err
	}

	var limiter *rate.Limiter
	if opts.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(opts.RateLimit), opts.RateLimit*limiterBurstPerRate)
	}

	rt := &roundTripper{
		base:       base,
		headers:    headers,
		cookie:     opts.Cookie,
		userAgent:  opts.UserAgent,
		limiter:    limiter,
		maxRetries: opts.MaxRetries,
	}

	mu.Lock()
	configured = rt
	mu.Unlock()

	return nil
}

// Client returns an http client wired to the configured transport. It works
// before Configure is ever called (plain transport) so existing code and tests
// behave unchanged. A zero timeout means no timeout, matching http.Client.
func Client(timeout time.Duration) *http.Client {
	mu.RLock()
	rt := configured
	mu.RUnlock()

	return &http.Client{Timeout: timeout, Transport: rt}
}

// buildTransport clones the default transport, tunes its pool for the worker
// count and applies the proxy. An empty proxy leaves the default behavior
// (respects HTTP_PROXY env) intact.
func buildTransport(proxyURL string, threads int) (*http.Transport, error) {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// unreachable in practice, but never trust an assertion silently.
		return nil, fmt.Errorf("default transport is not *http.Transport")
	}
	transport := tr.Clone()

	// size the idle pool so every worker can keep its conn warm. per-host idle
	// must clear the thread count or workers past the cap re-dial each request;
	// MaxConnsPerHost stays 0 (unbounded) so the limiter, not the pool, paces us.
	transport.MaxIdleConns = maxIdleConns
	transport.MaxIdleConnsPerHost = idlePerHost(threads)
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = idleConnTimeout
	transport.ForceAttemptHTTP2 = true

	if proxyURL == "" {
		return transport, nil
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url %q: %w", proxyURL, err)
	}

	switch parsed.Scheme {
	case schemeHTTP, schemeHTTPS:
		transport.Proxy = http.ProxyURL(parsed)
	case schemeSOCKS5:
		// socks5 needs a custom dialer. proxy.SOCKS5 takes a forward dialer, so
		// hand it our own net.Dialer with keepalive set - the default
		// proxy.Direct has none, which would kill os-level conn pooling.
		fwd := &net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}
		dialer, err := proxy.SOCKS5("tcp", parsed.Host, nil, fwd)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy %q: %w", proxyURL, err)
		}
		ctxDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 proxy %q: dialer lacks context support", proxyURL)
		}
		transport.DialContext = ctxDialer.DialContext
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (want http/https/socks5)", parsed.Scheme)
	}

	return transport, nil
}

// idlePerHost picks the per-host idle pool size: at least the worker count so
// no worker re-dials, never below the floor so a small thread count still pools.
func idlePerHost(threads int) int {
	if threads < minIdleConnsPerHost {
		return minIdleConnsPerHost
	}
	return threads
}

// DrainClose fully reads (up to drainCap) and closes resp.Body. go only returns
// a conn to the idle pool when the body is read to EOF, so a caller that only
// closes leaks the conn and forces a fresh dial next time. Call this instead of
// a bare resp.Body.Close() to keep the pool warm. Safe on a nil response.
func DrainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	// the read result is intentionally ignored: we're discarding the body and
	// about to close it, so a copy error changes nothing we can act on.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainCap))
	resp.Body.Close()
}

// parseHeaders splits each "Key: Value" entry on the first ": ". Entries
// without the separator are rejected so a typo fails loud instead of silently.
// The returned map is always non-nil so callers can range it unconditionally.
func parseHeaders(raw []string) (map[string]string, error) {
	headers := make(map[string]string, len(raw))
	for i := 0; i < len(raw); i++ {
		key, value, ok := strings.Cut(raw[i], headerSep)
		if !ok {
			return nil, fmt.Errorf("invalid header %q (want \"Key: Value\")", raw[i])
		}
		headers[key] = value
	}

	return headers, nil
}

// roundTripper paces and decorates each request before delegating to base.
type roundTripper struct {
	base       *http.Transport
	headers    map[string]string
	cookie     string
	userAgent  string
	limiter    *rate.Limiter
	maxRetries int
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// only set what the caller hasn't already; a scanner that explicitly sets a
	// header (e.g. an api key) must win over the global default.
	for key, value := range rt.headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}
	if rt.cookie != "" && req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", rt.cookie)
	}
	if rt.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", rt.userAgent)
	}

	for attempt := 0; ; attempt++ {
		if rt.limiter != nil {
			if err := rt.limiter.Wait(req.Context()); err != nil {
				return nil, fmt.Errorf("rate limiter: %w", err)
			}
		}

		resp, err := rt.base.RoundTrip(req)
		if err != nil || attempt >= rt.maxRetries || !retryableStatus(resp.StatusCode) {
			return resp, err
		}

		// back off and retry, unless the body can't be replayed.
		if !rewind(req) {
			return resp, nil
		}
		wait := retryAfter(resp, attempt)
		DrainClose(resp)

		if err := sleepCtx(req.Context(), wait); err != nil {
			return nil, err
		}
	}
}

func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
}

const (
	retryAfterCap    = 20 * time.Second
	retryBackoffBase = 500 * time.Millisecond
	// clamp the shift so a large -max-retries can't overflow the duration.
	retryBackoffMaxShift = 16
)

// retryAfter honors a Retry-After header (delta-seconds or HTTP-date) and
// otherwise falls back to capped exponential backoff.
func retryAfter(resp *http.Response, attempt int) time.Duration {
	if v := strings.TrimSpace(resp.Header.Get("Retry-After")); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return capDuration(time.Duration(secs) * time.Second)
		}
		if t, err := http.ParseTime(v); err == nil {
			return capDuration(time.Until(t))
		}
	}
	shift := attempt
	if shift > retryBackoffMaxShift {
		shift = retryBackoffMaxShift
	}
	return capDuration(retryBackoffBase << shift)
}

// capDuration clamps d to [0, retryAfterCap].
func capDuration(d time.Duration) time.Duration {
	switch {
	case d < 0:
		return 0
	case d > retryAfterCap:
		return retryAfterCap
	default:
		return d
	}
}

// rewind restores req.Body for a resend. Only a GetBody-backed body (set by
// net/http for the in-memory bodies sif uses) is replayable; a nil or NoBody
// request needs nothing, anything else can't be retried.
func rewind(req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return true
	}
	if req.GetBody == nil {
		return false
	}
	body, err := req.GetBody()
	if err != nil {
		return false
	}
	req.Body = body
	return true
}

// sleepCtx waits for d or until ctx is cancelled, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
