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
	"fmt"
	"net/http"
	"net/url"
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

// Options carries the runtime knobs that apply to every outbound request.
// RateLimit is requests/sec (0 = unlimited); Headers are "Key: Value" strings.
type Options struct {
	Proxy     string
	Headers   []string
	Cookie    string
	UserAgent string
	RateLimit int
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
	base, err := buildTransport(opts.Proxy)
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
		base:      base,
		headers:   headers,
		cookie:    opts.Cookie,
		userAgent: opts.UserAgent,
		limiter:   limiter,
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

// buildTransport clones the default transport and applies the proxy. An empty
// proxy leaves the default behavior (respects HTTP_PROXY env) intact.
func buildTransport(proxyURL string) (*http.Transport, error) {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// unreachable in practice, but never trust an assertion silently.
		return nil, fmt.Errorf("default transport is not *http.Transport")
	}
	transport := tr.Clone()

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
		// socks5 needs a custom dialer; the returned dialer implements
		// ContextDialer so cancellation/timeouts propagate.
		dialer, err := proxy.SOCKS5("tcp", parsed.Host, nil, proxy.Direct)
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
	base      *http.Transport
	headers   map[string]string
	cookie    string
	userAgent string
	limiter   *rate.Limiter
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.limiter != nil {
		if err := rt.limiter.Wait(req.Context()); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}
	}

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

	return rt.base.RoundTrip(req)
}
