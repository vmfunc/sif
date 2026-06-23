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
	"bufio"
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/dnsx"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/pool"
)

// dnsURL is a var so integration tests can repoint it at a fixture.
var dnsURL = "https://raw.githubusercontent.com/vmfunc/sif-runtime/main/dnslist/"

// dnsTransport is a var so integration tests can route the per-host probes at a
// local server instead of resolving real DNS. nil keeps http.DefaultTransport.
var dnsTransport http.RoundTripper

// hostResolver is the small slice of dnsx the dnslist worker needs: resolve a
// candidate and report whether it's a real, non-wildcard hit.
type hostResolver interface {
	Resolve(host string) (bool, error)
}

// newDNSResolver builds the resolver for one run; it's a var so integration
// tests inject a fake that answers without touching real dns. the apex is
// fingerprinted for wildcards before any candidate is checked.
var newDNSResolver = func(apex string, resolvers []string) (hostResolver, error) {
	r, err := dnsx.NewResolver(resolvers)
	if err != nil {
		return nil, fmt.Errorf("dns resolver: %w", err)
	}
	if err := r.FingerprintWildcard(apex); err != nil {
		return nil, fmt.Errorf("wildcard fingerprint: %w", err)
	}

	return r, nil
}

const (
	dnsSmallFile  = "subdomains-100.txt"
	dnsMediumFile = "subdomains-1000.txt"
	dnsBigFile    = "subdomains-10000.txt"
)

// dnsScheme labels which url won a subdomain so we don't probe the second
// scheme once the first already counted it.
type dnsScheme string

const (
	dnsSchemeHTTP  dnsScheme = "http"
	dnsSchemeHTTPS dnsScheme = "https"
)

// meaningfulStatus reports whether a probe response is a real "this host
// exists" signal rather than a 404 or a wildcard catch-all redirect. a
// wildcard-DNS host answers every candidate with the same redirect/404, so
// gating on a successful, non-redirect status keeps it from flooding results.
func meaningfulStatus(code int) bool {
	return code >= http.StatusOK && code < http.StatusMultipleChoices
}

// Dnslist performs DNS subdomain enumeration on the target domain. each
// candidate is resolved first; only names that actually resolve (and aren't a
// wildcard catch-all) are http-probed, so a big wordlist no longer means a
// http request per dead name.
func Dnslist(size string, url string, timeout time.Duration, threads int, logdir string, resolvers []string) ([]string, error) {
	log := output.Module("DNS")
	log.Start()

	var list string
	switch size {
	case "small":
		list = dnsURL + dnsSmallFile
	case "medium":
		list = dnsURL + dnsMediumFile
	case "large":
		list = dnsURL + dnsBigFile
	}

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, list, http.NoBody)
	if err != nil {
		log.Error("Error creating request: %s", err)
		return nil, err
	}
	resp, err := httpx.Client(timeout).Do(req)
	if err != nil {
		log.Error("Error downloading DNS list: %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	var dns []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		dns = append(dns, scanner.Text())
	}

	sanitizedURL := stripScheme(url)

	// resolve against dns first, fingerprinting the apex for wildcards so a
	// catch-all zone can't flood the probe step. build it once and share across
	// the workers - the underlying client is concurrency-safe.
	resolver, err := newDNSResolver(sanitizedURL, resolvers)
	if err != nil {
		log.Error("Error building DNS resolver: %s", err)
		return nil, err
	}

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, size+" subdomain fuzzing"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	// per-host probe client. dnsTransport pins every dial at a fixture in
	// integration tests; nil keeps the shared transport for real runs.
	client := httpx.Client(timeout)
	if dnsTransport != nil {
		client.Transport = dnsTransport
	}
	// don't chase redirects: a wildcard catch-all that 301s every candidate to
	// the same landing page must read as a redirect status, not a 200, so it
	// gets gated out instead of counting as a found host.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	progress := output.NewProgress(len(dns), "enumerating")

	var mu sync.Mutex

	urls := make([]string, 0, 64)
	pool.Each(dns, threads, func(domain string) {
		progress.Increment(domain)

		charmlog.Debugf("Looking up: %s", domain)

		host := domain + "." + sanitizedURL

		// dns gate: skip the http probe entirely for names that don't
		// resolve or that a wildcard zone answers. this is the whole point -
		// no request per dead candidate.
		ok, err := resolver.Resolve(host)
		if err != nil {
			charmlog.Debugf("resolve %s: %s", host, err)
			return
		}
		if !ok {
			return
		}

		// probe http first, then https - but a subdomain is recorded at
		// most once. firing both schemes and appending on each is what
		// double-counted every host on the old path.
		foundURL, scheme := probeSubdomain(client, host)
		if foundURL == "" {
			return
		}

		mu.Lock()
		urls = append(urls, foundURL)
		mu.Unlock()

		progress.Pause()
		log.Success("found: %s [%s]", output.Highlight.Render(host), scheme)
		progress.Resume()

		if logdir != "" {
			_ = logger.Write(sanitizedURL, logdir, fmt.Sprintf("[%s] %s\n", scheme, host))
		}
	})
	progress.Done()

	log.Complete(len(urls), "found")

	return urls, nil
}

// probeSubdomain tries http then https for one host and returns the resolved
// url + winning scheme on the first meaningful hit, or "" if neither scheme
// gave a real signal. trying https only when http didn't already count is the
// per-subdomain dedupe.
func probeSubdomain(client *http.Client, host string) (string, dnsScheme) {
	schemes := []struct {
		prefix string
		label  dnsScheme
	}{
		{"http://", dnsSchemeHTTP},
		{"https://", dnsSchemeHTTPS},
	}

	for i := 0; i < len(schemes); i++ {
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, schemes[i].prefix+host, http.NoBody)
		if err != nil {
			charmlog.Debugf("Error %s: %s", host, err)
			continue
		}
		resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
		if err != nil {
			charmlog.Debugf("Error %s: %s", host, err)
			continue
		}
		code := resp.StatusCode
		resolved := resp.Request.URL.String()
		// status/url only; drain so the conn returns to the pool.
		httpx.DrainClose(resp)

		if meaningfulStatus(code) {
			return resolved, schemes[i].label
		}
		charmlog.Debugf("skip %s [%s]: status %d", host, schemes[i].label, code)
	}

	return "", ""
}
