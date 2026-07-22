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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// RedirectResult collects every open-redirect found on the target.
type RedirectResult struct {
	Findings     []RedirectFinding `json:"findings,omitempty"`
	TestedParams int               `json:"tested_params"`
}

// RedirectFinding is a single param/payload that sends the user off-site.
type RedirectFinding struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Location  string `json:"location"`
	Via       string `json:"via"` // header, meta-refresh, or javascript
	Severity  string `json:"severity"`
}

// redirectMaxBody caps the body we scan for meta/js redirects (100KB).
const redirectMaxBody = 1024 * 100

// the controlled sentinel host we steer redirects toward; a Location that lands
// on it proves the param is attacker-controlled.
const redirectSentinel = "sif-redirect-probe.evil.com"

// params that commonly drive a server-side redirect.
var redirectParams = []string{
	"url", "next", "redirect", "redirect_uri", "redirect_url",
	"return", "return_url", "returnurl", "returnto", "return_to",
	"dest", "destination", "continue", "goto", "go", "target",
	"to", "out", "view", "image_url", "checkout_url", "rurl", "u",
}

// payload variants: a plain sentinel plus filter bypasses that browsers still
// resolve as an absolute off-site target. {host} expands to the sentinel.
var redirectPayloads = []string{
	"https://{host}",          // plain absolute
	"//{host}",                // scheme-relative
	"https:/{host}",           // missing slash, browsers normalise it
	"https:{host}",            // no slashes
	"/\\{host}",               // backslash trick
	"/%2f%2f{host}",           // encoded scheme-relative
	"https://{host}%00.x.com", // null-byte truncation
	"https://x.com@{host}",    // userinfo confusion - real host is after @
}

// meta refresh redirect: <meta http-equiv="refresh" content="0;url=...">
var metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'>\s]+)`)

// client-side redirects baked into a script body
var jsRedirectRe = regexp.MustCompile(`(?i)(?:location\.(?:href|replace|assign)\s*(?:=|\()|window\.location\s*=)\s*["']([^"']+)["']`)

// a leading http(s) scheme and its authority slashes, however few.
var schemeSlashesRe = regexp.MustCompile(`(?i)^(https?):/*`)

// Redirect probes the target's redirect-prone params for open-redirect.
func Redirect(targetURL string, timeout time.Duration, threads int, logdir string) (*RedirectResult, error) {
	log := output.Module("REDIRECT")
	log.Start()

	spin := output.NewSpinner("Scanning for open redirects")
	spin.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "open redirect probe"); err != nil {
			spin.Stop()
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create redirect log: %w", err)
		}
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		spin.Stop()
		return nil, fmt.Errorf("parse url: %w", err)
	}
	existingParams := parsedURL.Query()

	// merge target's own params with the common redirect names so we cover both
	paramsToTest := make(map[string]bool, len(existingParams)+len(redirectParams))
	for param := range existingParams {
		paramsToTest[param] = true
	}
	for _, param := range redirectParams {
		paramsToTest[param] = true
	}

	// don't auto-follow: a 30x Location is exactly what we want to inspect.
	client := httpx.Client(timeout)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result := &RedirectResult{
		Findings:     make([]RedirectFinding, 0, 8),
		TestedParams: len(paramsToTest),
	}

	type workItem struct {
		param   string
		payload string
	}
	workItems := make([]workItem, 0, len(paramsToTest)*len(redirectPayloads))
	for param := range paramsToTest {
		for _, raw := range redirectPayloads {
			workItems = append(workItems, workItem{param: param, payload: strings.ReplaceAll(raw, "{host}", redirectSentinel)})
		}
	}

	log.Info("testing %d params with %d payloads", len(paramsToTest), len(redirectPayloads))

	workChan := make(chan workItem, len(workItems))
	for _, item := range workItems {
		workChan <- item
	}
	close(workChan)

	seen := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(threads)
	for t := 0; t < threads; t++ {
		go func() {
			defer wg.Done()
			for item := range workChan {
				testURL := buildRedirectURL(parsedURL, existingParams, item.param, item.payload)

				location, via, ok := probeRedirect(client, testURL)
				if !ok {
					continue
				}

				key := item.param + "|" + item.payload
				mu.Lock()
				if seen[key] {
					mu.Unlock()
					continue
				}
				seen[key] = true
				finding := RedirectFinding{
					URL:       testURL,
					Parameter: item.param,
					Payload:   item.payload,
					Location:  location,
					Via:       via,
					Severity:  "medium",
				}
				result.Findings = append(result.Findings, finding)
				mu.Unlock()

				spin.Stop()
				log.Warn("open redirect via %s in param %s -> %s",
					output.SeverityMedium.Render(via),
					output.Highlight.Render(item.param),
					output.Status.Render(location))
				spin.Start()

				if logdir != "" {
					logger.Write(sanitizedURL, logdir,
						fmt.Sprintf("open redirect: param [%s] via %s -> [%s] (payload %s)\n",
							item.param, via, location, item.payload))
				}
			}
		}()
	}
	wg.Wait()

	spin.Stop()

	if len(result.Findings) == 0 {
		log.Info("no open redirects detected")
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // no finding is not an error, mirrors the other scanners
	}

	log.Complete(len(result.Findings), "found")
	return result, nil
}

// buildRedirectURL rebuilds the target with the payload injected into one param,
// preserving the rest of the original query.
func buildRedirectURL(parsedURL *url.URL, existing url.Values, param, payload string) string {
	testParams := url.Values{}
	for k, v := range existing {
		if k != param {
			testParams[k] = v
		}
	}
	testParams.Set(param, payload)
	return fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, testParams.Encode())
}

// probeRedirect requests testURL and reports the first off-site redirect it
// finds, whether that's a 30x Location header, a meta-refresh, or a js
// location assignment. via names the channel; ok is false when nothing points
// at the sentinel.
func probeRedirect(client *http.Client, testURL string) (location, via string, ok bool) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, testURL, http.NoBody)
	if err != nil {
		charmlog.Debugf("redirect: build request for %s: %v", testURL, err)
		return "", "", false
	}
	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		charmlog.Debugf("redirect: request %s: %v", testURL, err)
		return "", "", false
	}
	// the header-redirect branch returns before reading the body, so drain on
	// close to keep that conn reusable instead of leaking it.
	defer httpx.DrainClose(resp)

	// header redirect: a 30x whose Location resolves to the sentinel host
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		if loc := resp.Header.Get("Location"); pointsAtSentinel(loc) {
			return loc, "header", true
		}
	}

	// body redirects: meta refresh or a client-side location assignment
	body, err := io.ReadAll(io.LimitReader(resp.Body, redirectMaxBody))
	if err != nil {
		return "", "", false
	}
	bodyStr := string(body)

	if m := metaRefreshRe.FindStringSubmatch(bodyStr); len(m) > 1 && pointsAtSentinel(m[1]) {
		return m[1], "meta-refresh", true
	}
	if m := jsRedirectRe.FindStringSubmatch(bodyStr); len(m) > 1 && pointsAtSentinel(m[1]) {
		return m[1], "javascript", true
	}

	return "", "", false
}

// pointsAtSentinel reports whether a redirect target lands on our controlled
// host. We resolve the value the way a browser would so scheme-relative ("//x")
// and backslash tricks are caught, then compare hostnames - a sentinel that only
// shows up in a path or query (still same-origin) is not a redirect off-site.
func pointsAtSentinel(location string) bool {
	if location == "" {
		return false
	}

	// a location like " //host" or "htt\tps://host" still navigates off-site
	// in a browser even though it fails net/url's stricter parse.
	location = stripURLWhitespace(location)
	if location == "" {
		return false
	}

	// browsers treat backslashes in the authority as forward slashes
	normalized := strings.ReplaceAll(location, "\\", "/")

	// "https:/host" still navigates off-site; normalise the slashes so it parses.
	normalized = schemeSlashesRe.ReplaceAllString(normalized, "$1://")

	parsed, err := url.Parse(normalized)
	if err != nil {
		// unparseable but still naming the sentinel as the leading authority is a hit
		return strings.HasPrefix(strings.TrimLeft(normalized, "/:"), redirectSentinel)
	}

	// the resolved host is what the navigation actually targets
	if strings.EqualFold(parsed.Hostname(), redirectSentinel) {
		return true
	}

	// scheme-relative "//host" parses with an empty scheme but a populated host
	if parsed.Host != "" && strings.EqualFold(stripPort(parsed.Host), redirectSentinel) {
		return true
	}

	return false
}

// stripURLWhitespace mirrors the whatwg url parser's whitespace pass: trim
// leading/trailing c0 control or space, then strip every tab, cr and lf
// wherever they occur.
func stripURLWhitespace(s string) string {
	s = strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
	return strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(s)
}

// stripPort drops a trailing :port so host comparisons ignore it.
func stripPort(host string) string {
	if h, _, ok := strings.Cut(host, ":"); ok {
		return h
	}
	return host
}

// ResultType identifies open-redirect findings for the result registry.
func (r *RedirectResult) ResultType() string { return "redirect" }

var _ ScanResult = (*RedirectResult)(nil)
