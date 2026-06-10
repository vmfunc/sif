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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

// source base urls are vars so tests can repoint them at local fixtures. they
// carry a trailing %s for the domain (or query) each source expects.
var (
	crtshBaseURL       = "https://crt.sh/?q=%%25.%s&output=json"
	certspotterBaseURL = "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names"
	waybackBaseURL     = "http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey"
)

// cap the response we read from any one source so a hostile/huge feed can't
// exhaust memory.
const passiveMaxBytes = 25 * 1024 * 1024

// PassiveResult holds passively-gathered subdomains and historical urls. all
// data comes from third-party feeds; the target itself sees zero traffic.
type PassiveResult struct {
	Subdomains []string `json:"subdomains"`
	URLs       []string `json:"urls"`
}

func (r *PassiveResult) ResultType() string { return "passive" }

// compile-time check so a result-type drift fails the build, not a run.
var _ ScanResult = (*PassiveResult)(nil)

// crtshEntry is one certificate record from crt.sh; name_value may itself hold
// several newline-separated names.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// certspotterEntry is one issuance from certspotter, expanded to dns names.
type certspotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

// Passive performs keyless passive recon: subdomains from certificate
// transparency feeds plus historical urls from the wayback machine. each source
// fails independently so one feed being down doesn't sink the rest.
func Passive(targetURL string, timeout time.Duration, logdir string) (*PassiveResult, error) {
	log := output.Module("PASSIVE")
	log.Start()

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target url %q: %w", targetURL, err)
	}
	domain := parsed.Hostname()
	if domain == "" {
		return nil, fmt.Errorf("target url %q has no host", targetURL)
	}

	sanitizedURL := stripScheme(targetURL)
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "passive recon"); err != nil {
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create passive log: %w", err)
		}
	}

	client := httpx.Client(timeout)
	ctx := context.TODO()

	subSet := make(map[string]struct{})
	urlSet := make(map[string]struct{})

	// crt.sh certificate transparency
	if subs, err := fetchCrtsh(ctx, client, domain); err != nil {
		log.Warn("crt.sh failed: %v", err)
	} else {
		addAll(subSet, subs)
	}

	// certspotter certificate transparency
	if subs, err := fetchCertspotter(ctx, client, domain); err != nil {
		log.Warn("certspotter failed: %v", err)
	} else {
		addAll(subSet, subs)
	}

	// wayback machine historical urls
	if urls, err := fetchWayback(ctx, client, domain); err != nil {
		log.Warn("wayback failed: %v", err)
	} else {
		addAll(urlSet, urls)
	}

	result := &PassiveResult{
		Subdomains: sortedKeys(subSet),
		URLs:       sortedKeys(urlSet),
	}

	logPassiveResults(log, sanitizedURL, logdir, result)

	log.Complete(len(result.Subdomains)+len(result.URLs), "discovered")
	return result, nil
}

// fetchCrtsh pulls subdomains from crt.sh's certificate transparency json.
func fetchCrtsh(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := passiveGET(ctx, client, fmt.Sprintf(crtshBaseURL, domain))
	if err != nil {
		return nil, err
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse crt.sh json: %w", err)
	}

	var names []string
	for i := 0; i < len(entries); i++ {
		// name_value can pack several names separated by newlines.
		for _, name := range strings.Split(entries[i].NameValue, "\n") {
			if host := normalizeHost(name); host != "" {
				names = append(names, host)
			}
		}
	}
	return names, nil
}

// fetchCertspotter pulls subdomains from certspotter's keyless issuances feed.
func fetchCertspotter(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := passiveGET(ctx, client, fmt.Sprintf(certspotterBaseURL, domain))
	if err != nil {
		return nil, err
	}

	var entries []certspotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse certspotter json: %w", err)
	}

	var names []string
	for i := 0; i < len(entries); i++ {
		for _, name := range entries[i].DNSNames {
			if host := normalizeHost(name); host != "" {
				names = append(names, host)
			}
		}
	}
	return names, nil
}

// fetchWayback pulls historical urls from the wayback machine cdx index, which
// returns one original url per line.
func fetchWayback(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := passiveGET(ctx, client, fmt.Sprintf(waybackBaseURL, domain))
	if err != nil {
		return nil, err
	}

	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	// historical urls can be long; give the scanner a generous line buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wayback lines: %w", err)
	}
	return urls, nil
}

// passiveGET performs a bounded GET against a passive source. non-200 responses
// are treated as a source failure so the caller can skip it.
func passiveGET(ctx context.Context, client *http.Client, reqURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	// the non-200 branch returns before reading the body, so drain on close to
	// keep the conn reusable instead of leaking it.
	defer httpx.DrainClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, passiveMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return body, nil
}

// normalizeHost lowercases a name and strips a leading wildcard label so
// "*.example.com" and "EXAMPLE.com" collapse to one canonical host.
func normalizeHost(name string) string {
	host := strings.ToLower(strings.TrimSpace(name))
	host = strings.TrimPrefix(host, "*.")
	return host
}

// addAll inserts every value into the dedupe set.
func addAll(set map[string]struct{}, values []string) {
	for _, v := range values {
		set[v] = struct{}{}
	}
}

func logPassiveResults(log *output.ModuleLogger, sanitizedURL, logdir string, result *PassiveResult) {
	for _, sub := range result.Subdomains {
		log.Success("subdomain: %s", output.Highlight.Render(sub))
	}
	for _, u := range result.URLs {
		log.Info("url: %s", u)
	}

	if logdir == "" {
		return
	}

	var sb strings.Builder
	if len(result.Subdomains) > 0 {
		sb.WriteString(fmt.Sprintf("Subdomains (%d):\n", len(result.Subdomains)))
		for _, sub := range result.Subdomains {
			sb.WriteString("  " + sub + "\n")
		}
	}
	if len(result.URLs) > 0 {
		sb.WriteString(fmt.Sprintf("\nHistorical URLs (%d):\n", len(result.URLs)))
		for _, u := range result.URLs {
			sb.WriteString("  " + u + "\n")
		}
	}
	_ = logger.Write(sanitizedURL, logdir, sb.String())
}
