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

package modules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// MaxBodySize limits response body to prevent memory exhaustion.
const MaxBodySize = 5 * 1024 * 1024

// ErrUnsupportedModuleType signals an executor for a module type that is not
// yet implemented. Returning it (rather than an empty result) keeps callers
// from mistaking "not implemented" for "scanned, found nothing".
var ErrUnsupportedModuleType = errors.New("unsupported module type")

// httpRequest represents a generated HTTP request.
type httpRequest struct {
	Method   string
	URL      string
	Headers  map[string]string
	Body     string
	Payload  string
	Original string // Original path template
}

// ExecuteHTTPModule runs an HTTP-based module.
func ExecuteHTTPModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	if def.HTTP == nil {
		return nil, fmt.Errorf("no HTTP configuration")
	}

	cfg := def.HTTP
	result := &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: make([]Finding, 0),
	}

	// Create HTTP client
	client := opts.Client
	if client == nil {
		client = &http.Client{
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}

	// a module with an explicit request chain runs its steps in order, threading
	// extracted variables between them; the concurrent single-request path below
	// stays the default when no chain is defined.
	if len(cfg.Requests) > 0 {
		return executeHTTPChain(ctx, client, target, def)
	}

	// Generate requests based on paths and payloads
	requests, err := generateHTTPRequests(target, cfg)
	if err != nil {
		return nil, err
	}

	// Determine thread count
	threads := cfg.Threads
	if threads == 0 {
		threads = opts.Threads
	}
	if threads == 0 {
		threads = 10
	}

	// Execute requests concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	resultsChan := make(chan Finding, len(requests))

	// Limit concurrency
	sem := make(chan struct{}, threads)

	for _, req := range requests {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(r *httpRequest) {
			defer wg.Done()
			defer func() { <-sem }()

			finding, ok := executeHTTPRequest(ctx, client, r, cfg, def.Info.Severity)
			if ok {
				resultsChan <- finding
			}
		}(req)
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for finding := range resultsChan {
		mu.Lock()
		result.Findings = append(result.Findings, finding)
		mu.Unlock()
	}

	return result, nil
}

// executeHTTPChain runs a module's ordered request chain. steps run in sequence
// sharing one variable map: each step's extractors feed {{name}} references in
// later steps' path, headers and body. a step with matchers records a finding
// on a match and halts the chain on a miss, so a login/setup step can gate an
// authenticated follow-up. steps are sequential by construction (a later step
// depends on an earlier one), so this path is not concurrent.
func executeHTTPChain(ctx context.Context, client *http.Client, target string, def *YAMLModule) (*Result, error) {
	result := &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: make([]Finding, 0),
	}
	base := strings.TrimSuffix(target, "/")
	vars := make(map[string]string)

	for i := range def.HTTP.Requests {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		step := &def.HTTP.Requests[i]

		method := step.Method
		if method == "" {
			method = "GET"
		}
		url := substituteVariablesWithVars(step.Path, base, "", vars)

		var bodyReader io.Reader
		if bodyStr := substituteVariablesWithVars(step.Body, base, "", vars); bodyStr != "" {
			bodyReader = strings.NewReader(bodyStr)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return result, nil
		}
		for k, v := range step.Headers {
			req.Header.Set(k, substituteVariablesWithVars(v, base, "", vars))
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", defaultUserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			// a transport error breaks the chain; return whatever matched earlier.
			return result, nil
		}
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
		resp.Body.Close()
		if err != nil {
			return result, nil
		}
		respStr := string(respBody)

		// feed this step's extractions into the shared vars for later steps,
		// regardless of whether the step also carries matchers.
		for k, v := range runExtractors(step.Extractors, resp, respStr) {
			vars[k] = v
		}

		// a step with matchers gates the chain: a match records a finding, a miss
		// means the precondition failed so the chain stops here.
		if len(step.Matchers) > 0 {
			if !checkMatchers(step.Matchers, step.MatchersCondition, resp, respStr) {
				break
			}
			result.Findings = append(result.Findings, Finding{
				URL:       url,
				Severity:  def.Info.Severity,
				Evidence:  truncateEvidence(respStr),
				Extracted: snapshotVars(vars),
			})
		}
	}

	return result, nil
}

// snapshotVars copies the running chain variables so each finding carries an
// independent view rather than aliasing the map that later steps keep mutating.
func snapshotVars(vars map[string]string) map[string]string {
	if len(vars) == 0 {
		return nil
	}
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		out[k] = v
	}
	return out
}

// generateHTTPRequests creates all requests based on paths and payloads.
func generateHTTPRequests(target string, cfg *HTTPConfig) ([]*httpRequest, error) {
	var requests []*httpRequest

	paths, err := resolvePaths(cfg)
	if err != nil {
		return nil, err
	}

	// Ensure target has no trailing slash
	target = strings.TrimSuffix(target, "/")

	method := cfg.Method
	if method == "" {
		method = "GET"
	}

	// If no payloads, just use paths directly
	if len(cfg.Payloads) == 0 {
		for _, path := range paths {
			url := substituteVariables(path, target, "")
			requests = append(requests, &httpRequest{
				Method:   method,
				URL:      url,
				Headers:  cfg.Headers,
				Body:     cfg.Body,
				Original: path,
			})
		}
		return requests, nil
	}

	// pitchfork pairs path[i] with payload[i] and stops at the shorter list;
	// clusterbomb (default) crosses every path with every payload.
	if strings.EqualFold(cfg.Attack, "pitchfork") {
		n := len(paths)
		if len(cfg.Payloads) < n {
			n = len(cfg.Payloads)
		}
		for i := 0; i < n; i++ {
			requests = append(requests, newPayloadRequest(method, target, paths[i], cfg.Payloads[i], cfg))
		}
		return requests, nil
	}

	for _, path := range paths {
		for _, payload := range cfg.Payloads {
			requests = append(requests, newPayloadRequest(method, target, path, payload, cfg))
		}
	}

	return requests, nil
}

// resolvePaths expands a wordlist over any {{word}} path templates so one
// "{{BaseURL}}/{{word}}" path fuzzes the whole list; paths without {{word}}
// pass through literally. no wordlist leaves cfg.Paths untouched.
func resolvePaths(cfg *HTTPConfig) ([]string, error) {
	if cfg.Wordlist == "" {
		return cfg.Paths, nil
	}

	words, err := loadWordlist(cfg.Wordlist)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, path := range cfg.Paths {
		if !strings.Contains(path, "{{word}}") && !strings.Contains(path, "{{Word}}") {
			paths = append(paths, path)
			continue
		}
		for _, word := range words {
			expanded := strings.ReplaceAll(path, "{{word}}", word)
			expanded = strings.ReplaceAll(expanded, "{{Word}}", word)
			paths = append(paths, expanded)
		}
	}

	return paths, nil
}

// loadWordlist reads non-empty lines from a local wordlist file, mirroring the
// dirlist scanner's scanLines so a converted module fuzzes the identical words.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist %q: %w", path, err)
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			words = append(words, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist %q: %w", path, err)
	}

	return words, nil
}

// newPayloadRequest builds one request with the path and body templates
// substituted for the given payload.
func newPayloadRequest(method, target, path, payload string, cfg *HTTPConfig) *httpRequest {
	return &httpRequest{
		Method:   method,
		URL:      substituteVariables(path, target, payload),
		Headers:  cfg.Headers,
		Body:     substituteVariables(cfg.Body, target, payload),
		Payload:  payload,
		Original: path,
	}
}

// validateAttack rejects an attack mode that is not "", "clusterbomb", or
// "pitchfork"; an empty value defaults to clusterbomb.
func validateAttack(attack string) error {
	switch strings.ToLower(attack) {
	case "", "clusterbomb", "pitchfork":
		return nil
	default:
		return fmt.Errorf("invalid attack %q (want \"clusterbomb\" or \"pitchfork\")", attack)
	}
}

// substituteVariables replaces template variables in a string.
func substituteVariables(template, baseURL, payload string) string {
	result := template
	result = strings.ReplaceAll(result, "{{BaseURL}}", baseURL)
	result = strings.ReplaceAll(result, "{{baseurl}}", baseURL)
	result = strings.ReplaceAll(result, "{{payload}}", payload)
	result = strings.ReplaceAll(result, "{{Payload}}", payload)
	return result
}

// substituteVariablesWithVars extends substituteVariables with the named values
// a request chain accumulates: after {{BaseURL}}/{{payload}} it replaces every
// {{name}} with the value an earlier step extracted under that name.
func substituteVariablesWithVars(template, baseURL, payload string, vars map[string]string) string {
	result := substituteVariables(template, baseURL, payload)
	for name, value := range vars {
		result = strings.ReplaceAll(result, "{{"+name+"}}", value)
	}
	return result
}

// defaultUserAgent is sent when a module doesn't set its own User-Agent header.
const defaultUserAgent = "Mozilla/5.0 (compatible; sif/1.0)"

// executeHTTPRequest executes a single HTTP request and checks matchers.
func executeHTTPRequest(ctx context.Context, client *http.Client, r *httpRequest, cfg *HTTPConfig, severity string) (Finding, bool) {
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
	if err != nil {
		return Finding{}, false
	}

	// Set headers
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()

	// Read body with limit
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
	if err != nil {
		return Finding{}, false
	}
	bodyStr := string(respBody)

	// Check matchers
	if !checkMatchers(cfg.Matchers, cfg.MatchersCondition, resp, bodyStr) {
		return Finding{}, false
	}

	// Extract data
	extracted := runExtractors(cfg.Extractors, resp, bodyStr)

	// favicon-only matches fire on binary icon bytes; report the hash, not the body.
	evidence := truncateEvidence(bodyStr)
	if fav, ok := faviconEvidence(cfg.Matchers, bodyStr); ok {
		evidence = fav
	}

	return Finding{
		URL:       r.URL,
		Severity:  severity,
		Evidence:  evidence,
		Extracted: extracted,
	}, true
}

// checkMatchers combines matchers with condition "and" (default, all match) or "or" (any).
func checkMatchers(matchers []Matcher, condition string, resp *http.Response, body string) bool {
	if len(matchers) == 0 {
		return false
	}

	or := strings.EqualFold(condition, "or")
	for i := range matchers {
		matched := checkMatcher(&matchers[i], resp, body)
		if matchers[i].Negative {
			matched = !matched
		}
		if or && matched {
			return true
		}
		if !or && !matched {
			return false
		}
	}

	// and: all matched; or: none matched.
	return !or
}

// validateMatchersCondition rejects a matchers-condition that is not "", "and", or "or".
func validateMatchersCondition(condition string) error {
	switch strings.ToLower(condition) {
	case "", "and", "or":
		return nil
	default:
		return fmt.Errorf("invalid matchers-condition %q (want \"and\" or \"or\")", condition)
	}
}

// checkMatcher evaluates a single matcher.
func checkMatcher(m *Matcher, resp *http.Response, body string) bool {
	switch m.Type {
	case "status":
		for _, status := range m.Status {
			if resp.StatusCode == status {
				return true
			}
		}
		return false

	case "word":
		return checkWords(getPart(m.Part, resp, body), m.Words, m.Condition)

	case "regex":
		return checkRegex(getPart(m.Part, resp, body), m.Regex, m.Condition)

	case "favicon":
		return checkFaviconHash(body, m.Hash)

	case "size":
		// size matches the response body length against any listed value.
		for _, n := range m.Size {
			if len(body) == n {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// getPart extracts the relevant part of the response.
func getPart(part string, resp *http.Response, body string) string {
	switch part {
	case "header", "headers":
		var sb strings.Builder
		for k, v := range resp.Header {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(strings.Join(v, ", "))
			sb.WriteString("\n")
		}
		return sb.String()
	case "body":
		return body
	case "all", "":
		var sb strings.Builder
		for k, v := range resp.Header {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(strings.Join(v, ", "))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
		sb.WriteString(body)
		return sb.String()
	default:
		return body
	}
}

// checkWords checks if any/all words are found.
func checkWords(content string, words []string, condition string) bool {
	if condition == "or" {
		for _, word := range words {
			if strings.Contains(content, word) {
				return true
			}
		}
		return false
	}
	// Default to AND
	for _, word := range words {
		if !strings.Contains(content, word) {
			return false
		}
	}
	return true
}

// checkRegex checks if any/all regex patterns match.
func checkRegex(content string, patterns []string, condition string) bool {
	if condition == "or" {
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(content) {
				return true
			}
		}
		return false
	}
	// Default to AND
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		if !re.MatchString(content) {
			return false
		}
	}
	return true
}

// runExtractors extracts data from the response.
func runExtractors(extractors []Extractor, resp *http.Response, body string) map[string]string {
	if len(extractors) == 0 {
		return nil
	}

	result := make(map[string]string)

	for _, e := range extractors {
		switch e.Type {
		case "regex":
			part := getPart(e.Part, resp, body)
			for _, pattern := range e.Regex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				matches := re.FindStringSubmatch(part)
				if len(matches) > e.Group {
					result[e.Name] = matches[e.Group]
					break
				}
			}
		case "kv":
			// kv records response header key/values, namespaced by the extractor
			// name when set (e.g. a headers module surfacing every header).
			for k, v := range resp.Header {
				key := k
				if e.Name != "" {
					key = e.Name + "." + k
				}
				result[key] = strings.Join(v, ", ")
			}
		case "json":
			part := getPart(e.Part, resp, body)
			for _, path := range e.JSON {
				if r := gjson.Get(part, path); r.Exists() {
					result[e.Name] = r.String()
					break
				}
			}
		}
	}

	return result
}

// truncateEvidence limits evidence length for storage.
func truncateEvidence(s string) string {
	const maxLen = 500
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ExecuteDNSModule runs a DNS-based module (not yet implemented).
// returns ErrUnsupportedModuleType so the caller logs a clear failure rather
// than reporting an empty (but successful-looking) result.
func ExecuteDNSModule(_ context.Context, _ string, def *YAMLModule, _ Options) (*Result, error) {
	return nil, fmt.Errorf("dns module %q: %w", def.ID, ErrUnsupportedModuleType)
}

// ExecuteTCPModule runs a TCP-based module (not yet implemented).
// returns ErrUnsupportedModuleType so the caller logs a clear failure rather
// than reporting an empty (but successful-looking) result.
func ExecuteTCPModule(_ context.Context, _ string, def *YAMLModule, _ Options) (*Result, error) {
	return nil, fmt.Errorf("tcp module %q: %w", def.ID, ErrUnsupportedModuleType)
}
