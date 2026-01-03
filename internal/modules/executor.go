/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// MaxBodySize limits response body to prevent memory exhaustion.
const MaxBodySize = 5 * 1024 * 1024

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

	// Generate requests based on paths and payloads
	requests := generateHTTPRequests(target, cfg)

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

// generateHTTPRequests creates all requests based on paths and payloads.
func generateHTTPRequests(target string, cfg *HTTPConfig) []*httpRequest {
	var requests []*httpRequest

	// Ensure target has no trailing slash
	target = strings.TrimSuffix(target, "/")

	method := cfg.Method
	if method == "" {
		method = "GET"
	}

	// If no payloads, just use paths directly
	if len(cfg.Payloads) == 0 {
		for _, path := range cfg.Paths {
			url := substituteVariables(path, target, "")
			requests = append(requests, &httpRequest{
				Method:   method,
				URL:      url,
				Headers:  cfg.Headers,
				Body:     cfg.Body,
				Original: path,
			})
		}
		return requests
	}

	// Generate requests with payloads
	for _, path := range cfg.Paths {
		for _, payload := range cfg.Payloads {
			url := substituteVariables(path, target, payload)
			body := substituteVariables(cfg.Body, target, payload)
			requests = append(requests, &httpRequest{
				Method:   method,
				URL:      url,
				Headers:  cfg.Headers,
				Body:     body,
				Payload:  payload,
				Original: path,
			})
		}
	}

	return requests
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sif/1.0)")
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
	if !checkMatchers(cfg.Matchers, resp, bodyStr) {
		return Finding{}, false
	}

	// Extract data
	extracted := runExtractors(cfg.Extractors, resp, bodyStr)

	return Finding{
		URL:       r.URL,
		Severity:  severity,
		Evidence:  truncateEvidence(bodyStr),
		Extracted: extracted,
	}, true
}

// checkMatchers evaluates all matchers against the response.
func checkMatchers(matchers []Matcher, resp *http.Response, body string) bool {
	if len(matchers) == 0 {
		return false
	}

	// Default to AND condition across matchers
	for _, m := range matchers {
		matched := checkMatcher(m, resp, body)
		if m.Negative {
			matched = !matched
		}
		if !matched {
			return false // AND logic
		}
	}

	return true
}

// checkMatcher evaluates a single matcher.
func checkMatcher(m Matcher, resp *http.Response, body string) bool {
	part := getPart(m.Part, resp, body)

	switch m.Type {
	case "status":
		for _, status := range m.Status {
			if resp.StatusCode == status {
				return true
			}
		}
		return false

	case "word":
		return checkWords(part, m.Words, m.Condition)

	case "regex":
		return checkRegex(part, m.Regex, m.Condition)

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
		part := getPart(e.Part, resp, body)

		switch e.Type {
		case "regex":
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

// ExecuteDNSModule runs a DNS-based module (stub for now).
func ExecuteDNSModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	// TODO: Implement DNS module execution
	return &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: []Finding{},
	}, nil
}

// ExecuteTCPModule runs a TCP-based module (stub for now).
func ExecuteTCPModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	// TODO: Implement TCP module execution
	return &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: []Finding{},
	}, nil
}
