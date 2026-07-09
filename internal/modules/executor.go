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
	"iter"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"
	"github.com/tidwall/gjson"
	"github.com/vmfunc/sif/internal/httpx"
)

// ErrUnsupportedModuleType signals an executor for a module type that is not
// yet implemented. Returning it (rather than an empty result) keeps callers
// from mistaking "not implemented" for "scanned, found nothing".
var ErrUnsupportedModuleType = errors.New("unsupported module type")

// FuzzBudget is a scan-wide ceiling on total fuzz requests shared by every
// fuzzing module's producer across every module and target in one scan run,
// on top of each module's own FuzzMaxRequests. A nil *FuzzBudget is always
// unlimited, so callers never need to nil-check before use.
type FuzzBudget struct {
	max    int64
	sent   atomic.Int64
	warned atomic.Bool
}

// NewFuzzBudget returns a budget shared across a scan, capped at max total
// fuzz requests. max <= 0 means unlimited, in which case NewFuzzBudget
// returns nil so Reserve is a no-op cap check.
func NewFuzzBudget(maxRequests int) *FuzzBudget {
	if maxRequests <= 0 {
		return nil
	}
	return &FuzzBudget{max: int64(maxRequests)}
}

// Reserve claims one request against the budget and reports whether it fit.
// Safe for concurrent use by any number of producers across modules and
// targets; a nil receiver (unlimited) always reports true.
func (b *FuzzBudget) Reserve() bool {
	if b == nil {
		return true
	}
	return b.sent.Add(1) <= b.max
}

// warnOnce logs the scan-wide exhaustion line exactly once no matter how many
// producers hit it concurrently, so N truncated modules produce one log line
// instead of N.
func (b *FuzzBudget) warnOnce(moduleID, target string) {
	if b.warned.CompareAndSwap(false, true) {
		log.Warnf("fuzz: scan-wide budget of %d requests exhausted (module %s on %s hit it; further fuzz requests across all modules are skipped)", b.max, moduleID, target)
	}
}

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

	// disable-redirects only applies to this module's requests; opts.Client may
	// be the shared httpx client reused by every other module in the run, so a
	// module-scoped policy shallow-copies it (keeping the pooled Transport)
	// rather than mutating CheckRedirect on the shared instance.
	if cfg.DisableRedirects {
		scoped := *client
		scoped.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = &scoped
	}

	// a module with an explicit request chain runs its steps in order, threading
	// extracted variables between them; the concurrent single-request path below
	// stays the default when no chain is defined.
	if len(cfg.Requests) > 0 {
		return executeHTTPChain(ctx, client, target, def)
	}

	// Resolve paths and payload sets up front (the only failing steps); the
	// product itself is streamed and never materialized.
	paths, err := resolvePaths(cfg)
	if err != nil {
		return nil, err
	}
	sets, err := resolveSets(cfg)
	if err != nil {
		return nil, err
	}
	for _, s := range sets {
		if len(s.Values) == 0 {
			log.Warnf("fuzz: module %s has empty payload set %q on %s; no requests sent", def.ID, s.Name, target)
		}
	}

	// Determine thread count
	threads := cfg.Threads
	if threads == 0 {
		threads = opts.Threads
	}
	if threads == 0 {
		threads = 10
	}

	reqCh := make(chan *httpRequest)
	resultCh := make(chan Finding)

	// Producer: stream combinations into reqCh, stopping at the request budget
	// (0 = unlimited) and logging a single truncation line. Watches ctx so a
	// cancelled run stops pulling promptly.
	go func() {
		defer close(reqCh)
		var sent int
		budget := opts.FuzzMaxRequests
		for req := range streamRequests(target, cfg, paths, sets) {
			if ctx.Err() != nil {
				return
			}
			if budget > 0 && sent >= budget {
				log.Warnf("fuzz: module %s hit the %d-request budget on %s (further combinations skipped)", def.ID, budget, target)
				return
			}
			if !opts.FuzzGlobalBudget.Reserve() {
				opts.FuzzGlobalBudget.warnOnce(def.ID, target)
				return
			}
			select {
			case <-ctx.Done():
				return
			case reqCh <- req:
				sent++
			}
		}
	}()

	// Workers: a fixed pool pulling from reqCh; matches flow to resultCh.
	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for r := range reqCh {
				if ctx.Err() != nil {
					return
				}
				if finding, ok := executeHTTPRequest(ctx, client, r, cfg, def.Info.Severity); ok {
					select {
					case <-ctx.Done():
						return
					case resultCh <- finding:
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collector: single consumer owns result.Findings, so no mutex is needed.
	for finding := range resultCh {
		result.Findings = append(result.Findings, finding)
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

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			// a transport error breaks the chain; return whatever matched earlier.
			return result, nil
		}
		respBody, err := httpx.ReadCappedBody(resp)
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
			mc := &MatchContext{
				Resp:      resp,
				Body:      respStr,
				URL:       url,
				Duration:  elapsed,
				Extracted: vars,
			}
			if !checkMatchers(step.Matchers, step.MatchersCondition, mc) {
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

// generateHTTPRequests materializes every fuzz request. The streaming path in
// ExecuteHTTPModule does not call this; it remains for tests and any caller that
// wants the full slice. It errors only where path resolution can fail.
func generateHTTPRequests(target string, cfg *HTTPConfig) ([]*httpRequest, error) {
	paths, err := resolvePaths(cfg)
	if err != nil {
		return nil, err
	}
	sets, err := resolveSets(cfg)
	if err != nil {
		return nil, err
	}
	var requests []*httpRequest
	for req := range streamRequests(target, cfg, paths, sets) {
		requests = append(requests, req)
	}
	return requests, nil
}

// resolveSets loads any file-backed payload sets into inline values, returning
// the sets ready for streaming. It is the only place set resolution can fail.
func resolveSets(cfg *HTTPConfig) ([]PayloadSet, error) {
	sets := cfg.Payloads.Sets
	out := make([]PayloadSet, len(sets))
	for i, s := range sets {
		if s.File == "" {
			out[i] = s
			continue
		}
		vals, err := loadWordlist(s.File)
		if err != nil {
			return nil, fmt.Errorf("payloads[%s]: %w", s.Name, err)
		}
		out[i] = PayloadSet{Name: s.Name, Values: vals}
	}
	return out, nil
}

// streamRequests lazily yields one *httpRequest per fuzz combination, so at
// most one combination exists at a time. clusterbomb crosses paths against
// every set as a nested odometer, rightmost fastest; pitchfork zips them by
// index and stops at the shortest.
func streamRequests(target string, cfg *HTTPConfig, paths []string, sets []PayloadSet) iter.Seq[*httpRequest] {
	method := cfg.Method
	if method == "" {
		method = "GET"
	}
	target = strings.TrimSuffix(target, "/")

	return func(yield func(*httpRequest) bool) {
		if len(sets) == 0 {
			for _, path := range paths {
				if !yield(newFuzzRequest(method, target, path, nil, cfg)) {
					return
				}
			}
			return
		}

		if strings.EqualFold(cfg.Attack, "pitchfork") {
			n := pitchforkLen(paths, sets)
			for i := 0; i < n; i++ {
				vars := make(map[string]string, len(sets))
				for _, s := range sets {
					vars[s.Name] = s.Values[i]
				}
				if !yield(newFuzzRequest(method, target, paths[i], vars, cfg)) {
					return
				}
			}
			return
		}

		// clusterbomb: an empty set makes the product empty.
		for _, s := range sets {
			if len(s.Values) == 0 {
				return
			}
		}
		idx := make([]int, len(sets))
		for _, path := range paths {
			for {
				vars := make(map[string]string, len(sets))
				for k, s := range sets {
					vars[s.Name] = s.Values[idx[k]]
				}
				if !yield(newFuzzRequest(method, target, path, vars, cfg)) {
					return
				}
				if !advance(idx, sets) {
					break
				}
			}
			for k := range idx {
				idx[k] = 0
			}
		}
	}
}

// advance increments the odometer over set value indices, rightmost fastest,
// and reports whether a next combination exists.
func advance(idx []int, sets []PayloadSet) bool {
	for k := len(idx) - 1; k >= 0; k-- {
		idx[k]++
		if idx[k] < len(sets[k].Values) {
			return true
		}
		idx[k] = 0
	}
	return false
}

// pitchforkLen is the shortest of the path list and every set, the number of
// index-paired combinations pitchfork emits.
func pitchforkLen(paths []string, sets []PayloadSet) int {
	n := len(paths)
	for _, s := range sets {
		if len(s.Values) < n {
			n = len(s.Values)
		}
	}
	return n
}

// newFuzzRequest builds one request for a combination. It substitutes
// {{BaseURL}}, the legacy {{payload}}/{{Payload}} builtin, and every {{name}} in
// vars into the url, body and each header value. Headers are copied only when a
// substitution could apply, preserving the shared cfg.Headers map otherwise.
func newFuzzRequest(method, target, path string, vars map[string]string, cfg *HTTPConfig) *httpRequest {
	pv := vars["payload"] // drives {{payload}}/{{Payload}}; "" when no such set
	sub := func(s string) string { return substituteVariablesWithVars(s, target, pv, vars) }

	headers := cfg.Headers
	if len(cfg.Headers) > 0 {
		headers = make(map[string]string, len(cfg.Headers))
		for k, v := range cfg.Headers {
			headers[k] = sub(v)
		}
	}
	return &httpRequest{
		Method:   method,
		URL:      sub(path),
		Headers:  headers,
		Body:     sub(cfg.Body),
		Payload:  payloadLabel(vars),
		Original: path,
	}
}

// payloadLabel renders a combination for the httpRequest.Payload debug field:
// the lone value for a single set (the legacy shape), else name=value pairs in
// name order joined by "&". The field is metadata only; findings key off URL.
func payloadLabel(vars map[string]string) string {
	switch len(vars) {
	case 0:
		return ""
	case 1:
		for _, v := range vars {
			return v
		}
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + vars[k]
	}
	return strings.Join(parts, "&")
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

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()

	// Read body with limit
	respBody, err := httpx.ReadCappedBody(resp)
	if err != nil {
		return Finding{}, false
	}
	bodyStr := string(respBody)

	// extract before matching: runExtractors is side-effect-free and the finding
	// is only built on a match, so hoisting it is behavior-preserving and lets a
	// matcher read extractor values out of the context.
	extracted := runExtractors(cfg.Extractors, resp, bodyStr)

	mc := &MatchContext{
		Resp:      resp,
		Body:      bodyStr,
		URL:       r.URL,
		Duration:  elapsed,
		Extracted: extracted,
	}

	if !checkMatchers(cfg.Matchers, cfg.MatchersCondition, mc) {
		return Finding{}, false
	}

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
func checkMatchers(matchers []Matcher, condition string, mc *MatchContext) bool {
	if len(matchers) == 0 {
		return false
	}

	or := strings.EqualFold(condition, "or")
	for i := range matchers {
		matched := checkMatcher(&matchers[i], mc)
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
func checkMatcher(m *Matcher, mc *MatchContext) bool {
	switch m.Type {
	case "status":
		for _, status := range m.Status {
			if mc.Resp.StatusCode == status {
				return true
			}
		}
		return false

	case "word":
		return checkWords(getPart(m.Part, mc.Resp, mc.Body), m.Words, m.Condition, m.CaseInsensitive)

	case "regex":
		return checkRegex(getPart(m.Part, mc.Resp, mc.Body), m.Regex, m.Condition)

	case "favicon":
		return checkFaviconHash(mc.Body, m.Hash)

	case "size":
		// size matches the response body length against any listed value.
		for _, n := range m.Size {
			if len(mc.Body) == n {
				return true
			}
		}
		return false

	case "range":
		switch strings.ToLower(m.Source) {
		case "status":
			return inRange(mc.Resp.StatusCode, m.Min, m.Max)
		case "size", "":
			return inRange(len(mc.Body), m.Min, m.Max)
		default:
			return false
		}

	case "dsl":
		return evalDSL(m, mc)

	default:
		return false
	}
}

// inRange reports whether v is within the inclusive bounds; a nil bound is open.
func inRange(v int, lo, hi *int) bool {
	if lo != nil && v < *lo {
		return false
	}
	if hi != nil && v > *hi {
		return false
	}
	return true
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
func checkWords(content string, words []string, condition string, caseInsensitive bool) bool {
	if caseInsensitive {
		content = strings.ToLower(content)
	}
	fold := func(w string) string {
		if caseInsensitive {
			return strings.ToLower(w)
		}
		return w
	}
	if condition == "or" {
		for _, word := range words {
			if strings.Contains(content, fold(word)) {
				return true
			}
		}
		return false
	}
	// Default to AND
	for _, word := range words {
		if !strings.Contains(content, fold(word)) {
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
				if e.Group >= 0 && len(matches) > e.Group {
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
