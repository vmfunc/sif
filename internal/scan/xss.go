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
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

// XSSResult collects every likely reflected-xss point on the target.
type XSSResult struct {
	Findings     []XSSFinding `json:"findings,omitempty"`
	TestedParams int          `json:"tested_params"`
}

// XSSFinding is a reflection where one or more breaking chars survived
// unescaped in a context that makes injection plausible.
type XSSFinding struct {
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter"`
	Context     string   `json:"context"`      // html, attribute, or script
	SurvivedRaw []string `json:"survived_raw"` // breaking chars echoed unescaped
	Severity    string   `json:"severity"`
}

// xssMaxBody caps the body we scan for the canary (100KB).
const xssMaxBody = 1024 * 100

// canaryToken is a unique, alnum-only marker we can grep for unambiguously; it
// survives every output encoder so a missing reflection means no echo at all.
const canaryToken = "sifxss9173canary" //nolint:gosec // not a credential, just a reflection marker

// the chars that let an attacker break out of a context; we inject the canary
// wrapped in each and check which come back raw.
var xssBreakChars = []string{"<", ">", "\"", "'", "`"}

// params we test when the target carries none of its own.
var xssParams = []string{
	"q", "s", "search", "query", "id", "name", "page",
	"keyword", "lang", "redirect", "url", "return", "ref",
	"message", "msg", "error", "title", "text", "comment",
}

// XSS probes the target's params for reflected cross-site scripting.
func XSS(targetURL string, timeout time.Duration, threads int, logdir string) (*XSSResult, error) {
	log := output.Module("XSS")
	log.Start()

	spin := output.NewSpinner("Scanning for reflected XSS")
	spin.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "reflected XSS probe"); err != nil {
			spin.Stop()
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create xss log: %w", err)
		}
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		spin.Stop()
		return nil, fmt.Errorf("parse url: %w", err)
	}
	existingParams := parsedURL.Query()

	paramsToTest := make(map[string]bool, len(existingParams)+len(xssParams))
	for param := range existingParams {
		paramsToTest[param] = true
	}
	for _, param := range xssParams {
		paramsToTest[param] = true
	}

	client := httpx.Client(timeout)
	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= corsMaxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}

	result := &XSSResult{
		Findings:     make([]XSSFinding, 0, 8),
		TestedParams: len(paramsToTest),
	}

	params := make([]string, 0, len(paramsToTest))
	for param := range paramsToTest {
		params = append(params, param)
	}

	log.Info("testing %d params with reflection canary", len(paramsToTest))

	paramChan := make(chan string, len(params))
	for _, param := range params {
		paramChan <- param
	}
	close(paramChan)

	seen := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(threads)
	for t := 0; t < threads; t++ {
		go func() {
			defer wg.Done()
			for param := range paramChan {
				finding, ok := probeXSS(client, parsedURL, existingParams, param)
				if !ok {
					continue
				}

				mu.Lock()
				if seen[param] {
					mu.Unlock()
					continue
				}
				seen[param] = true
				result.Findings = append(result.Findings, finding)
				mu.Unlock()

				spin.Stop()
				log.Warn("reflected xss in param %s (%s context, raw: %s)",
					output.Highlight.Render(param),
					output.SeverityHigh.Render(finding.Context),
					strings.Join(finding.SurvivedRaw, ""))
				spin.Start()

				if logdir != "" {
					logger.Write(sanitizedURL, logdir,
						fmt.Sprintf("reflected XSS: param [%s] in %s context, unescaped chars [%s]\n",
							param, finding.Context, strings.Join(finding.SurvivedRaw, "")))
				}
			}
		}()
	}
	wg.Wait()

	spin.Stop()

	if len(result.Findings) == 0 {
		log.Info("no reflected xss detected")
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // no finding is not an error, mirrors the other scanners
	}

	log.Complete(len(result.Findings), "found")
	return result, nil
}

// probeXSS injects a canary wrapped in the breaking chars into one param, then
// inspects the reflection: it classifies where the canary landed and which
// breaking chars came back unescaped there. ok is false unless at least one
// dangerous char survived in an exploitable context.
func probeXSS(client *http.Client, parsedURL *url.URL, existing url.Values, param string) (XSSFinding, bool) {
	// wrap the canary so a single request tells us both that it reflected and
	// which surrounding chars survived: <canary> "canary' `canary`
	payload := fmt.Sprintf("<%s>\"%s'`%s`", canaryToken, canaryToken, canaryToken)

	testParams := url.Values{}
	for k, v := range existing {
		if k != param {
			testParams[k] = v
		}
	}
	testParams.Set(param, payload)
	testURL := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, testParams.Encode())

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, testURL, http.NoBody)
	if err != nil {
		charmlog.Debugf("xss: build request for %s: %v", testURL, err)
		return XSSFinding{}, false
	}
	resp, err := client.Do(req)
	if err != nil {
		charmlog.Debugf("xss: request %s: %v", testURL, err)
		return XSSFinding{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, xssMaxBody))
	resp.Body.Close()
	if err != nil {
		return XSSFinding{}, false
	}
	bodyStr := string(body)

	// no echo of the canary at all means the param isn't reflected; bail early.
	if !strings.Contains(bodyStr, canaryToken) {
		return XSSFinding{}, false
	}

	reflectCtx := classifyXSSContext(bodyStr)
	survived := survivingBreakChars(bodyStr)

	// a reflection that escaped every dangerous char can't break out, so it's not
	// reported - only raw chars that matter in the detected context count.
	survived = relevantForContext(reflectCtx, survived)
	if len(survived) == 0 {
		return XSSFinding{}, false
	}

	return XSSFinding{
		URL:         testURL,
		Parameter:   param,
		Context:     reflectCtx,
		SurvivedRaw: survived,
		Severity:    "high",
	}, true
}

// classifyXSSContext guesses where the canary was reflected. We look at the
// markup immediately around the token: a live <canary> tag means html text, a
// reflection inside a <script> block means js, otherwise it sits in an attribute
// value. The html-tag check wins because it's the most directly exploitable.
func classifyXSSContext(body string) string {
	// a surviving "<canary>" means the < and > both passed through into markup
	if strings.Contains(body, "<"+canaryToken+">") {
		return "html"
	}

	// reflected between <script> ... </script> is a script context
	for {
		open := strings.Index(body, "<script")
		if open < 0 {
			break
		}
		closeIdx := strings.Index(body[open:], "</script>")
		if closeIdx < 0 {
			break
		}
		segment := body[open : open+closeIdx]
		if strings.Contains(segment, canaryToken) {
			return "script"
		}
		body = body[open+closeIdx+len("</script>"):]
	}

	// default: echoed inside an html attribute value
	return "attribute"
}

// survivingBreakChars reports which dangerous chars came back next to the canary
// unescaped. We only trust occurrences adjacent to the token so unrelated chars
// elsewhere on the page don't create false positives.
func survivingBreakChars(body string) []string {
	survived := make([]string, 0, len(xssBreakChars))
	markers := []string{
		"<" + canaryToken,  // leading < survived
		canaryToken + ">",  // trailing > survived
		"\"" + canaryToken, // leading " survived
		canaryToken + "'",  // trailing ' survived
		"`" + canaryToken,  // backtick wrap survived (token + ` and ` + token)
		canaryToken + "`",
	}
	present := make(map[string]bool, len(xssBreakChars))
	for i := 0; i < len(markers); i++ {
		if !strings.Contains(body, markers[i]) {
			continue
		}
		switch {
		case strings.HasPrefix(markers[i], "<"):
			present["<"] = true
		case strings.HasSuffix(markers[i], ">"):
			present[">"] = true
		case strings.HasPrefix(markers[i], "\""):
			present["\""] = true
		case strings.HasSuffix(markers[i], "'"):
			present["'"] = true
		default:
			present["`"] = true
		}
	}

	// keep the canonical order for stable output
	for i := 0; i < len(xssBreakChars); i++ {
		if present[xssBreakChars[i]] {
			survived = append(survived, xssBreakChars[i])
		}
	}
	return survived
}

// relevantForContext filters surviving chars to the ones that actually enable a
// breakout in the detected context: angle brackets matter in html, quotes and
// backticks matter inside attributes/scripts.
func relevantForContext(reflectCtx string, survived []string) []string {
	wanted := make(map[string]bool, len(survived))
	switch reflectCtx {
	case "html":
		wanted["<"] = true
		wanted[">"] = true
	case "attribute":
		// breaking out of an attribute value needs the quote that delimits it; a
		// bare backtick isn't a delimiter in html, so it doesn't count here.
		wanted["\""] = true
		wanted["'"] = true
	case "script":
		// a quote, backtick, or angle bracket all let you close/escape the script
		wanted["\""] = true
		wanted["'"] = true
		wanted["`"] = true
		wanted["<"] = true
		wanted[">"] = true
	}

	filtered := make([]string, 0, len(survived))
	for i := 0; i < len(survived); i++ {
		if wanted[survived[i]] {
			filtered = append(filtered, survived[i])
		}
	}
	return filtered
}

// ResultType identifies reflected-xss findings for the result registry.
func (r *XSSResult) ResultType() string { return "xss" }

var _ ScanResult = (*XSSResult)(nil)
