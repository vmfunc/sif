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

// Package scan provides various security scanning functionalities for web applications.
// This file handles Google dorking operations.

package scan

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	googlesearch "github.com/rocketlaunchr/google-search"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/pool"
)

const (
	dorkURL  = "https://raw.githubusercontent.com/vmfunc/sif-runtime/main/dork/"
	dorkFile = "dork.txt"
)

// DorkResult represents a single URL found by a Google dork search.
type DorkResult struct {
	Url   string `json:"url"`   // The URL found by the dork
	Dork  string `json:"dork"`  // The dork query that surfaced this URL
	Count int    `json:"count"` // The number of times this URL appeared in the dork's results
}

// Dork performs Google dorking operations on the target URL.
// It uses a predefined list of dorks to search for potentially sensitive information.
//
// Parameters:
//   - url: The target URL to dork
//   - timeout: Maximum duration for each dork search
//   - threads: Number of concurrent threads to use
//   - logdir: Directory to store log files (empty string for no logging)
//
// Returns:
//   - []DorkResult: A slice of results from the dorking operation
//   - error: Any error encountered during the dorking process
func Dork(url string, timeout time.Duration, threads int, logdir string) ([]DorkResult, error) {
	output.ScanStart("URL dorking")

	spin := output.NewSpinner("Running Google dorks")
	spin.Start()

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL dorking"); err != nil {
			spin.Stop()
			output.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	ctx := context.TODO()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dorkURL+dorkFile, http.NoBody)
	if err != nil {
		spin.Stop()
		output.Error("Error creating dork list request: %s", err)
		return nil, err
	}
	resp, err := httpx.Client(timeout).Do(req)
	if err != nil {
		spin.Stop()
		output.Error("Error downloading dork list: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	var dorks []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		dorks = append(dorks, scanner.Text())
	}

	// util.InitProgressBar()
	var mu sync.Mutex

	dorkResults := []DorkResult{}
	pool.Each(dorks, threads, func(dork string) {
		results, err := googlesearch.Search(context.TODO(), fmt.Sprintf("%s %s", dork, sanitizedURL))
		if err != nil {
			log.Debugf("error searching for dork %s: %v", dork, err)
			return
		}
		if len(results) > 0 {
			spin.Stop()
			output.Success("%s dork results found for dork %s", output.Status.Render(strconv.Itoa(len(results))), output.Highlight.Render(dork))
			spin.Start()
			if logdir != "" {
				_ = logger.Write(sanitizedURL, logdir, strconv.Itoa(len(results))+" dork results found for dork ["+dork+"]\n")
			}

			mu.Lock()
			dorkResults = append(dorkResults, groupDorkResults(dork, results)...)
			mu.Unlock()
		}
	})
	spin.Stop()

	output.ScanComplete("URL dorking", len(dorkResults), "found")
	return dorkResults, nil
}

// groupDorkResults turns the raw search hits for a single dork query into
// DorkResults, one per unique URL found, with Count tracking how many times
// that URL showed up in the query's results. Results with an empty URL are
// dropped since there is nothing to report.
func groupDorkResults(dork string, results []googlesearch.Result) []DorkResult {
	counts := make(map[string]int, len(results))
	order := make([]string, 0, len(results))
	for _, r := range results {
		if r.URL == "" {
			continue
		}
		if counts[r.URL] == 0 {
			order = append(order, r.URL)
		}
		counts[r.URL]++
	}

	out := make([]DorkResult, 0, len(order))
	for _, foundURL := range order {
		out = append(out, DorkResult{
			Url:   foundURL,
			Dork:  dork,
			Count: counts[foundURL],
		})
	}
	return out
}
