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

// Package scan provides various security scanning functionalities for web applications.
// This file handles Google dorking operations.

package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
	googlesearch "github.com/rocketlaunchr/google-search"
)

const (
	dorkURL  = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/dork/"
	dorkFile = "dork.txt"
)

// DorkResult represents the result of a Google dork search.
type DorkResult struct {
	Url   string `json:"url"`   // The URL found by the dork
	Count int    `json:"count"` // The number of times this URL was found
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

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL dorking"); err != nil {
			spin.Stop()
			output.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	resp, err := http.Get(dorkURL + dorkFile)
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
	var wg sync.WaitGroup
	wg.Add(threads)

	dorkResults := []DorkResult{}
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, dork := range dorks {

				if i%threads != thread {
					continue
				}

				results, err := googlesearch.Search(nil, fmt.Sprintf("%s %s", dork, sanitizedURL))
				if err != nil {
					log.Debugf("error searching for dork %s: %v", dork, err)
					continue
				}
				if len(results) > 0 {
					spin.Stop()
					output.Success("%s dork results found for dork %s", output.Status.Render(strconv.Itoa(len(results))), output.Highlight.Render(dork))
					spin.Start()
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, strconv.Itoa(len(results))+" dork results found for dork ["+dork+"]\n")
					}

					result := DorkResult{
						Url:   dork,
						Count: len(results),
					}

					dorkResults = append(dorkResults, result)
				}
			}
		}(thread)
	}
	wg.Wait()
	spin.Stop()

	output.ScanComplete("URL dorking", len(dorkResults), "found")
	return dorkResults, nil
}
