/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                                  SIF                                         ║
║                                                                              ║
║        Blazing-fast pentesting suite written in Go                           ║
║                                                                              ║
║        Copyright (c) 2023-2024 vmfunc, xyzeva, lunchcat contributors         ║
║                    and other sif contributors.                               ║
║                                                                              ║
║                                                                              ║
║        Use of this tool is restricted to research and educational            ║
║        purposes only. Usage in a production environment outside              ║
║        of these categories is strictly prohibited.                           ║
║                                                                              ║
║        Any person or entity wishing to use this tool outside of              ║
║        research or educational purposes must purchase a license              ║
║        from https://lunchcat.dev                                             ║
║                                                                              ║
║        For more information, visit: https://github.com/lunchcat/sif          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

// Package scan provides various security scanning functionalities for web applications.
// This file handles Google dorking operations.

package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
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

	fmt.Println(styles.Separator.Render("🤓 Starting " + styles.Status.Render("URL Dorking") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL dorking"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	dorklog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dorking 🤓",
	}).With("url", url)

	dorklog.Infof("Starting URL dorking...")

	resp, err := http.Get(dorkURL + dorkFile)
	if err != nil {
		log.Errorf("Error downloading dork list: %s", err)
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

				results, _ := googlesearch.Search(nil, fmt.Sprintf("%s %s", dork, sanitizedURL))
				if len(results) > 0 {
					dorklog.Infof("%s dork results found for dork [%s]", styles.Status.Render(strconv.Itoa(len(results))), styles.Highlight.Render(dork))
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s dork results found for dork [%s]\n", strconv.Itoa(len(results)), dork))
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

	return dorkResults, nil
}
