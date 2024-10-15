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
)

const (
	directoryURL = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/dirlist/"
	smallFile    = "directory-list-2.3-small.txt"
	mediumFile   = "directory-list-2.3-medium.txt"
	bigFile      = "directory-list-2.3-big.txt"
)

type DirectoryResult struct {
	Url        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// Dirlist performs directory fuzzing on the target URL.
//
// Parameters:
//   - size: determines the size of the directory list to use ("small", "medium", or "large")
//   - url: the target URL to scan
//   - timeout: maximum duration for each request
//   - threads: number of concurrent threads to use
//   - logdir: directory to store log files (empty string for no logging)
//
// Returns:
//   - []DirectoryResult: a slice of discovered directories and their status codes
//   - error: any error encountered during the scan
func Dirlist(size string, url string, timeout time.Duration, threads int, logdir string) ([]DirectoryResult, error) {

	fmt.Println(styles.Separator.Render("📂 Starting " + styles.Status.Render("directory fuzzing") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, size+" directory fuzzing"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	dirlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dirlist 📂",
	}).With("url", url)

	var list string

	switch size {
	case "small":
		list = directoryURL + smallFile
	case "medium":
		list = directoryURL + mediumFile
	case "large":
		list = directoryURL + bigFile
	}

	dirlog.Infof("Starting %s directory listing", size)

	resp, err := http.Get(list)
	if err != nil {
		log.Errorf("Error downloading directory list: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	var directories []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		directories = append(directories, scanner.Text())
	}

	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	wg.Add(threads)

	results := []DirectoryResult{}
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, directory := range directories {
				if i%threads != thread {
					continue
				}

				log.Debugf("%s", directory)
				resp, err := client.Get(url + "/" + directory)
				if err != nil {
					log.Debugf("Error %s: %s", directory, err)
					return
				}

				if resp.StatusCode != 404 && resp.StatusCode != 403 {
					// log url, directory, and status code
					dirlog.Infof("%s [%s]", styles.Status.Render(strconv.Itoa(resp.StatusCode)), styles.Highlight.Render(directory))
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s [%s]\n", strconv.Itoa(resp.StatusCode), directory))
					}

					result := DirectoryResult{
						Url:        resp.Request.URL.String(),
						StatusCode: resp.StatusCode,
					}
					results = append(results, result)
				}
			}
		}(thread)
	}
	wg.Wait()

	return results, nil
}
