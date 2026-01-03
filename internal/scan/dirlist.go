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

package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
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
func Dirlist(size string, url string, timeout time.Duration, threads int, logdir string) ([]DirectoryResult, error) {
	log := output.Module("DIRLIST")
	log.Start()

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, size+" directory fuzzing"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	var list string
	switch size {
	case "small":
		list = directoryURL + smallFile
	case "medium":
		list = directoryURL + mediumFile
	case "large":
		list = directoryURL + bigFile
	}

	resp, err := http.Get(list)
	if err != nil {
		log.Error("Error downloading directory list: %s", err)
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

	progress := output.NewProgress(len(directories), "fuzzing")

	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(threads)

	results := make([]DirectoryResult, 0, 64)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, directory := range directories {
				if i%threads != thread {
					continue
				}

				progress.Increment(directory)

				charmlog.Debugf("%s", directory)
				resp, err := client.Get(url + "/" + directory)
				if err != nil {
					charmlog.Debugf("Error %s: %s", directory, err)
					continue
				}

				if resp.StatusCode != 404 && resp.StatusCode != 403 {
					progress.Pause()
					log.Success("found: %s [%s]", output.Highlight.Render(directory), output.Status.Render(strconv.Itoa(resp.StatusCode)))
					progress.Resume()

					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s [%s]\n", strconv.Itoa(resp.StatusCode), directory))
					}

					result := DirectoryResult{
						Url:        resp.Request.URL.String(),
						StatusCode: resp.StatusCode,
					}
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}
		}(thread)
	}
	wg.Wait()
	progress.Done()

	log.Complete(len(results), "found")

	return results, nil
}
