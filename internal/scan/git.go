/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"bufio"
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
	gitURL  = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/git/"
	gitFile = "git.txt"
)

func Git(url string, timeout time.Duration, threads int, logdir string) ([]string, error) {
	log := output.Module("GIT")
	log.Start()

	spin := output.NewSpinner("Scanning for exposed git repositories")
	spin.Start()

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "git directory fuzzing"); err != nil {
			spin.Stop()
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	resp, err := http.Get(gitURL + gitFile)
	if err != nil {
		spin.Stop()
		log.Error("Error downloading git list: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	var gitUrls []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		gitUrls = append(gitUrls, scanner.Text())
	}

	// util.InitProgressBar()
	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	wg.Add(threads)

	foundUrls := []string{}
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, repourl := range gitUrls {
				if i%threads != thread {
					continue
				}

				charmlog.Debugf("%s", repourl)
				resp, err := client.Get(url + "/" + repourl)
				if err != nil {
					charmlog.Debugf("Error %s: %s", repourl, err)
				}

				if resp.StatusCode == 200 && !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
					spin.Stop()
					log.Success("Git found at %s [%s]", output.Highlight.Render(repourl), output.Status.Render(strconv.Itoa(resp.StatusCode)))
					spin.Start()
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, strconv.Itoa(resp.StatusCode)+" git found at ["+repourl+"]\n")
					}

					foundUrls = append(foundUrls, resp.Request.URL.String())
				}
			}
		}(thread)
	}
	wg.Wait()

	spin.Stop()
	log.Complete(len(foundUrls), "found")

	return foundUrls, nil
}
