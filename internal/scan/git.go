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
	"bufio"
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/pool"
)

// gitURL is a var so integration tests can repoint it at a fixture.
var gitURL = "https://raw.githubusercontent.com/vmfunc/sif-runtime/main/git/"

const gitFile = "git.txt"

func Git(url string, timeout time.Duration, threads int, logdir string) ([]string, error) {
	log := output.Module("GIT")
	log.Start()

	spin := output.NewSpinner("Scanning for exposed git repositories")
	spin.Start()

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "git directory fuzzing"); err != nil {
			spin.Stop()
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, gitURL+gitFile, http.NoBody)
	if err != nil {
		spin.Stop()
		log.Error("Error creating git list request: %s", err)
		return nil, err
	}
	resp, err := client.Do(req)
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

	var mu sync.Mutex

	foundUrls := []string{}
	pool.Each(gitUrls, threads, func(repourl string) {
		charmlog.Debugf("%s", repourl)
		gitReq, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url+"/"+repourl, http.NoBody)
		if err != nil {
			charmlog.Debugf("Error creating request for %s: %s", repourl, err)
			return
		}
		resp, err := client.Do(gitReq) //nolint:bodyclose // drained and closed via httpx.DrainClose
		if err != nil {
			charmlog.Debugf("Error %s: %s", repourl, err)
			return
		}

		if resp.StatusCode == 200 && !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			spin.Stop()
			log.Success("Git found at %s [%s]", output.Highlight.Render(repourl), output.Status.Render(strconv.Itoa(resp.StatusCode)))
			spin.Start()
			if logdir != "" {
				logger.Write(sanitizedURL, logdir, strconv.Itoa(resp.StatusCode)+" git found at ["+repourl+"]\n")
			}

			mu.Lock()
			foundUrls = append(foundUrls, resp.Request.URL.String())
			mu.Unlock()
		}
		// status/headers only; drain so the conn returns to the pool.
		httpx.DrainClose(resp)
	})

	spin.Stop()
	log.Complete(len(foundUrls), "found")

	return foundUrls, nil
}
