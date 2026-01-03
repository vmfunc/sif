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
	gitURL  = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/git/"
	gitFile = "git.txt"
)

func Git(url string, timeout time.Duration, threads int, logdir string) ([]string, error) {

	fmt.Println(styles.Separator.Render("🌿 Starting " + styles.Status.Render("git repository scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "git directory fuzzing"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	gitlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Git 🌿",
	}).With("url", url)

	gitlog.Infof("Starting repository scanning")

	resp, err := http.Get(gitURL + gitFile)
	if err != nil {
		log.Errorf("Error downloading git list: %s", err)
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

				log.Debugf("%s", repourl)
				resp, err := client.Get(url + "/" + repourl)
				if err != nil {
					log.Debugf("Error %s: %s", repourl, err)
				}

				if resp.StatusCode == 200 && !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
					// log url, directory, and status code
					gitlog.Infof("%s git found at [%s]", styles.Status.Render(strconv.Itoa(resp.StatusCode)), styles.Highlight.Render(repourl))
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s git found at [%s]\n", strconv.Itoa(resp.StatusCode), repourl))
					}

					foundUrls = append(foundUrls, resp.Request.URL.String())
				}
			}
		}(thread)
	}
	wg.Wait()

	return foundUrls, nil
}
