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

// The scan package provides a collection of security scanning functions.
//
// Each scanning function typically returns a slice of custom result structures and an error.
// The package utilizes concurrent operations to improve scanning performance and provides
// options for logging and timeout management.
package scan

import (
	"bufio"
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

func fetchRobotsTXT(url string, client *http.Client) *http.Response {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url, http.NoBody)
	if err != nil {
		log.Debugf("Error creating request for robots.txt: %s", err)
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Debugf("Error fetching robots.txt: %s", err)
		return nil
	}

	if resp.StatusCode == http.StatusMovedPermanently {
		redirectURL := resp.Header.Get("Location")
		if redirectURL == "" {
			log.Debugf("Redirect location is empty for %s", url)
			return nil
		}
		resp.Body.Close()
		return fetchRobotsTXT(redirectURL, client)
	}

	return resp
}

// Scan performs a basic URL scan, including checks for robots.txt and other common endpoints.
// It logs the results and doesn't return any values.
//
// Parameters:
//   - url: the target URL to scan
//   - timeout: maximum duration for the scan
//   - threads: number of concurrent threads to use
//   - logdir: directory to store log files (empty string for no logging)
func Scan(url string, timeout time.Duration, threads int, logdir string) {
	output.ScanStart("base URL scanning")

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL scanning"); err != nil {
			output.Error("Error creating log file: %v", err)
			return
		}
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp := fetchRobotsTXT(url+"/robots.txt", client)
	if resp == nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 && resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 {
		output.Success("File %s found", output.Status.Render("robots.txt"))

		var robotsData []string
		scanner := bufio.NewScanner(resp.Body)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			robotsData = append(robotsData, scanner.Text())
		}

		var wg sync.WaitGroup
		wg.Add(threads)
		for thread := 0; thread < threads; thread++ {
			go func(thread int) {
				defer wg.Done()

				for i, robot := range robotsData {
					if i%threads != thread {
						continue
					}

					if robot == "" || strings.HasPrefix(robot, "#") || strings.HasPrefix(robot, "User-agent: ") || strings.HasPrefix(robot, "Sitemap: ") {
						continue
					}

					_, sanitizedRobot, _ := strings.Cut(robot, ": ")
					log.Debugf("%s", robot)
					robotReq, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url+"/"+sanitizedRobot, http.NoBody)
					if err != nil {
						log.Debugf("Error creating request for %s: %s", sanitizedRobot, err)
						continue
					}
					resp, err := client.Do(robotReq)
					if err != nil {
						log.Debugf("Error %s: %s", sanitizedRobot, err)
						continue
					}

					if resp.StatusCode != 404 {
						output.Success("%s from robots: %s", output.Status.Render(strconv.Itoa(resp.StatusCode)), output.Highlight.Render(sanitizedRobot))
						if logdir != "" {
							logger.Write(sanitizedURL, logdir, strconv.Itoa(resp.StatusCode)+" from robots: ["+sanitizedRobot+"]\n")
						}
					}
					resp.Body.Close()
				}

			}(thread)
		}
		wg.Wait()
	}
}
