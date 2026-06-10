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
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
	"github.com/dropalldatabases/sif/internal/pool"
)

// stripScheme drops the scheme:// prefix from url, or returns it unchanged when
// there's no scheme (so a bare host doesn't panic).
func stripScheme(url string) string {
	if _, rest, ok := strings.Cut(url, "://"); ok {
		return rest
	}
	return url
}

// maxRobotsRedirects caps how many 301 hops fetchRobotsTXT will chase. without
// a bound an A->B->A redirect loop recursed forever and blew the stack.
const maxRobotsRedirects = 10

// fetchRobotsTXT follows 301s to robots.txt iteratively, bounded by both a hop
// cap and a visited set so a redirect cycle terminates instead of recursing
// without end.
func fetchRobotsTXT(url string, client *http.Client) *http.Response {
	visited := make(map[string]bool, maxRobotsRedirects)

	for hop := 0; hop < maxRobotsRedirects; hop++ {
		if visited[url] {
			log.Debugf("redirect loop hit at %s, stopping", url)
			return nil
		}
		visited[url] = true

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

		if resp.StatusCode != http.StatusMovedPermanently {
			return resp
		}

		redirectURL := resp.Header.Get("Location")
		// only the Location header is used here; drain so the conn is reusable.
		httpx.DrainClose(resp)
		if redirectURL == "" {
			log.Debugf("Redirect location is empty for %s", url)
			return nil
		}
		url = redirectURL
	}

	log.Debugf("robots.txt redirect depth exceeded (%d hops)", maxRobotsRedirects)
	return nil
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

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL scanning"); err != nil {
			output.Error("Error creating log file: %v", err)
			return
		}
	}

	client := httpx.Client(timeout)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp := fetchRobotsTXT(url+"/robots.txt", client) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if resp == nil {
		return
	}
	// drain on close: the non-success branch never reads the body, so a bare
	// close would leak the conn instead of returning it to the pool.
	defer httpx.DrainClose(resp)

	if resp.StatusCode != 404 && resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 {
		output.Success("File %s found", output.Status.Render("robots.txt"))

		var robotsData []string
		scanner := bufio.NewScanner(resp.Body)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			robotsData = append(robotsData, scanner.Text())
		}

		pool.Each(robotsData, threads, func(robot string) {
			if robot == "" || strings.HasPrefix(robot, "#") || strings.HasPrefix(robot, "User-agent: ") || strings.HasPrefix(robot, "Sitemap: ") {
				return
			}

			_, sanitizedRobot, _ := strings.Cut(robot, ": ")
			log.Debugf("%s", robot)
			robotReq, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url+"/"+sanitizedRobot, http.NoBody)
			if err != nil {
				log.Debugf("Error creating request for %s: %s", sanitizedRobot, err)
				return
			}
			resp, err := client.Do(robotReq) //nolint:bodyclose // drained and closed via httpx.DrainClose
			if err != nil {
				log.Debugf("Error %s: %s", sanitizedRobot, err)
				return
			}

			if resp.StatusCode != 404 {
				output.Success("%s from robots: %s", output.Status.Render(strconv.Itoa(resp.StatusCode)), output.Highlight.Render(sanitizedRobot))
				if logdir != "" {
					logger.Write(sanitizedURL, logdir, strconv.Itoa(resp.StatusCode)+" from robots: ["+sanitizedRobot+"]\n")
				}
			}
			// status only; drain so the conn returns to the pool.
			httpx.DrainClose(resp)
		})
	}
}
