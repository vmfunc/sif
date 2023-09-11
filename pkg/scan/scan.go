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

func Scan(url string, timeout time.Duration, threads int, logdir string) {

	fmt.Println(styles.Separator.Render("🐾 Starting " + styles.Status.Render("base url scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL scanning"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return
		}
	}

	scanlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Scan 👁️‍🗨️",
	}).With("url", url)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url + "/robots.txt")
	if err != nil {
		log.Debugf("Error: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 && resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 307 {
		scanlog.Infof("file [%s] found", styles.Status.Render("robots.txt"))

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
					resp, err := client.Get(url + "/" + sanitizedRobot)
					if err != nil {
						log.Debugf("Error %s: %s", sanitizedRobot, err)
						return
					}

					if resp.StatusCode != 404 {
						scanlog.Infof("%s from robots: [%s]", styles.Status.Render(strconv.Itoa(resp.StatusCode)), styles.Highlight.Render(sanitizedRobot))
						if logdir != "" {
							logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s from robots: [%s]\n", strconv.Itoa(resp.StatusCode), sanitizedRobot))
						}
					}
				}

			}(thread)
		}
		wg.Wait()
	}
}
