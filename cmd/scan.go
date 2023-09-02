package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	// "github.com/pushfs/sif/util"
)

func Scan(url string, timeout time.Duration, logdir string) {

	fmt.Println(separator.Render("🐾 Starting " + statusstyle.Render("base url scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\n\n--------------\nStarting URL scanning\n--------------\n"))
	}

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Scan 👁️‍🗨️",
	})
	scanlog := logger.With("url", url)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url + "/robots.txt")
	if err != nil {
		log.Debugf("Error: %s", err)
	}
	if resp.StatusCode != 404 {
		scanlog.Infof("file [%s] found", statusstyle.Render("robots.txt"))

		var robotsData []string
		scanner := bufio.NewScanner(resp.Body)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			robotsData = append(robotsData, scanner.Text())
		}

		for _, robot := range robotsData {

			if robot == "" || strings.HasPrefix(robot, "#") || strings.HasPrefix(robot, "Disallow: ") || strings.HasPrefix(robot, "User-agent: ") || strings.HasPrefix(robot, "Sitemap: ") {
				continue
			}

			sanitizedRobot := strings.Split(robot, ": ")[1]
			log.Debugf("%s", robot)
			resp, err := client.Get(url + "/" + sanitizedRobot)
			if err != nil {
				log.Debugf("Error %s: %s", sanitizedRobot, err)
			}

			if resp.StatusCode != 404 {
				scanlog.Infof("%s from robots: [%s]", statusstyle.Render(strconv.Itoa(resp.StatusCode)), directorystyle.Render(sanitizedRobot))
				if logdir != "" {
					f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
					if err != nil {
						log.Errorf("Error creating log file: %s", err)
						return
					}
					defer f.Close()
					f.WriteString(fmt.Sprintf("%s from robots: [%s]\n", strconv.Itoa(resp.StatusCode), sanitizedRobot))
				}
			}
		}
	}
}
