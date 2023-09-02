package cmd

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
	// "github.com/pushfs/sif/util"
)

const (
	gitURL  = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/git/"
	gitFile = "git.txt"
)

func Git(url string, timeout time.Duration, logdir string) {

	fmt.Println(separator.Render("🌿 Starting " + statusstyle.Render("git repository scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString("\n\n--------------\nStarting git repository scanning\n--------------\n")
	}

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Git 🌿",
	})
	gitlog := logger.With("url", url)

	gitlog.Infof("Starting repository scanning")

	resp, err := http.Get(gitURL + gitFile)
	if err != nil {
		log.Errorf("Error downloading git list: %s", err)
		return
	}
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
	wg.Add(len(gitUrls))
	for _, repourl := range gitUrls {
		go func(repourl string) {
			defer wg.Done()

			log.Debugf("%s", repourl)
			resp, err := client.Get(url + "/" + repourl)
			if err != nil {
				log.Debugf("Error %s: %s", repourl, err)
			}

			if resp.StatusCode != 404 {
				// log url, directory, and status code
				gitlog.Infof("%s git found at [%s]", statusstyle.Render(strconv.Itoa(resp.StatusCode)), directorystyle.Render(repourl))
				if logdir != "" {
					f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
					if err != nil {
						log.Errorf("Error creating log file: %s", err)
						return
					}
					defer f.Close()
					f.WriteString(fmt.Sprintf("%s git found at [%s]\n", strconv.Itoa(resp.StatusCode), repourl))
				}
			}
		}(repourl)
	}
}
