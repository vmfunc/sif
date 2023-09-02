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
	googlesearch "github.com/rocketlaunchr/google-search"
	// "github.com/pushfs/sif/util"
)

const (
	dorkURL  = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/dork/"
	dorkFile = "dork.txt"
)

func Dork(url string, timeout time.Duration, logdir string) {

	fmt.Println(separator.Render("📂 Starting " + statusstyle.Render("URL Dorking") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\n\n--------------\nStarting URL dorking...\n--------------\n"))
	}

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dorking 🤓",
	})
	dorklog := logger.With("url", url)

	dorklog.Infof("Starting URL dorking...")

	resp, err := http.Get(dorkURL + dorkFile)
	if err != nil {
		log.Errorf("Error downloading dork list: %s", err)
		return
	}
	var dorks []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		dorks = append(dorks, scanner.Text())
	}

	// util.InitProgressBar()
	for _, dork := range dorks {
		results, _ := googlesearch.Search(nil, fmt.Sprintf("%s %s", dork, sanitizedURL))
		if len(results) > 0 {
			dorklog.Infof("%s dork results found for dork [%s]", statusstyle.Render(strconv.Itoa(len(results))), directorystyle.Render(dork))
			if logdir != "" {
				f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					log.Errorf("Error creating log file: %s", err)
					return
				}
				defer f.Close()
				f.WriteString(fmt.Sprintf("%s dork results found for dork [%s]\n", strconv.Itoa(len(results)), dork))
			}
		}
	}
}
