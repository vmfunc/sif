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
	googlesearch "github.com/rocketlaunchr/google-search"
)

const (
	dorkURL  = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/dork/"
	dorkFile = "dork.txt"
)

func Dork(url string, timeout time.Duration, threads int, logdir string) {

	fmt.Println(styles.Separator.Render("🤓 Starting " + styles.Status.Render("URL Dorking") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "URL dorking"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return
		}
	}

	dorklog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dorking 🤓",
	}).With("url", url)

	dorklog.Infof("Starting URL dorking...")

	resp, err := http.Get(dorkURL + dorkFile)
	if err != nil {
		log.Errorf("Error downloading dork list: %s", err)
		return
	}
	defer resp.Body.Close()
	var dorks []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		dorks = append(dorks, scanner.Text())
	}

	// util.InitProgressBar()
	var wg sync.WaitGroup
	wg.Add(threads)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, dork := range dorks {
				if i%threads != thread {
					continue
				}

				results, _ := googlesearch.Search(nil, fmt.Sprintf("%s %s", dork, sanitizedURL))
				if len(results) > 0 {
					dorklog.Infof("%s dork results found for dork [%s]", styles.Status.Render(strconv.Itoa(len(results))), styles.Highlight.Render(dork))
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s dork results found for dork [%s]\n", strconv.Itoa(len(results)), dork))
					}
				}
			}
		}(thread)
	}
	wg.Wait()
}
