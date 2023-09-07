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
	directoryURL = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/dirlist/"
	smallFile    = "directory-list-2.3-small.txt"
	mediumFile   = "directory-list-2.3-medium.txt"
	bigFile      = "directory-list-2.3-big.txt"
)

func Dirlist(size string, url string, timeout time.Duration, threads int, logdir string) {

	fmt.Println(separator.Render("📂 Starting " + statusstyle.Render("directory fuzzing") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\n\n--------------\nStarting %s directory fuzzing\n--------------\n", size))
	}

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dirlist 📂",
	})
	dirlog := logger.With("url", url)

	var list string

	switch size {
	case "small":
		list = directoryURL + smallFile
	case "medium":
		list = directoryURL + mediumFile
	case "large":
		list = directoryURL + bigFile
	}

	dirlog.Infof("Starting %s directory listing", size)

	resp, err := http.Get(list)
	if err != nil {
		log.Errorf("Error downloading directory list: %s", err)
		return
	}
	defer resp.Body.Close()
	var directories []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		directories = append(directories, scanner.Text())
	}

	// util.InitProgressBar()
	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	wg.Add(threads)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, directory := range directories {
				if i%threads != thread {
					continue
				}

				log.Debugf("%s", directory)
				resp, err := client.Get(url + "/" + directory)
				if err != nil {
					log.Debugf("Error %s: %s", directory, err)
					return
				}

				if resp.StatusCode != 404 {
					// log url, directory, and status code
					dirlog.Infof("%s [%s]", statusstyle.Render(strconv.Itoa(resp.StatusCode)), directorystyle.Render(directory))
					if logdir != "" {
						f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
						if err != nil {
							log.Errorf("Error creating log file: %s", err)
							return
						}
						defer f.Close()
						f.WriteString(fmt.Sprintf("%s [%s]\n", strconv.Itoa(resp.StatusCode), directory))
					}
				}
			}
		}(thread)
	}
	wg.Wait()
}
