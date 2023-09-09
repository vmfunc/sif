package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/pushfs/sif/internal/styles"
	"github.com/pushfs/sif/pkg/logger"
)

const (
	dnsURL        = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/dnslist/"
	dnsSmallFile  = "subdomains-100.txt"
	dnsMediumFile = "subdomains-1000.txt"
	dnsBigFile    = "subdomains-10000.txt"
)

func Dnslist(size string, url string, timeout time.Duration, threads int, logdir string) {

	fmt.Println(styles.Separator.Render("📡 Starting " + styles.Status.Render("DNS fuzzing") + "..."))

	dnslog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dnslist 📡",
	}).With("url", url)

	var list string

	switch size {
	case "small":
		list = dnsURL + dnsSmallFile
	case "medium":
		list = dnsURL + dnsMediumFile
	case "large":
		list = dnsURL + dnsBigFile
	}

	dnslog.Infof("Starting %s DNS listing", size)

	resp, err := http.Get(list)
	if err != nil {
		log.Errorf("Error downloading DNS list: %s", err)
		return
	}
	defer resp.Body.Close()
	var dns []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		dns = append(dns, scanner.Text())
	}

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, size+" subdomain fuzzing"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return
		}
	}

	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	wg.Add(threads)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, domain := range dns {
				if i%threads != thread {
					continue
				}

				log.Debugf("Looking up: %s", domain)
				_, err := client.Get("http://" + domain + "." + sanitizedURL)
				if err != nil {
					log.Debugf("Error %s: %s", domain, err)
				} else {
					dnslog.Infof("%s %s.%s", styles.Status.Render("[http]"), styles.Highlight.Render(domain), sanitizedURL)

					if logdir != "" {
						f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
						if err != nil {
							log.Errorf("Error creating log file: %s", err)
							return
						}
						defer f.Close()
						f.WriteString(fmt.Sprintf("[http] %s.%s\n", domain, sanitizedURL))
					}
				}

				_, err = client.Get("https://" + domain + "." + sanitizedURL)
				if err != nil {
					log.Debugf("Error %s: %s", domain, err)
				} else {
					dnslog.Infof("%s %s.%s", styles.Status.Render("[https]"), styles.Highlight.Render(domain), sanitizedURL)
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("[https] %s.%s\n", domain, sanitizedURL))
					}
				}
			}
		}(thread)
	}
	wg.Wait()
}
