/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                                  SIF                                         ║
║                                                                              ║
║        Blazing-fast pentesting suite written in Go                           ║
║                                                                              ║
║        Copyright (c) 2023-2024 vmfunc, xyzeva, lunchcat contributors         ║
║                    and other sif contributors.                               ║
║                                                                              ║
║                                                                              ║
║        Use of this tool is restricted to research and educational            ║
║        purposes only. Usage in a production environment outside              ║
║        of these categories is strictly prohibited.                           ║
║                                                                              ║
║        Any person or entity wishing to use this tool outside of              ║
║        research or educational purposes must purchase a license              ║
║        from https://lunchcat.dev                                             ║
║                                                                              ║
║        For more information, visit: https://github.com/lunchcat/sif          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

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
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

const (
	dnsURL        = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/dnslist/"
	dnsSmallFile  = "subdomains-100.txt"
	dnsMediumFile = "subdomains-1000.txt"
	dnsBigFile    = "subdomains-10000.txt"
)

// Dnslist performs DNS subdomain enumeration on the target domain.
//
// Parameters:
//   - size: determines the size of the subdomain list to use ("small", "medium", or "large")
//   - url: the target URL to scan
//   - timeout: maximum duration for each DNS lookup
//   - threads: number of concurrent threads to use
//   - logdir: directory to store log files (empty string for no logging)
//
// Returns:
//   - []string: a slice of discovered subdomains
//   - error: any error encountered during the enumeration
func Dnslist(size string, url string, timeout time.Duration, threads int, logdir string) ([]string, error) {

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
		return nil, err
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
			return nil, err
		}
	}

	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	wg.Add(threads)

	urls := []string{}
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, domain := range dns {
				if i%threads != thread {
					continue
				}

				log.Debugf("Looking up: %s", domain)
				resp, err := client.Get("http://" + domain + "." + sanitizedURL)
				if err != nil {
					log.Debugf("Error %s: %s", domain, err)
				} else {
					urls = append(urls, resp.Request.URL.String())
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

				resp, err = client.Get("https://" + domain + "." + sanitizedURL)
				if err != nil {
					log.Debugf("Error %s: %s", domain, err)
				} else {
					urls = append(urls, resp.Request.URL.String())
					dnslog.Infof("%s %s.%s", styles.Status.Render("[https]"), styles.Highlight.Render(domain), sanitizedURL)
					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("[https] %s.%s\n", domain, sanitizedURL))
					}
				}
			}
		}(thread)
	}
	wg.Wait()

	return urls, nil
}
