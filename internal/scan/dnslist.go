/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

const (
	dnsURL        = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/dnslist/"
	dnsSmallFile  = "subdomains-100.txt"
	dnsMediumFile = "subdomains-1000.txt"
	dnsBigFile    = "subdomains-10000.txt"
)

// Dnslist performs DNS subdomain enumeration on the target domain.
func Dnslist(size string, url string, timeout time.Duration, threads int, logdir string) ([]string, error) {
	log := output.Module("DNS")
	log.Start()

	var list string
	switch size {
	case "small":
		list = dnsURL + dnsSmallFile
	case "medium":
		list = dnsURL + dnsMediumFile
	case "large":
		list = dnsURL + dnsBigFile
	}

	resp, err := http.Get(list)
	if err != nil {
		log.Error("Error downloading DNS list: %s", err)
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
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := &http.Client{
		Timeout: timeout,
	}

	progress := output.NewProgress(len(dns), "enumerating")

	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(threads)

	urls := make([]string, 0, 64)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, domain := range dns {
				if i%threads != thread {
					continue
				}

				progress.Increment(domain)

				charmlog.Debugf("Looking up: %s", domain)

				// Check HTTP
				resp, err := client.Get("http://" + domain + "." + sanitizedURL)
				if err != nil {
					charmlog.Debugf("Error %s: %s", domain, err)
				} else {
					mu.Lock()
					urls = append(urls, resp.Request.URL.String())
					mu.Unlock()

					progress.Pause()
					log.Success("found: %s.%s [http]", output.Highlight.Render(domain), sanitizedURL)
					progress.Resume()

					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("[http] %s.%s\n", domain, sanitizedURL))
					}
				}

				// Check HTTPS
				resp, err = client.Get("https://" + domain + "." + sanitizedURL)
				if err != nil {
					charmlog.Debugf("Error %s: %s", domain, err)
				} else {
					mu.Lock()
					urls = append(urls, resp.Request.URL.String())
					mu.Unlock()

					progress.Pause()
					log.Success("found: %s.%s [https]", output.Highlight.Render(domain), sanitizedURL)
					progress.Resume()

					if logdir != "" {
						logger.Write(sanitizedURL, logdir, fmt.Sprintf("[https] %s.%s\n", domain, sanitizedURL))
					}
				}
			}
		}(thread)
	}
	wg.Wait()
	progress.Done()

	log.Complete(len(urls), "found")

	return urls, nil
}
