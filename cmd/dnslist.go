package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	// "github.com/pushfs/sif/util"
)

const (
	dnsURL        = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/dnslist/"
	dnsSmallFile  = "subdomains-100.txt"
	dnsMediumFile = "subdomains-1000.txt"
	dnsBigFile    = "subdomains-10000.txt"
)

func Dnslist(size string, url string, timeout time.Duration, logdir string) {

	fmt.Println(separator.Render("📡 Starting " + statusstyle.Render("DNS fuzzing") + "..."))

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dnslist 📡",
	})

	dnslog := logger.With("url", url)

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
	var dns []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		dns = append(dns, scanner.Text())
	}

	// util.InitProgressBar()

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\n\n--------------\nStarting %s DNS listing\n--------------\n", size))
	}

	client := &http.Client{
		Timeout: timeout,
	}
	for _, domain := range dns {
		log.Debugf("Looking up: %s", domain)
		_, err := client.Get("http://" + domain + "." + sanitizedURL)
		if err != nil {
			log.Debugf("Error %s: %s", domain, err)
		} else {
			dnslog.Infof("%s %s.%s", statusstyle.Render("[http]"), dnsstyle.Render(domain), sanitizedURL)

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
			dnslog.Infof("%s %s.%s", statusstyle.Render("[https]"), dnsstyle.Render(domain), sanitizedURL)
			if logdir != "" {
				f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					log.Errorf("Error creating log file: %s", err)
					return
				}
				defer f.Close()
				f.WriteString(fmt.Sprintf("[https] %s.%s\n", domain, sanitizedURL))
			}
		}
	}
}
