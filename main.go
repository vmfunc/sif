package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/pushfs/sif/cmd"
)

var style = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#FAFAFA")).
	BorderStyle(lipgloss.RoundedBorder()).
	Align(lipgloss.Center).
	PaddingRight(15).
	PaddingLeft(15).
	Width(60)

var subline = lipgloss.NewStyle().
	Bold(true).
	Align(lipgloss.Center).
	PaddingRight(15).
	PaddingLeft(15).
	Width(60)

var subtext = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#FAFAFA")).
	BorderStyle(lipgloss.RoundedBorder()).
	PaddingTop(5).
	PaddingLeft(15).
	PaddingBottom(5).
	Width(60)

func main() {
	fmt.Println(style.Render("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/    \n"))
	fmt.Println(subline.Render("\nhttps://sif.sh\nman's best friend\n\ncopyright (c) 2023 pushfs, sfr and contributors.\n\n"))

	settings := parseURLs()

	if settings.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if settings.LogDir != "" {
		if _, err := os.Stat(settings.LogDir); os.IsNotExist(err) {
			os.Mkdir(settings.LogDir, 0755)
		}
	}

	// initialize array to store all the log file names
	logFiles := make([]string, 0)

	for _, url := range settings.URLs {
		if !strings.Contains(url, "://") {
			log.Warnf("URL %s must contain leading protocol. Skipping...", url)
			continue
		}

		log.Infof("📡Starting scan on %s...", url)

		if settings.LogDir != "" {
			sanitizedURL := strings.Split(url, "://")[1]
			if _, err := os.Stat(settings.LogDir + "/" + sanitizedURL + ".log"); os.IsNotExist(err) {
				f, err := os.OpenFile(settings.LogDir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					log.Errorf("Error creating log file: %s", err)
					return
				}
				defer f.Close()
			}

			f, err := os.OpenFile(settings.LogDir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				log.Errorf("Error creating log file: %s", err)
				return
			}
			defer f.Close()

			f.WriteString(fmt.Sprintf("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/    \n\nsif log file for %s\nhttps://sif.sh\n\n", url))
			logFiles = append(logFiles, settings.LogDir+"/"+sanitizedURL+".log")
		}

		if !settings.NoScan {
			cmd.Scan(url, settings.Timeout, settings.Threads, settings.LogDir)
		}

		if settings.Dirlist != "none" {
			cmd.Dirlist(settings.Dirlist, url, settings.Timeout, settings.Threads, settings.LogDir)
		}

		if settings.Dnslist != "none" {
			cmd.Dnslist(settings.Dnslist, url, settings.Timeout, settings.Threads, settings.LogDir)
		}

		if settings.Ports != "none" {
			cmd.Ports(settings.Ports, url, settings.Timeout, settings.Threads, settings.LogDir)
		}

		if settings.Dorking {
			cmd.Dork(url, settings.Timeout, settings.Threads, settings.LogDir)
		}

		if settings.Git {
			cmd.Git(url, settings.Timeout, settings.Threads, settings.LogDir)
		}

		// TODO: WHOIS

		fmt.Println()
	}

	if settings.LogDir != "" {
		fmt.Println(style.Render(fmt.Sprintf("🌿 All scans completed!\n📂 Output saved to files: %s\n", strings.Join(logFiles, ", "))))
	} else {
		fmt.Println(style.Render(fmt.Sprintf("🌿 All scans completed!\n")))
	}
}
