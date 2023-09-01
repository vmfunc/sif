package main

import (
	"fmt"

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

	for _, url := range settings.URLs {

		log.Infof("📡Starting scan on %s...", url)

		if !settings.NoScan {
			cmd.Scan(url, settings.Timeout)
		}

		if settings.Dirlist != "none" {
			cmd.Dirlist(settings.Dirlist, url, settings.Timeout)
		}

		if settings.Dnslist != "none" {
			cmd.Dnslist(settings.Dnslist, url, settings.Timeout)
		}

		// TODO: WHOIS

		fmt.Println()
		fmt.Println(style.Render("🐾 All scans completed!\n\n📂 Outputs saved to files:"))
	}
}
