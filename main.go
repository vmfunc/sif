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
	PaddingRight(5).
	PaddingLeft(5).
	Width(30)

var subline = lipgloss.NewStyle().
	Bold(true).
	Align(lipgloss.Center).
	PaddingLeft(5).
	Width(30)

func main() {
	fmt.Println(style.Render("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/"))
	fmt.Println(subline.Render("https://sif.sh - man's best friend"))

	log.Info("Hello World!")

	settings := parseURLs()
	for _, url := range settings.URLs {
		log.Infof("Looking up %s...", url)
		if settings.Dirlist {
			cmd.Dirlist(url)
		}
	}
}
