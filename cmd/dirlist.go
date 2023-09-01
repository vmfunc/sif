package cmd

import (
	"fmt"

	"github.com/charmbracelet/log"
)

func Dirlist(size string, url string) {
	log.Infof("Starting directory scan on %s...", url)

	switch size {
	case "small":
		fmt.Println("small")
	case "medium":
		fmt.Println("medium")
	case "large":
		fmt.Println("large")
	}
}
