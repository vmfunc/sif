package cmd

import (
	"fmt"

	"github.com/charmbracelet/log"
)

func Dirlist(url string) {
	log.Infof("Starting directory scan on %s...", url)
	fmt.Println(url)
}
