package main

import (
	"bufio"
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/pflag"
)

func parseURLs() []string {
	var url = pflag.StringArrayP("url", "u", []string{}, "URL to check")
	var file = pflag.StringP("file", "f", "", "File that includes URLs to check")
	pflag.Parse()

	if *url != nil {
		return *url
	} else if *file != "" {
		if _, err := os.Stat(*file); err != nil {
			log.Fatal(err)
		}
		log.Infof("Reading file %s", *file)

		data, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}
		defer data.Close()

		var urls []string
		scanner := bufio.NewScanner(data)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}

		return urls
	}

	return []string{}
}
