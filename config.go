package main

import (
	"bufio"
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/pflag"
)

type Settings struct {
	URLs    []string
	Dirlist string
}

func parseURLs() Settings {
	var url = pflag.StringArrayP("url", "u", []string{}, "URL to check")
	var file = pflag.StringP("file", "f", "", "File that includes URLs to check")
	var dirlist = pflag.String("dirlist", "none", "Dirlist scan size (small, medium, large)")
	pflag.Parse()

	if len(*url) > 0 {
		return Settings{
			Dirlist: *dirlist,
			URLs:    *url,
		}
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

		return Settings{
			Dirlist: *dirlist,
			URLs:    urls,
		}
	}

	log.Fatal("Please specify either a URL or a file containing URLs")
	return Settings{}
}
