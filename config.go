package main

import (
	"bufio"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/pflag"
)

type Settings struct {
	URLs    []string
	Dirlist string
	Dnslist string
	Debug   bool
	NoScan  bool
	Timeout time.Duration
}

func parseURLs() Settings {
	var debug = pflag.BoolP("debug", "d", false, "Enable debug logging")

	var timeout = pflag.DurationP("timeout", "t", 10*time.Second, "General http timeout value - Default is 10 seconds")

	var url = pflag.StringArrayP("url", "u", []string{}, "URL to check")
	var file = pflag.StringP("file", "f", "", "File that includes URLs to check")
	var dirlist = pflag.String("dirlist", "none", "Directory fuzzing scan size (small, medium, large)")
	var dnslist = pflag.String("dnslist", "none", "DNS fuzzing scan size (small, medium, large)")
	var noscan = pflag.Bool("noscan", false, "Do not perform base URL (robots.txt, etc) scanning")
	pflag.Parse()

	if len(*url) > 0 {
		return Settings{
			Debug:   *debug,
			Timeout: *timeout,
			Dirlist: *dirlist,
			Dnslist: *dnslist,
			NoScan:  *noscan,
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
			Timeout: *timeout,
			Debug:   *debug,
			Dirlist: *dirlist,
			Dnslist: *dnslist,
			NoScan:  *noscan,
			URLs:    urls,
		}
	}

	log.Fatal("Please specify either a URL or a file containing URLs, as well as options.\nSee --help for more information.")
	return Settings{}
}
