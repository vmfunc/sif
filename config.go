package main

import (
	"bufio"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/projectdiscovery/goflags"
)

type Settings struct {
	URLs    []string
	Dirlist string
	Dnslist string
	Debug   bool
	LogDir  string
	NoScan  bool
	Ports   string
	Dorking bool
	Git     bool
	Threads int
	Nuclei  bool
	Timeout time.Duration
}

const (
	Nil goflags.EnumVariable = iota

	// list sizes
	Small
	Medium
	Large

	// port scan scopes
	Common
	Full
)

func parseURLs() Settings {
	settings := &Settings{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("a blazing-fast pentesting (recon/exploitation) suite")

	var urls goflags.StringSlice
	var file string
	flagSet.CreateGroup("target", "Targets",
		flagSet.StringSliceVarP(&urls, "urls", "u", nil, "List of URLs to check (comma-separated)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&file, "file", "f", "", "File that includes URLs to check"),
	)

	listSizes := goflags.AllowdTypes{"small": Small, "medium": Medium, "large": Large, "none": Nil}
	portScopes := goflags.AllowdTypes{"common": Common, "full": Full, "none": Nil}
	flagSet.CreateGroup("scans", "Scans",
		flagSet.EnumVar(&settings.Dirlist, "dirlist", Nil, "Directory fuzzing scan size (small/medium/large)", listSizes),
		flagSet.EnumVar(&settings.Dnslist, "dnslist", Nil, "DNS fuzzing scan size (small/medium/large)", listSizes),
		flagSet.EnumVar(&settings.Ports, "ports", Nil, "Port scanning scope (common/full)", portScopes),
		flagSet.BoolVar(&settings.Dorking, "dork", false, "Enable Google dorking"),
		flagSet.BoolVar(&settings.Git, "git", false, "Enable git repository scanning"),
		flagSet.BoolVar(&settings.Nuclei, "nuclei", false, "Enable scanning using nuclei templates"),
		flagSet.BoolVar(&settings.NoScan, "noscan", false, "Do not perform base URL (robots.txt, etc) scanning"),
	)

	flagSet.CreateGroup("runtime", "Runtime",
		flagSet.BoolVarP(&settings.Debug, "debug", "d", false, "Enable debug logging"),
		flagSet.DurationVarP(&settings.Timeout, "timeout", "t", 10*time.Second, "HTTP request timeout"),
		flagSet.StringVarP(&settings.LogDir, "log", "l", "", "Directory to store logs in"),
		flagSet.IntVar(&settings.Threads, "threads", 10, "Number of threads to run scans on"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s", err)
	}

	if len(urls) > 0 {
		settings.URLs = urls
	} else if file != "" {
		if _, err := os.Stat(file); err != nil {
			log.Fatal(err)
		}
		log.Infof("Reading file %s", file)

		data, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}
		defer data.Close()

		scanner := bufio.NewScanner(data)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			settings.URLs = append(settings.URLs, scanner.Text())
		}
	} else {
		log.Fatal("Please specify either a URL or a file containing URLs, as well as options.\nSee -help for more information.")
	}

	return *settings
}
