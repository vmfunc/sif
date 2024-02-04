package config

import (
	"time"

	"github.com/charmbracelet/log"
	"github.com/projectdiscovery/goflags"
)

type Settings struct {
	Dirlist string
	Dnslist string
	Debug   bool
	LogDir  string
	NoScan  bool
	Ports   string
	Dorking bool
	Git     bool
	Whois   bool
	Threads int
	Nuclei  bool
	Timeout time.Duration
	URLs    goflags.StringSlice
	File    string
	ApiMode bool
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

func Parse() *Settings {
	settings := &Settings{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("a blazing-fast pentesting (recon/exploitation) suite")

	flagSet.CreateGroup("target", "Targets",
		flagSet.StringSliceVarP(&settings.URLs, "urls", "u", nil, "List of URLs to check (comma-separated)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&settings.File, "file", "f", "", "File that includes URLs to check"),
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
		flagSet.BoolVar(&settings.Whois, "whois", false, "Enable WHOIS lookup"),
	)

	flagSet.CreateGroup("runtime", "Runtime",
		flagSet.BoolVarP(&settings.Debug, "debug", "d", false, "Enable debug logging"),
		flagSet.DurationVarP(&settings.Timeout, "timeout", "t", 10*time.Second, "HTTP request timeout"),
		flagSet.StringVarP(&settings.LogDir, "log", "l", "", "Directory to store logs in"),
		flagSet.IntVar(&settings.Threads, "threads", 10, "Number of threads to run scans on"),
	)

	flagSet.CreateGroup("api", "API",
		flagSet.BoolVar(&settings.ApiMode, "api", false, "Enable API mode. Only useful for internal lunchcat usage"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s", err)
	}

	return settings
}
