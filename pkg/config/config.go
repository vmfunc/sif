/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package config

import (
	"time"

	"github.com/charmbracelet/log"
	"github.com/projectdiscovery/goflags"
)

type Settings struct {
	Dirlist           string
	Dnslist           string
	Debug             bool
	LogDir            string
	NoScan            bool
	Ports             string
	Dorking           bool
	Git               bool
	Whois             bool
	Threads           int
	Nuclei            bool
	JavaScript        bool
	Timeout           time.Duration
	URLs              goflags.StringSlice
	File              string
	ApiMode           bool
	Template          string
	CMS               bool
	Headers           bool
	CloudStorage      bool
	SubdomainTakeover bool
	Shodan            bool
	SQL               bool
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
		flagSet.BoolVar(&settings.JavaScript, "js", false, "Enable JavaScript scans"),
		flagSet.BoolVar(&settings.CMS, "cms", false, "Enable CMS detection"),
		flagSet.BoolVar(&settings.Headers, "headers", false, "Enable HTTP Header Analysis"),
		flagSet.BoolVar(&settings.CloudStorage, "c3", false, "Enable C3 Misconfiguration Scan"),
		flagSet.BoolVar(&settings.SubdomainTakeover, "st", false, "Enable Subdomain Takeover Check"),
		flagSet.BoolVar(&settings.Shodan, "shodan", false, "Enable Shodan lookup (requires SHODAN_API_KEY env var)"),
		flagSet.BoolVar(&settings.SQL, "sql", false, "Enable SQL reconnaissance (admin panels, error disclosure)"),
	)

	flagSet.CreateGroup("runtime", "Runtime",
		flagSet.BoolVarP(&settings.Debug, "debug", "d", false, "Enable debug logging"),
		flagSet.DurationVarP(&settings.Timeout, "timeout", "t", 10*time.Second, "HTTP request timeout"),
		flagSet.StringVarP(&settings.LogDir, "log", "l", "", "Directory to store logs in"),
		flagSet.IntVar(&settings.Threads, "threads", 10, "Number of threads to run scans on"),
		flagSet.StringVar(&settings.Template, "template", "", "Sif runtime template to use"),
	)

	flagSet.CreateGroup("api", "API",
		flagSet.BoolVar(&settings.ApiMode, "api", false, "Enable API mode. Only useful for internal lunchcat usage"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s", err)
	}

	return settings
}
