/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package config

import (
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/projectdiscovery/goflags"
)

type Settings struct {
	Dirlist           string
	DirMatchCodes     string // -mc dirlist: status codes to keep
	DirFilterCodes    string // -fc dirlist: status codes to drop
	DirFilterSizes    string // -fs dirlist: body sizes to drop
	DirFilterWords    string // -fw dirlist: word counts to drop
	DirFilterRegex    string // -fr dirlist: regex; body match drops response
	Calibrate         bool   // -ac auto-calibrate the soft-404 baseline (dirlist, sql)
	DirWordlist       string // -w  dirlist: custom wordlist (file path or url)
	DirExtensions     string // -e  dirlist: extensions appended to each word
	Dnslist           string
	Resolvers         string // -resolvers dnslist: comma list overriding the bundled pool
	Debug             bool
	LogDir            string
	NoScan            bool
	Ports             string
	Dorking           bool
	Git               bool
	Whois             bool
	Threads           int
	Concurrency       int
	Nuclei            bool
	JavaScript        bool
	Timeout           time.Duration
	URLs              goflags.StringSlice
	File              string
	ApiMode           bool
	Template          string
	CMS               bool
	Headers           bool
	SecurityHeaders   bool
	CloudStorage      bool
	SubdomainTakeover bool
	Shodan            bool
	SecurityTrails    bool
	SQL               bool
	LFI               bool
	JWT               bool
	OpenAPI           bool
	Favicon           bool
	CORS              bool
	Redirect          bool
	XSS               bool
	Framework         bool
	Crawl             bool
	CrawlDepth        int
	TLSCert           bool
	TLSCertPort       int
	Passive           bool
	Probe             bool
	SARIF             string // path to write a sarif 2.1.0 report to ("" = off)
	Markdown          string // path to write a markdown report to ("" = off)
	JSONReport        string // path to write a json findings report to ("" = off)
	Silent            bool   // route chrome to stderr, print one finding per line to stdout
	Diff              bool   // surface only findings added/removed vs the last snapshot
	Store             string // snapshot dir for diff mode ("" = default state dir)
	Modules           string // Comma-separated list of module IDs to run
	ModuleTags        string // Run modules matching these tags
	AllModules        bool   // Run all loaded modules
	ListModules       bool   // List available modules and exit
	Proxy             string
	Header            goflags.StringSlice // custom request headers ("Key: Value")
	Cookie            string
	RateLimit         int
	MaxRetries        int    // -max-retries: retries on 429/503 (0 = off)
	Notify            bool   // -notify: ship findings to configured providers
	NotifySeverity    string // -notify-severity: minimum severity to send (info..critical)
	NotifyConfig      string // -notify-config: path to a notify-compatible yaml file
	ConfigFile        string // -config: path to a yaml config file ("" = default ~/.config/sif/config.yaml)
	Profile           string // -profile: named profile overlay from the config file
}

// minThreads is the floor for the worker count. Threads feeds wg.Add across the
// scanners, so 0 silently runs nothing and a negative value panics with
// "negative WaitGroup counter"; clamp the parsed value up to this.
const minThreads = 1

// defaultCrawlDepth bounds how far the spider recurses by default; deep enough
// to find linked pages without crawling an entire site.
const defaultCrawlDepth = 2

// defaultNotifySeverity is the floor notify sends at when -notify-severity is
// unset: medium drops pure recon/info noise so alerts stay actionable.
const defaultNotifySeverity = "medium"

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

// registerFlags builds the flag set for the given settings without parsing it,
// so callers (Parse and tests) can inspect the registered flags.
func registerFlags(settings *Settings) *goflags.FlagSet {
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
		flagSet.StringVar(&settings.DirMatchCodes, "mc", "", "Dirlist: match these status codes (comma list, e.g. 200,301)"),
		flagSet.StringVar(&settings.DirFilterCodes, "fc", "", "Dirlist: filter out these status codes (comma list)"),
		flagSet.StringVar(&settings.DirFilterSizes, "fs", "", "Dirlist: filter out responses of these body sizes (comma list)"),
		flagSet.StringVar(&settings.DirFilterWords, "fw", "", "Dirlist: filter out responses with these word counts (comma list)"),
		flagSet.StringVar(&settings.DirFilterRegex, "fr", "", "Dirlist: filter out responses whose body matches this regex"),
		flagSet.BoolVar(&settings.Calibrate, "ac", false, "Auto-calibrate the soft-404 wildcard baseline (dirlist, sql)"),
		flagSet.StringVar(&settings.DirWordlist, "w", "", "Dirlist: custom wordlist (local file path or url; overrides -dirlist size)"),
		flagSet.StringVar(&settings.DirExtensions, "e", "", "Dirlist: extensions appended to each word (comma list, e.g. php,bak,env)"),
		flagSet.EnumVar(&settings.Dnslist, "dnslist", Nil, "DNS fuzzing scan size (small/medium/large)", listSizes),
		flagSet.StringVar(&settings.Resolvers, "resolvers", "", "Dnslist: DNS resolvers to use (comma list, e.g. 1.1.1.1,8.8.8.8; overrides the bundled pool)"),
		flagSet.EnumVar(&settings.Ports, "ports", Nil, "Port scanning scope (common/full)", portScopes),
		flagSet.BoolVar(&settings.Dorking, "dork", false, "Enable Google dorking"),
		flagSet.BoolVar(&settings.Git, "git", false, "Enable git repository scanning"),
		flagSet.BoolVar(&settings.Nuclei, "nuclei", false, "Enable scanning using nuclei templates"),
		flagSet.BoolVar(&settings.NoScan, "noscan", false, "Do not perform base URL (robots.txt, etc) scanning"),
		flagSet.BoolVar(&settings.Whois, "whois", false, "Enable WHOIS lookup"),
		flagSet.BoolVar(&settings.JavaScript, "js", false, "Enable JavaScript scans"),
		flagSet.BoolVar(&settings.CMS, "cms", false, "Enable CMS detection"),
		flagSet.BoolVar(&settings.Headers, "headers", false, "Enable HTTP Header Analysis"),
		flagSet.BoolVarP(&settings.SecurityHeaders, "security-headers", "sh", false, "Enable security header analysis (missing/weak headers)"),
		flagSet.BoolVar(&settings.CloudStorage, "c3", false, "Enable C3 Misconfiguration Scan"),
		flagSet.BoolVar(&settings.SubdomainTakeover, "st", false, "Enable Subdomain Takeover Check"),
		flagSet.BoolVar(&settings.Shodan, "shodan", false, "Enable Shodan lookup (requires SHODAN_API_KEY env var)"),
		flagSet.BoolVar(&settings.SecurityTrails, "securitytrails", false, "Enable SecurityTrails domain discovery (requires SECURITYTRAILS_API_KEY env var)"),
		flagSet.BoolVar(&settings.SQL, "sql", false, "Enable SQL reconnaissance (admin panels, error disclosure)"),
		flagSet.BoolVar(&settings.LFI, "lfi", false, "Enable LFI (Local File Inclusion) reconnaissance"),
		flagSet.BoolVar(&settings.JWT, "jwt", false, "Enable JWT discovery + offline weakness analysis"),
		flagSet.BoolVar(&settings.OpenAPI, "openapi", false, "Enable OpenAPI/Swagger spec exposure probe"),
		flagSet.BoolVar(&settings.Favicon, "favicon", false, "Enable favicon hash fingerprinting (shodan-style)"),
		flagSet.BoolVar(&settings.CORS, "cors", false, "Enable CORS misconfiguration probe"),
		flagSet.BoolVar(&settings.Redirect, "redirect", false, "Enable open redirect probe"),
		flagSet.BoolVar(&settings.XSS, "xss", false, "Enable reflected XSS probe"),
		flagSet.BoolVar(&settings.Framework, "framework", false, "Enable framework detection"),
		flagSet.BoolVar(&settings.Crawl, "crawl", false, "Enable web crawling (spider same-host links/scripts/forms)"),
		flagSet.IntVar(&settings.CrawlDepth, "crawl-depth", defaultCrawlDepth, "Max crawl recursion depth"),
		flagSet.BoolVar(&settings.TLSCert, "tls-cert", false, "Enable tls certificate recon (mine SANs, issuer, posture from the leaf cert)"),
		flagSet.IntVar(&settings.TLSCertPort, "tls-cert-port", 0, "Port for tls certificate recon (default 443)"),
		flagSet.BoolVar(&settings.Passive, "passive", false, "Enable passive subdomain/url discovery (zero traffic to target)"),
		flagSet.BoolVar(&settings.Probe, "probe", false, "Probe the target for liveness (status, title, server, redirect chain)"),
	)

	flagSet.CreateGroup("runtime", "Runtime",
		flagSet.BoolVarP(&settings.Debug, "debug", "d", false, "Enable debug logging"),
		flagSet.DurationVarP(&settings.Timeout, "timeout", "t", 10*time.Second, "HTTP request timeout"),
		flagSet.StringVarP(&settings.LogDir, "log", "l", "", "Directory to store logs in"),
		flagSet.IntVar(&settings.Threads, "threads", 10, "Number of threads to run scans on"),
		flagSet.IntVar(&settings.Concurrency, "concurrency", 1, "Number of targets to scan in parallel (>1 interleaves console output)"),
		flagSet.StringVar(&settings.Template, "template", "", "Load scan settings from a template (preset minimal/recon/full, or a local yaml file)"),
	)

	flagSet.CreateGroup("config", "Config",
		flagSet.StringVar(&settings.ConfigFile, "config", "", "Load flags from a yaml config file (default ~/.config/sif/config.yaml)"),
		flagSet.StringVar(&settings.Profile, "profile", "", "Select a named profile from the config file"),
	)

	flagSet.CreateGroup("http", "HTTP",
		flagSet.StringVar(&settings.Proxy, "proxy", "", "Proxy for all requests (http/https/socks5 url)"),
		flagSet.StringSliceVarP(&settings.Header, "header", "H", nil, "Custom header to send (repeatable or comma-separated, \"Key: Value\")", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVar(&settings.Cookie, "cookie", "", "Cookie header to send with every request"),
		flagSet.IntVar(&settings.RateLimit, "rate-limit", 0, "Max requests per second (0 = unlimited)"),
		flagSet.IntVar(&settings.MaxRetries, "max-retries", 2, "Retries on 429/503 with Retry-After backoff (0 = off)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVar(&settings.SARIF, "sarif", "", "Write a SARIF 2.1.0 report to this file"),
		flagSet.StringVarP(&settings.Markdown, "markdown", "md", "", "Write a markdown report to this file"),
		flagSet.StringVar(&settings.JSONReport, "json", "", "Write a json findings report to this file"),
		flagSet.BoolVar(&settings.Silent, "silent", false, "Plain output: chrome to stderr, one finding per line to stdout (for pipelines)"),
		flagSet.BoolVar(&settings.Diff, "diff", false, "Diff mode: surface only findings added/removed since the last snapshot of each target"),
		flagSet.StringVar(&settings.Store, "store", "", "Snapshot directory for -diff (default: log dir, else <user-config>/sif/state)"),
	)

	flagSet.CreateGroup("notify", "Notify",
		flagSet.BoolVar(&settings.Notify, "notify", false, "Ship findings to configured providers (slack/discord/telegram/webhook)"),
		flagSet.StringVar(&settings.NotifySeverity, "notify-severity", defaultNotifySeverity, "Minimum severity to notify on (info/low/medium/high/critical)"),
		flagSet.StringVar(&settings.NotifyConfig, "notify-config", "", "Path to a notify-compatible yaml config (overrides env vars)"),
	)

	flagSet.CreateGroup("api", "API",
		flagSet.BoolVar(&settings.ApiMode, "api", false, "Enable API mode. Only useful for internal usage"),
	)

	flagSet.CreateGroup("modules", "Modules",
		flagSet.StringVarP(&settings.Modules, "modules", "m", "", "Comma-separated list of module IDs to run"),
		flagSet.StringVarP(&settings.ModuleTags, "module-tags", "mt", "", "Run modules matching these tags"),
		flagSet.BoolVarP(&settings.AllModules, "all-modules", "am", false, "Run all loaded modules"),
		flagSet.BoolVarP(&settings.ListModules, "list-modules", "lm", false, "List available modules and exit"),
	)

	return flagSet
}

func Parse() *Settings {
	settings := &Settings{}
	flagSet := registerFlags(settings)

	// -config/-profile/-template all resolve to a single flat yaml config path
	// for goflags to merge, so point it there before Parse (cli flags still
	// win). unset, this returns "" and goflags falls back to its own ambient
	// default config path, unchanged from before this feature existed.
	configPath, cleanup, err := resolveConfigInput(os.Args[1:])
	if err != nil {
		log.Fatalf("Could not load config: %s", err)
	}
	if configPath != "" {
		flagSet.SetConfigFilePath(configPath)
	}

	// Parse merges the config synchronously, so a temp overlay file can be
	// removed right after, before any fatal exit (no leaking defer).
	parseErr := flagSet.Parse()
	if cleanup != nil {
		cleanup()
	}
	if parseErr != nil {
		log.Fatalf("Could not parse flags: %s", parseErr)
	}

	// threads feeds wg.Add directly; floor it so 0 isn't a silent no-op and a
	// negative value can't panic the waitgroup.
	if settings.Threads < minThreads {
		settings.Threads = minThreads
	}

	// concurrency bounds the target worker pool; floor it so 0/negative means
	// sequential rather than a stalled or panicking pool.
	if settings.Concurrency < 1 {
		settings.Concurrency = 1
	}

	return settings
}
