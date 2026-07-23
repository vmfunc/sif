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

// Package sif provides the main functionality for the SIF (Security Information Finder) tool.
// It handles the initialization, configuration, and execution of various security scanning modules.

package sif

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/dnsx"
	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/modules"
	"github.com/vmfunc/sif/internal/notify"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/report"
	"github.com/vmfunc/sif/internal/scan"
	"github.com/vmfunc/sif/internal/scan/builtin"
	"github.com/vmfunc/sif/internal/scan/frameworks"
	jsscan "github.com/vmfunc/sif/internal/scan/js"
	"github.com/vmfunc/sif/internal/store"
)

// App represents the main application structure for sif.
// It encapsulates the configuration settings, target URLs, and logging information.
type App struct {
	settings *config.Settings
	targets  []string
	logFiles []string
}

// Version is set by main to the resolved build version and shown on the banner.
var Version = "dev"

// reportFileMode is the permission applied to written report files: owner
// read/write, group/other read. reports aren't secret but may name targets.
const reportFileMode = 0o644

type UrlResult struct {
	Url     string `json:"url"`
	Results []ModuleResult
}

type ModuleResult struct {
	Id   string      `json:"id"`
	Data interface{} `json:"data"`
}

// ScanResult is the interface that all scan result types must implement.
// This mirrors the definition in pkg/scan/result.go for use by the main package.
type ScanResult interface {
	ResultType() string
}

// NewModuleResult creates a ModuleResult with compile-time type safety.
// The data parameter must implement ScanResult, which is enforced at compile time.
func NewModuleResult[T ScanResult](data T) ModuleResult {
	return ModuleResult{
		Id:   data.ResultType(),
		Data: data,
	}
}

// New creates a new App struct by parsing the configuration options,
// figuring out the targets from list or file, etc.
//
// Errors if no targets are supplied through URLs or File.
func New(settings *config.Settings) (*App, error) {
	app := &App{settings: settings}

	// -silent reroutes all chrome to stderr (and suppresses spinners) before the
	// banner prints, so stdout carries nothing but findings even on the banner.
	if settings.Silent {
		output.SetSilent(true)
	}

	if !settings.ApiMode {
		fmt.Fprintln(output.Writer(), output.Box.Render("   █▀ █ █▀▀\n  ▄█ █ █▀ "))
		tagline := "blazing-fast pentesting suite"
		if Version != "dev" {
			tagline += " · v" + Version
		}
		fmt.Fprintln(output.Writer(), output.Subheading.Render("\n"+tagline+"\n\nbsd 3-clause · (c) 2022-2026 vmfunc, xyzeva & contributors\n"))
	} else {
		output.SetAPIMode(true)
	}

	// Skip target requirement if just listing modules
	if settings.ListModules {
		return app, nil
	}

	// -u and -f are explicit; stdin is additive so `subfinder | sif -u extra`
	// still works. order: flags first, then piped lines appended.
	app.targets = append(app.targets, settings.URLs...)

	if settings.File != "" {
		if _, err := os.Stat(settings.File); err != nil {
			return nil, err
		}

		data, err := os.Open(settings.File)
		if err != nil {
			return nil, err
		}
		defer data.Close()

		scanner := bufio.NewScanner(data)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			app.targets = append(app.targets, scanner.Text())
		}
	}

	// when stdin is a pipe (not a terminal), drain it for targets so sif slots
	// into a unix pipeline: `subfinder -d x | sif -silent | notify`. keyed off
	// stdin's mode, never stdout - a redirected stdout (>file) is not a pipe in.
	piped, err := stdinPipedFn()
	if err != nil {
		return nil, err
	}
	if piped {
		stdinTargets, err := readTargets(stdinReader)
		if err != nil {
			return nil, fmt.Errorf("reading targets from stdin: %w", err)
		}
		app.targets = append(app.targets, stdinTargets...)
	}

	if len(app.targets) == 0 {
		return nil, fmt.Errorf("target(s) must be supplied with -u, -f, or stdin\n\nSee 'sif -h' for more information")
	}

	// normalize every target in place: a naked host gains a default scheme, an
	// explicit scheme is kept, genuinely invalid input is rejected early.
	for i := 0; i < len(app.targets); i++ {
		normalized, err := normalizeTarget(app.targets[i])
		if err != nil {
			return nil, err
		}
		app.targets[i] = normalized
	}

	return app, nil
}

// defaultScheme is prepended to scheme-less targets. https is the safer default
// for recon: it's what modern hosts serve and avoids a cleartext first hop.
const defaultScheme = "https://"

// stdin ingestion is wired through two seams so it's hermetically testable: the
// pipe check and the reader can be swapped in tests without touching real fds.
var (
	stdinPipedFn           = stdinPiped
	stdinReader  io.Reader = os.Stdin
)

// stdinPiped reports whether stdin is a pipe/redirect rather than a terminal.
// a char device (the tty) means interactive with no piped input; anything else
// (pipe, file redirect) is treated as a target stream.
func stdinPiped() (bool, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false, fmt.Errorf("stat stdin: %w", err)
	}
	return info.Mode()&os.ModeCharDevice == 0, nil
}

// readTargets scans one target per line from r, dropping blank lines and
// trimming surrounding whitespace. shared by the stdin path; the file path keeps
// its own scanner since it preserves lines verbatim for back-compat.
func readTargets(r io.Reader) ([]string, error) {
	var out []string
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning targets: %w", err)
	}
	return out, nil
}

// normalizeTarget canonicalizes a single target. a scheme-less host gets the
// default scheme; an http:// or https:// target is kept as-is. an empty string
// or a non-http(s) scheme (ftp://, file://, ...) is rejected so junk can't slip
// into the scan loop.
func normalizeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target provided")
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target, nil
	}
	// reject anything that carries some other scheme; "://" present but not
	// http(s) is a deliberate non-web target, not a naked host.
	if strings.Contains(target, "://") {
		return "", fmt.Errorf("target %s must use http:// or https:// scheme", target)
	}
	// a bare "host:port" or path-only token would also be ambiguous; require at
	// least a host-looking first segment (no spaces) before defaulting a scheme.
	if strings.ContainsAny(target, " \t") {
		return "", fmt.Errorf("invalid target %q", target)
	}
	return defaultScheme + target, nil
}

// Run runs the pentesting suite, with the targets specified, according to the
// settings specified.
func (app *App) Run(ctx context.Context) error {
	// Handle --list-modules before any other processing
	if app.settings.ListModules {
		loader, err := modules.NewLoader()
		if err != nil {
			return fmt.Errorf("failed to create module loader: %w", err)
		}
		if err := loader.LoadAll(); err != nil {
			log.Warnf("Failed to load modules: %v", err)
		}

		// Register built-in Go modules
		builtin.Register()

		fmt.Println("Available modules:")
		for _, m := range modules.All() {
			info := m.Info()
			fmt.Printf("  %-25s %s [%s]\n", info.ID, info.Name, strings.Join(info.Tags, ", "))
		}
		return nil
	}

	if app.settings.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if app.settings.ApiMode {
		log.SetLevel(5)
	}

	if app.settings.LogDir != "" {
		if err := logger.Init(app.settings.LogDir); err != nil {
			return err
		}
		defer func() {
			if err := logger.Close(); err != nil {
				log.Errorf("closing logger: %v", err)
			}
		}()
	}

	// wire proxy/headers/cookie/rate-limit into the shared http client once,
	// before any scanner runs. a bad proxy/header shouldn't kill the run -
	// scanners fall back to a plain client if this fails.
	if err := httpx.Configure(httpx.Options{
		Proxy:      app.settings.Proxy,
		Headers:    app.settings.Header,
		Cookie:     app.settings.Cookie,
		RateLimit:  app.settings.RateLimit,
		MaxRetries: app.settings.MaxRetries,
		Threads:    app.settings.Threads,
	}); err != nil {
		log.Warnf("http client config failed, continuing with defaults: %v", err)
	}

	// target expansion - securitytrails discovers new domains before scanning
	if app.settings.SecurityTrails {
		expanded := app.expandTargets()
		if len(expanded) > 0 {
			output.Info("SecurityTrails discovered %d additional targets", len(expanded))
			app.targets = append(app.targets, expanded...)
		}
	}

	// bound the whole run when -max-time is set; the deadline rides on the same
	// ctx as the interrupt handler, so either one cancels the in-flight scanners
	// that take a context and stops the target loop between steps.
	if app.settings.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, app.settings.MaxTime)
		defer cancel()
	}

	scansRun := make([]string, 0, 16)

	// accumulate every module result across targets so the report writers can
	// serialize the full run after the loop. only collected when an export flag
	// is set, so the common path pays nothing.
	wantReport := app.settings.SARIF != "" || app.settings.Markdown != ""
	reportResults := make([]report.Result, 0, 16)

	// normalized findings for the whole run; the single Flatten-driven view that
	// notify and diff consume. collected alongside the report so both describe the
	// same scanners from one pass.
	allFindings := make([]finding.Finding, 0, 16)

	// resolve the snapshot dir once when diff mode is on; a bad default isn't
	// fatal - diff just no-ops for the run rather than killing the scan.
	storeDir := ""
	if app.settings.Diff {
		dir, err := app.resolveStoreDir()
		if err != nil {
			log.Warnf("diff disabled: %v", err)
		} else {
			storeDir = dir
		}
	}

	results, err := app.scanAllTargets(ctx, storeDir, wantReport)
	if err != nil {
		return err
	}

	// merge per-target results in input order so the run-wide view is identical
	// regardless of the order workers finished under -concurrency.
	for _, ts := range results {
		scansRun = append(scansRun, ts.scansRun...)
		app.logFiles = append(app.logFiles, ts.logFiles...)
		allFindings = append(allFindings, ts.findings...)
		if wantReport {
			reportResults = append(reportResults, ts.reportResults...)
		}
	}

	return app.finishRun(ctx, scansRun, allFindings, reportResults, wantReport)
}

// targetScan holds one target's isolated scan output: its findings, report rows,
// scan labels and log files, which the run loop merges in target order.
type targetScan struct {
	findings      []finding.Finding
	reportResults []report.Result
	scansRun      []string
	logFiles      []string
}

// scanAllTargets scans every target and returns the per-target results in input
// order. With concurrency 1 it runs sequentially, behaviour-identical to a plain
// loop. Above 1 it runs a bounded worker pool: scanTarget is self-contained
// (isolated accumulators, no run-wide writes), so the only shared surface is the
// console, which output.SetConcurrent serializes and de-animates. Results are
// indexed by target position, so the caller merges them in a stable order no
// matter which worker finished first.
func (app *App) scanAllTargets(ctx context.Context, storeDir string, wantReport bool) ([]targetScan, error) {
	results := make([]targetScan, len(app.targets))

	concurrency := app.settings.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(app.targets) {
		concurrency = len(app.targets)
	}

	if concurrency <= 1 {
		for i, url := range app.targets {
			// stop cleanly on interrupt or -max-time rather than starting another
			// target; whatever was collected so far still gets reported.
			if ctx.Err() != nil {
				log.Warnf("scan cancelled, not starting further targets: %v", ctx.Err())
				break
			}
			ts, err := app.scanTarget(ctx, url, storeDir, wantReport)
			if err != nil {
				return nil, err
			}
			results[i] = ts
		}
		return results, nil
	}

	output.SetConcurrent(true)

	errs := make([]error, len(app.targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, url := range app.targets {
		if ctx.Err() != nil {
			log.Warnf("scan cancelled, not starting further targets: %v", ctx.Err())
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, url string) {
			defer wg.Done()
			defer func() { <-sem }()
			// a panic in one target's scan (a module bug, a nil deref deep in a
			// third-party client) must not take down every other worker's
			// in-flight scan; convert it into that target's error instead.
			defer func() {
				if r := recover(); r != nil {
					errs[i] = fmt.Errorf("panic scanning %s: %v", url, r)
				}
			}()
			results[i], errs[i] = app.scanTarget(ctx, url, storeDir, wantReport)
		}(i, url)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

// scanTarget runs the full scanner set for one target and returns its isolated
// accumulators without mutating run-wide state.
func (app *App) scanTarget(ctx context.Context, url, storeDir string, wantReport bool) (targetScan, error) {
	var scansRun []string
	var logFiles []string

	output.Info("Starting scan on %s", output.Highlight.Render(url))

	moduleResults := make([]ModuleResult, 0, 16)

	if app.settings.LogDir != "" {
		if err := logger.CreateFile(&logFiles, url, app.settings.LogDir); err != nil {
			return targetScan{}, err
		}
	}

	if !app.settings.NoScan {
		scan.Scan(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		scansRun = append(scansRun, "Basic Scan")
	}

	if app.settings.Framework {
		results, err := frameworks.DetectFrameworks(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running framework detection: %s", err)
		} else if len(results) > 0 {
			for _, result := range results {
				moduleResults = append(moduleResults, NewModuleResult(result))
			}
			scansRun = append(scansRun, "Framework Detection")
		}
	}

	if app.settings.Dirlist != "none" {
		result, err := scan.Dirlist(app.settings.Dirlist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir, scan.DirlistOptions{
			MatchCodes:  app.settings.DirMatchCodes,
			FilterCodes: app.settings.DirFilterCodes,
			FilterSizes: app.settings.DirFilterSizes,
			FilterWords: app.settings.DirFilterWords,
			FilterRegex: app.settings.DirFilterRegex,
			Calibrate:   app.settings.Calibrate,
			Wordlist:    app.settings.DirWordlist,
			Extensions:  app.settings.DirExtensions,
		})
		if err != nil {
			log.Errorf("Error while running directory scan: %s", err)
		} else {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Directory Listing")
		}
	}

	var dnsResults []string

	if app.settings.Dnslist != "none" {
		result, err := scan.Dnslist(app.settings.Dnslist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir, dnsx.ParseResolvers(app.settings.Resolvers))
		if err != nil {
			log.Errorf("Error while running dns scan: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"dnslist", result})
			dnsResults = result // Store the DNS results
			scansRun = append(scansRun, "DNS Scan")
		}

		// Only run subdomain takeover check if DNS scan is enabled
		if app.settings.SubdomainTakeover {
			result, err := scan.SubdomainTakeover(url, dnsResults, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running Subdomain Takeover Vulnerability Check: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"subdomain_takeover", result})
				scansRun = append(scansRun, "Subdomain Takeover")
			}
		}
	} else if app.settings.SubdomainTakeover {
		log.Warnf("Subdomain Takeover check is enabled but DNS scan is disabled. Skipping Subdomain Takeover check.")
	}

	if app.settings.Dorking {
		result, err := scan.Dork(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running Dork module: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"dork", result})
			scansRun = append(scansRun, "Dork")
		}
	}

	if app.settings.Ports != "none" {
		result, err := scan.Ports(ctx, app.settings.Ports, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running port scan: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"portscan", result})
			scansRun = append(scansRun, "Port Scan")
		}
	}

	if app.settings.Whois {
		scan.Whois(url, app.settings.LogDir)
		scansRun = append(scansRun, "Whois")
	}

	if app.settings.Git {
		result, err := scan.Git(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running Git module: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"git", result})
			scansRun = append(scansRun, "Git")
		}
	}

	if app.settings.Nuclei {
		result, err := scan.Nuclei(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running Nuclei module: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"nuclei", result})
			scansRun = append(scansRun, "Nuclei")
		}
	}

	if app.settings.JavaScript {
		result, err := jsscan.JavascriptScan(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running JS module: %s", err)
		} else {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "JS")
		}
	}

	if app.settings.CMS {
		result, err := scan.CMS(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running CMS detection: %s", err)
			scansRun = append(scansRun, "CMS")
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
		}
	}

	if app.settings.Headers {
		result, err := scan.Headers(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running HTTP Header Analysis: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"headers", result})
			scansRun = append(scansRun, "HTTP Headers")
		}
	}

	if app.settings.SecurityHeaders {
		result, err := scan.SecurityHeaders(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running Security Header Analysis: %s", err)
		} else {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Security Headers")
		}
	}

	if app.settings.CloudStorage {
		result, err := scan.CloudStorage(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running C3 Scan: %s", err)
		} else {
			moduleResults = append(moduleResults, ModuleResult{"cloudstorage", result})
			scansRun = append(scansRun, "Cloud Storage")
		}
	}

	if app.settings.Shodan {
		result, err := scan.Shodan(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running Shodan lookup: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Shodan")
		}
	}

	if app.settings.SQL {
		result, err := scan.SQL(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir, app.settings.Calibrate)
		if err != nil {
			log.Errorf("Error while running SQL reconnaissance: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "SQL Recon")
		}
	}

	if app.settings.LFI {
		result, err := scan.LFI(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running LFI reconnaissance: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "LFI Recon")
		}
	}

	if app.settings.JWT {
		result, err := scan.JWT(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running JWT analysis: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "JWT")
		}
	}

	if app.settings.OpenAPI {
		result, err := scan.OpenAPI(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running OpenAPI probe: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "OpenAPI")
		}
	}

	if app.settings.Favicon {
		result, err := scan.Favicon(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running favicon fingerprint: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Favicon")
		}
	}

	if app.settings.CORS {
		result, err := scan.CORS(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running CORS probe: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "CORS")
		}
	}

	if app.settings.Redirect {
		result, err := scan.Redirect(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running open redirect probe: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Open Redirect")
		}
	}

	if app.settings.XSS {
		result, err := scan.XSS(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running reflected XSS probe: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Reflected XSS")
		}
	}

	if app.settings.Crawl {
		result, err := scan.Crawl(url, app.settings.CrawlDepth, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running web crawl: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Crawl")
		}
	}

	if app.settings.TLSCert {
		result, err := scan.TLSCert(url, app.settings.TLSCertPort, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running tls certificate recon: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "TLSCert")
		}
	}

	if app.settings.Passive {
		result, err := scan.Passive(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running passive discovery: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Passive")
		}
	}

	if app.settings.Probe {
		result, err := scan.Probe(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("Error while running probe: %s", err)
		} else if result != nil {
			moduleResults = append(moduleResults, NewModuleResult(result))
			scansRun = append(scansRun, "Probe")
		}
	}

	// Load and run modules
	if app.settings.AllModules || app.settings.Modules != "" || app.settings.ModuleTags != "" {
		loader, err := modules.NewLoader()
		if err != nil {
			log.Warnf("Failed to create module loader: %v", err)
		} else {
			if err := loader.LoadAll(); err != nil {
				log.Warnf("Failed to load modules: %v", err)
			}

			// Register built-in Go modules
			builtin.Register()

			// Determine which modules to run
			var toRun []modules.Module
			switch {
			case app.settings.AllModules:
				toRun = modules.All()
			case app.settings.ModuleTags != "":
				for _, tag := range strings.Split(app.settings.ModuleTags, ",") {
					toRun = append(toRun, modules.ByTag(strings.TrimSpace(tag))...)
				}
			case app.settings.Modules != "":
				for _, id := range strings.Split(app.settings.Modules, ",") {
					if m, ok := modules.Get(strings.TrimSpace(id)); ok {
						toRun = append(toRun, m)
					} else {
						log.Warnf("Module not found: %s", id)
					}
				}
			}

			seen := make(map[string]bool, len(toRun))
			deduped := make([]modules.Module, 0, len(toRun))
			for _, m := range toRun {
				if id := m.Info().ID; !seen[id] {
					seen[id] = true
					deduped = append(deduped, m)
				}
			}
			toRun = deduped

			// Execute modules
			// Execute modules. Client routes through the shared httpx transport so
			// -proxy/-H/-cookie/-rate-limit apply to module scans the same as every
			// other scanner instead of each module dialing out on a bare client.
			opts := modules.Options{
				Timeout: app.settings.Timeout,
				Threads: app.settings.Threads,
				LogDir:  app.settings.LogDir,
				Client:  httpx.Client(app.settings.Timeout),
			}

			for _, m := range toRun {
				if ctx.Err() != nil {
					break
				}
				switch m.Info().ID {
				case "nuclei-scan":
					if app.settings.Nuclei {
						continue
					}
				case "framework-detection":
					if app.settings.Framework {
						continue
					}
				case "shodan-lookup":
					if app.settings.Shodan {
						continue
					}
				case "whois-lookup":
					if app.settings.Whois {
						continue
					}
				}
				modLog := output.Module(m.Info().ID)
				modLog.Start()
				result, err := m.Execute(ctx, url, opts)
				if err != nil {
					modLog.Error("failed: %v", err)
					continue
				}
				if result != nil && len(result.Findings) > 0 {
					moduleResults = append(moduleResults, NewModuleResult(result))
					modLog.Complete(len(result.Findings), "findings")
				} else {
					modLog.Complete(0, "findings")
				}
			}
		}
	}

	if app.settings.ApiMode {
		result := UrlResult{
			Url:     url,
			Results: moduleResults,
		}

		marshalled, err := json.Marshal(result)
		if err != nil {
			log.Errorf("failed to marshal result: %s", err)
			return targetScan{scansRun: scansRun, logFiles: logFiles}, nil
		}
		fmt.Println(string(marshalled))
	}

	targetFindings := collectFindings(url, moduleResults)

	// diff mode is per-target: load this target's last snapshot, surface only
	// the delta, then overwrite the snapshot so the next run diffs against now.
	// storeDir is "" when diff is off or the dir couldn't resolve, in which
	// case this is a no-op and behavior is unchanged.
	if storeDir != "" {
		app.diffTarget(storeDir, url, targetFindings)
	}

	// the report carries raw blobs and is only built when an export flag is
	// set, so the common path skips the marshalling entirely.
	var reportResults []report.Result
	if wantReport {
		reportResults = collectReportResults(url, moduleResults)
	}

	return targetScan{
		findings:      targetFindings,
		reportResults: reportResults,
		scansRun:      scansRun,
		logFiles:      logFiles,
	}, nil
}

// finishRun performs the run-wide steps after every target has been scanned:
// notify, the silent findings stream, report files and the summary. It consumes
// the merged accumulators so per-target scanning stays isolated in scanTarget.
func (app *App) finishRun(ctx context.Context, scansRun []string, allFindings []finding.Finding, reportResults []report.Result, wantReport bool) error {
	// the normalized findings are the handoff point for notify/diff; surface the
	// count now so the path is live and observable without changing output.
	log.Debugf("normalized %d findings across %d targets", len(allFindings), len(app.targets))

	// notify: ship the severity-filtered findings to any configured provider.
	// kept as an isolated block so it merges cleanly with the diff-store bundle.
	if app.settings.Notify {
		if err := app.notifyFindings(ctx, allFindings); err != nil {
			log.Errorf("notify: %v", err)
		}
	}

	// -silent: stdout is the findings stream, one terse line each. all chrome
	// already went to stderr via the rerouted sink, so this is the only thing a
	// downstream pipe sees.
	if app.settings.Silent {
		printFindings(allFindings)
	}

	if wantReport {
		if err := app.writeReports(reportResults); err != nil {
			return err
		}
	}

	if path := app.settings.JSONReport; path != "" {
		if err := app.writeJSONReport(path, allFindings); err != nil {
			return err
		}
	}

	if !app.settings.ApiMode {
		output.PrintSummary(scansRun, app.logFiles)
	}

	return nil
}

// printFindings writes one normalized finding per line to stdout for the
// -silent plain sink. a single Builder over the run avoids interleaving with
// any stray stderr chrome and keeps the write to one syscall.
func printFindings(findings []finding.Finding) {
	var b strings.Builder
	for i := 0; i < len(findings); i++ {
		b.WriteString(findings[i].Line())
		b.WriteByte('\n')
	}
	fmt.Print(b.String())
}

// collectFindings normalizes one target's module results through finding.Flatten
// - the single normalization path that notify and diff build on. every scan
// result struct collapses to flat, severity-ranked findings here so a scanner is
// described once, not once per consumer.
func collectFindings(target string, moduleResults []ModuleResult) []finding.Finding {
	out := make([]finding.Finding, 0, len(moduleResults))
	for _, mr := range moduleResults {
		out = append(out, finding.Flatten(target, mr.Id, mr.Data)...)
	}
	return out
}

// resolveStoreDir picks the snapshot directory for diff mode. precedence: an
// explicit -store wins; else the run's log dir is reused (snapshots live next to
// logs); else the per-user default under <user-config>/sif/state. returns an
// error only when no usable location exists, so the caller can disable diff
// without failing the scan.
func (app *App) resolveStoreDir() (string, error) {
	if app.settings.Store != "" {
		return app.settings.Store, nil
	}
	if app.settings.LogDir != "" {
		return app.settings.LogDir, nil
	}
	dir, err := store.DefaultDir()
	if err != nil {
		return "", fmt.Errorf("resolving snapshot dir: %w", err)
	}
	return dir, nil
}

// diffTarget loads target's previous snapshot, prints the added/removed delta
// against the current findings, then overwrites the snapshot so the next run
// diffs against this one. a load failure surfaces but doesn't abort the run -
// the new snapshot is still written so a corrupt baseline self-heals. always
// saves, even when the delta is empty, to advance the baseline.
func (app *App) diffTarget(dir, target string, current []finding.Finding) {
	previous, err := store.Load(dir, target)
	if err != nil {
		log.Warnf("diff: reading snapshot for %s, treating as fresh: %v", target, err)
		previous = nil
	}

	added, removed := store.Diff(previous, current)
	printDiff(target, added, removed)

	if err := store.Save(dir, target, current); err != nil {
		log.Warnf("diff: saving snapshot for %s: %v", target, err)
	}
}

// printDiff renders a target's diff: each added finding marked "+ new", each
// removed one "- gone", with a one-line note when nothing changed. routed
// through the shared output sink so -silent keeps it on stderr alongside the
// other chrome. a single Builder keeps the block from interleaving.
func printDiff(target string, added, removed []finding.Finding) {
	if len(added) == 0 && len(removed) == 0 {
		output.Info("diff %s: no changes since last snapshot", target)
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "diff %s: %d new, %d gone\n", target, len(added), len(removed))
	for i := 0; i < len(added); i++ {
		fmt.Fprintf(&b, "  + new  %s\n", added[i].Line())
	}
	for i := 0; i < len(removed); i++ {
		fmt.Fprintf(&b, "  - gone %s\n", removed[i].Line())
	}
	fmt.Fprint(output.Writer(), b.String())
}

// collectReportResults flattens one target's module results into the report
// model, carrying each finding as raw json so the report package stays free of
// scan types. a result that won't marshal is skipped rather than failing the run.
func collectReportResults(target string, moduleResults []ModuleResult) []report.Result {
	out := make([]report.Result, 0, len(moduleResults))
	for _, mr := range moduleResults {
		data, err := json.Marshal(mr.Data)
		if err != nil {
			log.Warnf("report: skipping %s result for %s: %v", mr.Id, target, err)
			continue
		}
		out = append(out, report.Result{
			Target:   target,
			Module:   mr.Id,
			Severity: reportSeverity(target, mr),
			Data:     data,
		})
	}
	return out
}

// reportSeverity derives one severity string for a module result by flattening
// it to per-item findings and taking the highest rank among them. a module
// result can flatten to several severities; the worst is the meaningful one for
// a single sarif result. an empty string means the source carried no severity.
func reportSeverity(target string, mr ModuleResult) string {
	findings := finding.Flatten(target, mr.Id, mr.Data)
	if len(findings) == 0 {
		return ""
	}
	worst := findings[0].Severity
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > worst {
			worst = findings[i].Severity
		}
	}
	if worst == finding.SeverityUnknown {
		return ""
	}
	return worst.String()
}

// writeReports serializes the collected results to the requested export files.
// each writer runs independently so a bad path for one format doesn't suppress
// the other.
func (app *App) writeReports(results []report.Result) error {
	if path := app.settings.SARIF; path != "" {
		data, err := report.SARIF(results)
		if err != nil {
			return fmt.Errorf("build sarif report: %w", err)
		}
		if err := os.WriteFile(path, data, reportFileMode); err != nil {
			return fmt.Errorf("write sarif report %q: %w", path, err)
		}
		output.Success("sarif report written to %s", path)
	}

	if path := app.settings.Markdown; path != "" {
		data := report.Markdown(results)
		if err := os.WriteFile(path, data, reportFileMode); err != nil {
			return fmt.Errorf("write markdown report %q: %w", path, err)
		}
		output.Success("markdown report written to %s", path)
	}

	return nil
}

// writeJSONReport serializes the run's normalized findings to a json file. it
// works off allFindings (not the raw report blobs) so the output carries the
// same severity and confidence the -silent stream and notify path see.
func (app *App) writeJSONReport(path string, findings []finding.Finding) error {
	data, err := finding.JSONReport(findings)
	if err != nil {
		return fmt.Errorf("build json report: %w", err)
	}
	if err := os.WriteFile(path, data, reportFileMode); err != nil {
		return fmt.Errorf("write json report %q: %w", path, err)
	}
	output.Success("json report written to %s", path)
	return nil
}

// notifyFindings filters the run's findings to the -notify-severity floor and
// ships the survivors to every configured provider. an unrecognized severity
// string parses to SeverityUnknown, which would let everything through; guard
// against that by defaulting to medium so a typo can't flood a channel with
// info noise. an empty filtered set makes notify.Send a no-op.
func (app *App) notifyFindings(ctx context.Context, findings []finding.Finding) error {
	floor := finding.ParseSeverity(app.settings.NotifySeverity)
	if floor == finding.SeverityUnknown {
		log.Warnf("notify: unknown severity %q, defaulting to medium", app.settings.NotifySeverity)
		floor = finding.SeverityMedium
	}

	filtered := make([]finding.Finding, 0, len(findings))
	for i := 0; i < len(findings); i++ {
		if findings[i].Severity.AtLeast(floor) {
			filtered = append(filtered, findings[i])
		}
	}

	return notify.Send(ctx, filtered, notify.Options{
		Timeout:    app.settings.Timeout,
		ConfigPath: app.settings.NotifyConfig,
	})
}

// expandTargets queries SecurityTrails for each original target and returns
// newly discovered domains (subdomains + associated) for target expansion
func (app *App) expandTargets() []string {
	seen := make(map[string]struct{})
	for _, t := range app.targets {
		seen[t] = struct{}{}
	}

	// snapshot original targets - don't expand discovered ones
	originals := make([]string, len(app.targets))
	copy(originals, app.targets)

	var expanded []string

	for _, url := range originals {
		result, err := scan.SecurityTrails(url, app.settings.Timeout, app.settings.LogDir)
		if err != nil {
			log.Errorf("SecurityTrails error for %s: %v", url, err)
			continue
		}
		if result == nil {
			continue
		}

		for _, d := range result.DiscoveredURLs() {
			if _, exists := seen[d]; !exists {
				seen[d] = struct{}{}
				expanded = append(expanded, d)
			}
		}
	}

	return expanded
}
