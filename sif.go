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

// Package sif provides the main functionality for the SIF (Security Information Finder) tool.
// It handles the initialization, configuration, and execution of various security scanning modules.

package sif

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/config"
	"github.com/dropalldatabases/sif/pkg/logger"
	"github.com/dropalldatabases/sif/pkg/scan"
	"github.com/dropalldatabases/sif/pkg/scan/frameworks"
	jsscan "github.com/dropalldatabases/sif/pkg/scan/js"
)

// App represents the main application structure for sif.
// It encapsulates the configuration settings, target URLs, and logging information.
type App struct {
	settings *config.Settings
	targets  []string
	logFiles []string
}

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

	if !settings.ApiMode {
		fmt.Println(styles.Box.Render("   █▀ █ █▀▀\n  ▄█ █ █▀ "))
		fmt.Println(styles.Subheading.Render("\nblazing-fast pentesting suite\nman's best friend\n\nbsd 3-clause · (c) 2022-2025 vmfunc, xyzeva & contributors\n"))
	}

	if len(settings.URLs) > 0 {
		app.targets = settings.URLs
	} else if settings.File != "" {
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
	} else {
		return nil, fmt.Errorf("target(s) must be supplied with -u or -f\n\nSee 'sif -h' for more information")
	}

	// Validate all URLs early
	for _, url := range app.targets {
		if err := validateURL(url); err != nil {
			return nil, err
		}
	}

	return app, nil
}

// validateURL checks that a URL has a valid HTTP/HTTPS protocol.
func validateURL(url string) error {
	if url == "" {
		return fmt.Errorf("empty URL provided")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("URL %s must include http:// or https:// protocol", url)
	}
	return nil
}

// Run runs the pentesting suite, with the targets specified, according to the
// settings specified.
func (app *App) Run() error {
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
		defer logger.Close()
	}

	scansRun := make([]string, 0, 16)

	for _, url := range app.targets {
		log.Infof("📡Starting scan on %s...", url)

		moduleResults := make([]ModuleResult, 0, 16)

		if app.settings.LogDir != "" {
			if err := logger.CreateFile(&app.logFiles, url, app.settings.LogDir); err != nil {
				return err
			}
		}

		if !app.settings.NoScan {
			scan.Scan(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			scansRun = append(scansRun, "Basic Scan")
		}

		if app.settings.Framework {
			result, err := frameworks.DetectFramework(url, app.settings.Timeout, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running framework detection: %s", err)
			} else if result != nil {
				moduleResults = append(moduleResults, NewModuleResult(result))
				scansRun = append(scansRun, "Framework Detection")
			}
		}

		if app.settings.Dirlist != "none" {
			result, err := scan.Dirlist(app.settings.Dirlist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running directory scan: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"dirlist", result})
				scansRun = append(scansRun, "Directory Listing")
			}
		}

		var dnsResults []string

		if app.settings.Dnslist != "none" {
			result, err := scan.Dnslist(app.settings.Dnslist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
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
			result, err := scan.Ports(app.settings.Ports, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
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

		// func Git(url string, timeout time.Duration, threads int, logdir string)
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
			result, err := scan.SQL(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
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

		if app.settings.ApiMode {
			result := UrlResult{
				Url:     url,
				Results: moduleResults,
			}

			marshalled, err := json.Marshal(result)
			if err != nil {
				log.Fatalf("failed to marshal result: %s", err)
			}
			fmt.Println(string(marshalled))
		}
	}

	if !app.settings.ApiMode {
		scansRunList := "  • " + strings.Join(scansRun, "\n  • ")
		if app.settings.LogDir != "" {
			fmt.Println(styles.Box.Render(fmt.Sprintf("🌿 All scans completed!\n📂 Output saved to files: %s\n\n🔍 Ran scans:\n%s",
				strings.Join(app.logFiles, ", "),
				scansRunList)))
		} else {
			fmt.Println(styles.Box.Render(fmt.Sprintf("🌿 All scans completed!\n\n🔍 Ran scans:\n%s",
				scansRunList)))
		}
	}

	return nil
}
