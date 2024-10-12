package sif

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/config"
	"github.com/dropalldatabases/sif/pkg/logger"
	"github.com/dropalldatabases/sif/pkg/scan"
	jsscan "github.com/dropalldatabases/sif/pkg/scan/js"
)

// App is a client instance. It is first initialised using New and then ran
// using Run, which starts the whole app process.
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

// New creates a new App struct by parsing the configuration options,
// figuring out the targets from list or file, etc.
//
// Errors if no targets are supplied through URLs or File.
func New(settings *config.Settings) (*App, error) {
	app := &App{settings: settings}

	if !settings.ApiMode {
		fmt.Println(styles.Box.Render("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/    \n"))
		fmt.Println(styles.Subheading.Render("\nhttps://sif.sh\nman's best friend\n\ncopyright (c) 2023-2024 lunchcat and contributors.\n\n"))
	}

	if len(settings.URLs) > 0 {
		app.targets = settings.URLs
	} else if settings.File != "" {
		if _, err := os.Stat(settings.File); err != nil {
			return app, err
		}

		data, err := os.Open(settings.File)
		if err != nil {
			return app, err
		}
		defer data.Close()

		scanner := bufio.NewScanner(data)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			app.targets = append(app.targets, scanner.Text())
		}
	} else {
		return app, errors.New("target(s) must be supplied with -u or -f\n\nSee 'sif -h' for more information")
	}

	return app, nil
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
	}

	for _, url := range app.targets {
		if !strings.Contains(url, "://") {
			return errors.New(fmt.Sprintf("URL %s must include leading protocol", url))
		}

		log.Infof("📡Starting scan on %s...", url)

		moduleResults := []ModuleResult{}

		if app.settings.LogDir != "" {
			if err := logger.CreateFile(&app.logFiles, url, app.settings.LogDir); err != nil {
				return err
			}
		}

		if !app.settings.NoScan {
			scan.Scan(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Dirlist != "none" {
			result, err := scan.Dirlist(app.settings.Dirlist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running directory scan: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"dirlist", result})
			}
		}

		if app.settings.Dnslist != "none" {
			result, err := scan.Dnslist(app.settings.Dnslist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running dns scan: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"dnslist", result})
			}
		}

		if app.settings.Ports != "none" {
			result, err := scan.Ports(app.settings.Ports, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running port scan: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"portscan", result})
			}
		}

		if app.settings.Whois {
			scan.Whois(url, app.settings.LogDir)
		}

		// func Git(url string, timeout time.Duration, threads int, logdir string)
		if app.settings.Git {
			result, err := scan.Git(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running Git module: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"git", result})
			}
		}

		if app.settings.Nuclei {
			result, err := scan.Nuclei(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running Nuclei module: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"nuclei", result})
			}
		}

		if app.settings.JavaScript {
			result, err := jsscan.JavascriptScan(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running JS module: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"js", result})
			}
		}

		if app.settings.CMS {
			result, err := scan.CMS(url, app.settings.Timeout, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running CMS detection: %s", err)
			} else if result != nil {
				moduleResults = append(moduleResults, ModuleResult{"cms", result})
			}
		}

		if app.settings.Headers {
			result, err := scan.Headers(url, app.settings.Timeout, app.settings.LogDir)
			if err != nil {
				log.Errorf("Error while running HTTP Header Analysis: %s", err)
			} else {
				moduleResults = append(moduleResults, ModuleResult{"headers", result})
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
		if app.settings.LogDir != "" {
			fmt.Println(styles.Box.Render(fmt.Sprintf("🌿 All scans completed!\n📂 Output saved to files: %s\n", strings.Join(app.logFiles, ", "))))
		} else {
			fmt.Println(styles.Box.Render(fmt.Sprintf("🌿 All scans completed!\n")))
		}
	}

	return nil
}