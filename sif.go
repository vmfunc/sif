package sif

import (
	"bufio"
	"errors"
	"fmt"
  "io"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/config"
	"github.com/dropalldatabases/sif/pkg/logger"
	"github.com/dropalldatabases/sif/pkg/scan"
	"github.com/dropalldatabases/sif/pkg/utils"
)

// App is a client instance. It is first initialised using New and then ran
// using Run, which starts the whole app process.
type App struct {
	settings *config.Settings
	targets  []string
	logFiles []string
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
		return app, errors.New("target(s) must be supplied with -u or -f")
	}

	return app, nil
}

func fetchRobotsTXT(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusMovedPermanently {
		redirectURL := resp.Header.Get("Location")
		if redirectURL == "" {
			return "", errors.New("redirect location is empty")
		}
		return fetchRobotsTXT(redirectURL)
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("failed to fetch robots.txt: %s", resp.Status))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// Run runs the pentesting suite, with the targets specified, according to the
// settings specified.
func (app *App) Run() error {
	if app.settings.Debug {
		log.SetLevel(log.DebugLevel)
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

		if app.settings.LogDir != "" {
			if err := logger.CreateFile(&app.logFiles, url, app.settings.LogDir); err != nil {
				return err
			}
		}

		if !app.settings.NoScan {
			robotsTxt, err := fetchRobotsTXT(fmt.Sprintf("%s/robots.txt", url))
			if err != nil {
				log.Errorf("Failed to fetch robots.txt for %s: %v", url, err)
			} else {
				log.Infof("robots.txt content for %s:\n%s", url, robotsTxt)
			}
			scan.Scan(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Dirlist != "none" {
			scan.Dirlist(app.settings.Dirlist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Dnslist != "none" {
			scan.Dnslist(app.settings.Dnslist, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Ports != "none" {
			scan.Ports(app.settings.Ports, url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Whois {
			scan.Whois(url, app.settings.LogDir)
		}

		// func Git(url string, timeout time.Duration, threads int, logdir string)
		if app.settings.Git {
			scan.Git(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.ApiMode {
			utils.ReturnApiOutput()
		}

		// TODO: WHOIS
	}

	if app.settings.LogDir != "" {
		fmt.Println(styles.Box.Render(fmt.Sprintf("🌿 All scans completed!\n📂 Output saved to files: %s\n", strings.Join(app.logFiles, ", "))))
	} else {
		fmt.Println(styles.Box.Render(fmt.Sprintf("🌿 All scans completed!\n")))
	}

	return nil
}
