package sif

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/pushfs/sif/internal/styles"
	"github.com/pushfs/sif/pkg/config"
	"github.com/pushfs/sif/pkg/logger"
	"github.com/pushfs/sif/pkg/scan"
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
			if err := logger.CreateFile(app.logFiles, url, app.settings.LogDir); err != nil {
				return err
			}
		}

		if !app.settings.NoScan {
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

		if app.settings.Dorking {
			scan.Dork(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Git {
			scan.Git(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
		}

		if app.settings.Nuclei {
			scan.Nuclei(url, app.settings.Timeout, app.settings.Threads, app.settings.LogDir)
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
