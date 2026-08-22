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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif"
	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/patchnotes"
	ver "github.com/vmfunc/sif/internal/version"

	// Register framework detectors
	_ "github.com/vmfunc/sif/internal/scan/frameworks/detectors"
)

// version is stamped at release time via -ldflags "-X main.version=...";
// ver.Resolve falls back to the build info or "dev" for other builds.
var version = "dev"

func main() {
	version = ver.Resolve(version)
	sif.Version = version

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "patchnote", "patchnotes", "-pn", "--patchnotes":
			patchnotes.Print("")
			return
		case "version", "-version", "--version":
			fmt.Printf("sif %s\n", version)
			return
		}
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run wires up the app and executes it, kept separate from main so its deferred
// signal cleanup actually fires (main's log.Fatal calls os.Exit, which would
// skip a defer placed there).
func run() error {
	settings := config.Parse()

	app, err := sif.New(settings)
	if err != nil {
		return err
	}

	// patchnotes print to stdout; skip them in api/silent mode so the only thing
	// on stdout is the machine-readable result stream.
	if !settings.ApiMode && !settings.Silent {
		patchnotes.ShowOnce(version)
	}

	// cancel the run on the first interrupt so a ctrl-c stops between scan steps
	// instead of only killing the process mid-write. a second interrupt still
	// hard-kills, since NotifyContext stops trapping once fired.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx)
}
