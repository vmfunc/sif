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
	"fmt"
	"os"

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

	settings := config.Parse()

	app, err := sif.New(settings)
	if err != nil {
		log.Fatal(err)
	}

	// patchnotes print to stdout; skip them in api/silent mode so the only thing
	// on stdout is the machine-readable result stream.
	if !settings.ApiMode && !settings.Silent {
		patchnotes.ShowOnce(version)
	}

	err = app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
