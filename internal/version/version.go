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

// Package version resolves sif's version from the build.
package version

import (
	"runtime/debug"
	"strings"
)

// Resolve returns the best version available: the build-time ldflag if it was
// stamped, else the go build info (module tag or vcs revision), else "dev". the
// leading v is dropped so it matches the bare form the rest of sif uses.
func Resolve(ldflag string) string {
	if ldflag != "" && ldflag != "dev" {
		return normalize(ldflag)
	}
	if v := fromBuildInfo(); v != "" {
		return normalize(v)
	}
	return "dev"
}

func fromBuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	// no module tag (a local build) - fall back to the commit it was built from
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return revision
}

func normalize(v string) string {
	return strings.TrimPrefix(v, "v")
}
