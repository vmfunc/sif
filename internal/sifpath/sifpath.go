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

// Package sifpath resolves the per-user sif directories so every subsystem
// agrees on where user-supplied files live.
package sifpath

import (
	"os"
	"path/filepath"
	"runtime"
)

// UserSubdir returns the per-user sif configuration subdirectory for name (for
// example "modules" or "signatures"). It preserves sif's historical layout:
// ~/.config/sif/<name> on unix-like systems and %LOCALAPPDATA%\sif\<name> on
// windows.
func UserSubdir(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local", "sif", name), nil
	}
	return filepath.Join(home, ".config", "sif", name), nil
}
