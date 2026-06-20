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
	"embed"
	"fmt"
	"os"
	"strings"
)

//go:embed templates/*.yaml
var embeddedTemplates embed.FS

// presetNames are the templates shipped in the binary, listed in help and
// error text. each presets a batch of scans without listing every flag.
var presetNames = []string{"minimal", "recon", "full"}

// templateConfigPath resolves the -template value into a config file path for
// goflags to merge, plus a cleanup to run after Parse (embedded presets are
// written to a temp file). it returns "" when -template is unset.
func templateConfigPath(args []string) (string, func(), error) {
	value := templateFlagValue(args)
	if value == "" {
		return "", nil, nil
	}
	return resolveTemplate(value)
}

// templateFlagValue pulls the -template value out of raw args; the config path
// has to be known before Parse, so it cannot come from the parsed flag itself.
func templateFlagValue(args []string) string {
	for i, arg := range args {
		if arg == "-template" || arg == "--template" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if v, ok := strings.CutPrefix(arg, "-template="); ok {
			return v
		}
		if v, ok := strings.CutPrefix(arg, "--template="); ok {
			return v
		}
	}
	return ""
}

// resolveTemplate turns the -template value into a config file path. an existing
// local file wins; a named preset is materialized from the embedded set; a
// path-shaped miss or an unknown name is a hard error.
func resolveTemplate(value string) (string, func(), error) {
	info, err := os.Stat(value) //nolint:gosec // G304: user-supplied local template path, by design (same as the -f/-w wordlist paths)
	switch {
	case err == nil && info.IsDir():
		return "", nil, fmt.Errorf("template path %q is a directory", value)
	case err == nil:
		return value, nil, nil
	}
	if data, ok := embeddedPreset(value); ok {
		return materializePreset(data)
	}
	if looksLikePath(value) {
		return "", nil, fmt.Errorf("template file %q not found", value)
	}
	return "", nil, fmt.Errorf("unknown template %q; use a local yaml file or one of: %s",
		value, strings.Join(presetNames, ", "))
}

// embeddedPreset returns the bytes of a named preset shipped in the binary.
func embeddedPreset(name string) ([]byte, bool) {
	data, err := embeddedTemplates.ReadFile("templates/" + name + ".yaml")
	if err != nil {
		return nil, false
	}
	return data, true
}

// materializePreset writes preset bytes to a temp file so goflags, which merges
// a config by path, can read it; the cleanup removes the file after Parse.
func materializePreset(data []byte) (string, func(), error) {
	file, err := os.CreateTemp("", "sif-template-*.yaml")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return file.Name(), cleanup, nil
}

// looksLikePath reports whether the value addresses a file rather than a named
// preset: a path separator or a yaml suffix marks a file.
func looksLikePath(value string) bool {
	if strings.ContainsAny(value, `/\`) {
		return true
	}
	return strings.HasSuffix(value, ".yaml") || strings.HasSuffix(value, ".yml")
}
