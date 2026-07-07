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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	folderutil "github.com/projectdiscovery/utils/folder"
	"gopkg.in/yaml.v3"
)

// resolveConfigInput turns -config/-profile/-template into a single flat yaml
// config path for goflags to merge, plus a cleanup for any temp file it wrote.
// it returns ("", nil, nil) when none of the three are set, so goflags falls
// back to its own ambient default config path, unchanged.
func resolveConfigInput(args []string) (string, func(), error) {
	cfg := rawFlagValue(args, "config")
	prof := rawFlagValue(args, "profile")
	tmpl := rawFlagValue(args, "template")

	if tmpl != "" && (cfg != "" || prof != "") {
		return "", nil, fmt.Errorf("-config and -template cannot be combined")
	}
	if tmpl != "" {
		return templateConfigPath(args)
	}
	if cfg == "" && prof == "" {
		return "", nil, nil
	}

	path := cfg
	if path == "" {
		path = defaultConfigFilePath()
	} else if info, err := os.Stat(path); err != nil { //nolint:gosec // G304/G703: user-supplied config path, same as -template/-w
		return "", nil, fmt.Errorf("config file %q not found", path)
	} else if info.IsDir() {
		return "", nil, fmt.Errorf("config file %q is a directory", path)
	}

	return buildFlatConfig(path, prof)
}

// rawFlagValue pulls a -name value out of raw args before Parse (space and =
// forms, single and double dash). the value has to be known before Parse, so
// it cannot come from the parsed flag itself.
func rawFlagValue(args []string, name string) string {
	long := "-" + name
	dlong := "--" + name
	for i, arg := range args {
		if arg == long || arg == dlong {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if v, ok := strings.CutPrefix(arg, long+"="); ok {
			return v
		}
		if v, ok := strings.CutPrefix(arg, dlong+"="); ok {
			return v
		}
	}
	return ""
}

// defaultConfigFilePath mirrors goflags' own GetConfigFilePath default
// (path.go:19 in goflags), so -profile without an explicit -config resolves
// to the same ambient file goflags would otherwise merge.
func defaultConfigFilePath() string {
	appName := filepath.Base(os.Args[0])
	toolName := strings.TrimSuffix(appName, filepath.Ext(appName))
	return filepath.Join(folderutil.AppConfigDirOrDefault(".", toolName), "config.yaml")
}

// buildFlatConfig reads the config file at path through loadConfigMap (so a
// malformed file always errors the same way, whether or not -profile is set),
// optionally overlays profiles[profile] onto the top-level keys, and writes
// the result to a temp yaml file for goflags to merge.
func buildFlatConfig(path, profile string) (string, func(), error) {
	top, profiles, err := loadConfigMap(path)
	if err != nil {
		return "", nil, err
	}

	merged := make(map[string]any, len(top))
	for k, v := range top {
		merged[k] = v
	}

	if profile != "" {
		overlay, ok := profiles[profile]
		if !ok {
			names := make([]string, 0, len(profiles))
			for name := range profiles {
				names = append(names, name)
			}
			sort.Strings(names)
			available := "none"
			if len(names) > 0 {
				available = strings.Join(names, ", ")
			}
			return "", nil, fmt.Errorf("unknown profile %q; available profiles: %s", profile, available)
		}
		for k, v := range overlay {
			merged[k] = v
		}
	}

	data, err := yaml.Marshal(merged)
	if err != nil {
		return "", nil, err
	}
	return materializePreset(data)
}

// loadConfigMap decodes a config file into its top-level keys and its
// profiles submap. a missing file (the ambient default that has never been
// written) yields empty maps rather than an error, so -profile against it
// fails with a normal "unknown profile" error instead of a raw stat error.
func loadConfigMap(path string) (top map[string]any, profiles map[string]map[string]any, err error) {
	data, readErr := os.ReadFile(path) //nolint:gosec // G304: user-supplied config path, same as -template/-w
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return map[string]any{}, map[string]map[string]any{}, nil
		}
		return nil, nil, readErr
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("config file %q is not valid yaml: %w", path, err)
	}

	top = make(map[string]any, len(raw))
	profiles = make(map[string]map[string]any)
	for k, v := range raw {
		if k != "profiles" {
			top[k] = v
			continue
		}
		pm, ok := v.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("config file %q: profiles must be a map", path)
		}
		for name, pv := range pm {
			sub, ok := pv.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("config file %q: profile %q must be a map", path, name)
			}
			profiles[name] = sub
		}
	}
	return top, profiles, nil
}
