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
	"flag"
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

	return buildFlatConfig(path, prof, args)
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
// optionally overlays profiles[profile] onto the top-level keys, strips any
// key the command line set explicitly, and writes what's left to a temp yaml
// file for goflags to merge.
//
// the strip step exists because goflags' own merge (readConfigFile) treats a
// flag whose current value equals its DefValue as "unset" and applies the
// config value over it; that makes an explicit cli flag lose to the config
// file whenever the user happens to pass the flag's own default (e.g.
// "-timeout 10s" against the built-in 10s default). deleting those keys here,
// before the map ever reaches goflags, makes cli precedence unconditional.
//
// note: goflags' merge also swallows a type-mismatched config value (e.g. a
// string where an int flag expects one) because readConfigFile discards
// fl.Value.Set's error. that is a separate, lower-severity gap in the vendored
// dependency itself and is not addressed here.
func buildFlatConfig(path, profile string, args []string) (string, func(), error) {
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

	for key := range explicitConfigKeys(args) {
		delete(merged, key)
	}

	data, err := yaml.Marshal(merged)
	if err != nil {
		return "", nil, err
	}
	return materializePreset(data)
}

// explicitConfigKeys returns every config key that the command line set
// explicitly (by long name or short alias), so buildFlatConfig can drop it
// from the file/profile map regardless of what value the flag was given.
func explicitConfigKeys(args []string) map[string]bool {
	groups := flagAliasGroups()
	keys := map[string]bool{}
	for token := range explicitFlagTokens(args) {
		for _, alias := range groups[token] {
			keys[alias] = true
		}
	}
	return keys
}

// explicitFlagTokens pulls the bare name out of every "-name"/"--name"/
// "-name=value"/"--name=value" token in args. it is a presence check only
// (not a value parse), so it does not need to know which flags take a
// following argument.
func explicitFlagTokens(args []string) map[string]bool {
	tokens := map[string]bool{}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if name == "" {
			continue
		}
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		tokens[name] = true
	}
	return tokens
}

// flagAliasGroups maps every registered flag name to the full set of names
// (long and short) that back the same Settings field, keyed by the shared
// flag.Value each alias registers against a throwaway FlagSet. registering
// flags has no side effects (no parsing, no file i/o), so building this on
// every call stays cheap and keeps it in sync with registerFlags by
// construction rather than a second hardcoded name table.
func flagAliasGroups() map[string][]string {
	flagSet := registerFlags(&Settings{})

	byValue := map[flag.Value][]string{}
	flagSet.CommandLine.VisitAll(func(f *flag.Flag) {
		byValue[f.Value] = append(byValue[f.Value], f.Name)
	})

	groups := make(map[string][]string, len(byValue))
	for _, names := range byValue {
		for _, name := range names {
			groups[name] = names
		}
	}
	return groups
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
