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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/goflags"
)

// this whole feature rests on an unverified-until-now goflags behavior: with
// no explicit SetConfigFilePath call, goflags still resolves an ambient
// config path from the binary name, auto-creates it (all keys commented out)
// on first Parse, and merges real values from it on a later Parse. verify
// that empirically rather than trusting the goflags source read.
func TestGoflagsAutoWritesAndMergesAmbientConfig(t *testing.T) {
	goflags.DisableAutoConfigMigration = true
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	settings := &Settings{}
	flagSet := registerFlags(settings)
	if err := flagSet.Parse("-u", "x"); err != nil {
		t.Fatalf("first parse: %s", err)
	}

	cfgPath, err := flagSet.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %s", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected goflags to auto-create %s, got: %s", cfgPath, err)
	}

	if err := os.WriteFile(cfgPath, append(data, []byte("\nthreads: 42\n")...), 0o600); err != nil {
		t.Fatalf("write real value: %s", err)
	}

	settings2 := &Settings{}
	flagSet2 := registerFlags(settings2)
	if err := flagSet2.Parse("-u", "x"); err != nil {
		t.Fatalf("second parse: %s", err)
	}
	if settings2.Threads != 42 {
		t.Fatalf("expected ambient config merge to set threads=42, got %d", settings2.Threads)
	}
}

// writeConfigFile drops a yaml config in a temp dir and returns its path.
func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %s", err)
	}
	return path
}

// parseWith registers the real flags, resolves -config/-profile/-template out
// of args, merges the result as the goflags config, and parses args. it
// mirrors how config.Parse() wires resolveConfigInput to flagSet.Parse.
func parseWith(t *testing.T, args ...string) *Settings {
	t.Helper()
	goflags.DisableAutoConfigMigration = true
	settings := &Settings{}
	flagSet := registerFlags(settings)

	path, cleanup, err := resolveConfigInput(args)
	if err != nil {
		t.Fatalf("resolveConfigInput: %s", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if path != "" {
		flagSet.SetConfigFilePath(path)
	}
	if err := flagSet.Parse(args...); err != nil {
		t.Fatalf("parse: %s", err)
	}
	return settings
}

// zero-config must stay byte-identical to today: no -config/-profile/-template
// means resolveConfigInput returns a no-op and every flag keeps its
// registered built-in default.
func TestResolveConfigInputZeroConfigUnchanged(t *testing.T) {
	path, cleanup, err := resolveConfigInput([]string{"-u", "x"})
	if err != nil {
		t.Fatalf("resolveConfigInput: %s", err)
	}
	if cleanup != nil {
		t.Error("expected no cleanup for zero-config")
	}
	if path != "" {
		t.Errorf("expected empty path for zero-config, got %q", path)
	}

	settings := parseWith(t, "-u", "x")
	if settings.Threads != 10 {
		t.Errorf("expected built-in default threads=10, got %d", settings.Threads)
	}
	if settings.Headers {
		t.Error("expected built-in default headers=false")
	}
	if settings.SQL {
		t.Error("expected built-in default sql=false")
	}
}

// a plain -config file overrides built-in defaults for the keys it sets and
// leaves everything else untouched.
func TestConfigFileOverridesDefault(t *testing.T) {
	path := writeConfigFile(t, "threads: 20\nheaders: true\n")
	settings := parseWith(t, "-u", "x", "-config", path)

	if settings.Threads != 20 {
		t.Errorf("expected file threads=20, got %d", settings.Threads)
	}
	if !settings.Headers {
		t.Error("expected file headers=true")
	}
	if settings.SQL {
		t.Error("expected untouched sql to stay false")
	}
}

// an explicit cli flag beats the file, mirroring TestTemplateConfigPrecedence.
func TestExplicitFlagBeatsFile(t *testing.T) {
	path := writeConfigFile(t, "threads: 20\n")
	settings := parseWith(t, "-u", "x", "-config", path, "-threads", "5")

	if settings.Threads != 5 {
		t.Errorf("expected cli threads=5 to win over file, got %d", settings.Threads)
	}
}

// an explicit cli flag must beat the file even when its value happens to
// equal the flag's own registered default: goflags treats "flag == DefValue"
// as "unset" (readConfigFile), so without stripping explicit keys out of the
// config map first, the file value would silently win here.
func TestExplicitFlagAtDefaultBeatsFile(t *testing.T) {
	path := writeConfigFile(t, "timeout: 1s\n")
	settings := parseWith(t, "-u", "x", "-config", path, "-timeout", "10s")

	if settings.Timeout != 10*time.Second {
		t.Errorf("expected explicit cli timeout=10s to beat file's 1s, got %s", settings.Timeout)
	}
}

// the same default-value precedence bug via the flag's short alias: a config
// keyed by the long name must not survive an explicit "-t 10s" on the cli.
func TestExplicitShortFlagAtDefaultBeatsFile(t *testing.T) {
	path := writeConfigFile(t, "timeout: 1s\n")
	settings := parseWith(t, "-u", "x", "-config", path, "-t", "10s")

	if settings.Timeout != 10*time.Second {
		t.Errorf("expected explicit cli -t 10s to beat file's 1s, got %s", settings.Timeout)
	}
}

// a profile overlays on top of the file's top-level keys, and also exercises
// an enum (dirlist) and a StringSlice (header) round-tripping through the
// yaml.Marshal + goflags merge.
func TestProfileOverlaysTopLevel(t *testing.T) {
	path := writeConfigFile(t, ""+
		"threads: 20\n"+
		"profiles:\n"+
		"  quick:\n"+
		"    probe: true\n"+
		"    threads: 30\n"+
		"    dirlist: small\n"+
		"    header:\n"+
		"      - \"X-Test: 1\"\n")

	settings := parseWith(t, "-u", "x", "-config", path, "-profile", "quick")

	if !settings.Probe {
		t.Error("expected profile probe=true")
	}
	if settings.Threads != 30 {
		t.Errorf("expected profile threads=30 to beat file top-level 20, got %d", settings.Threads)
	}
	if settings.Dirlist != "small" {
		t.Errorf("expected profile dirlist=small, got %q", settings.Dirlist)
	}
	if len(settings.Header) != 1 || settings.Header[0] != "X-Test: 1" {
		t.Errorf("expected profile header slice [X-Test: 1], got %v", settings.Header)
	}
}

// an explicit cli flag still beats a profile value for the same key.
func TestCLIBeatsProfile(t *testing.T) {
	path := writeConfigFile(t, ""+
		"threads: 20\n"+
		"profiles:\n"+
		"  quick:\n"+
		"    threads: 30\n")

	settings := parseWith(t, "-u", "x", "-config", path, "-profile", "quick", "-threads", "7")

	if settings.Threads != 7 {
		t.Errorf("expected cli threads=7 to win over profile, got %d", settings.Threads)
	}
}

// same default-value precedence bug as TestExplicitFlagAtDefaultBeatsFile,
// but through a profile overlay instead of the file's top level.
func TestExplicitFlagAtDefaultBeatsProfile(t *testing.T) {
	path := writeConfigFile(t, ""+
		"profiles:\n"+
		"  quick:\n"+
		"    timeout: 1s\n")

	settings := parseWith(t, "-u", "x", "-config", path, "-profile", "quick", "-timeout", "10s")

	if settings.Timeout != 10*time.Second {
		t.Errorf("expected explicit cli timeout=10s to beat profile's 1s, got %s", settings.Timeout)
	}
}

// selecting an unknown profile is a hard error listing the profiles that do
// exist, mirroring TestResolveTemplateUnknownName.
func TestUnknownProfileErrors(t *testing.T) {
	path := writeConfigFile(t, "profiles:\n  quick:\n    probe: true\n")

	_, _, err := resolveConfigInput([]string{"-config", path, "-profile", "deep"})
	if err == nil {
		t.Fatal("expected an error for an unknown profile")
	}
	if !containsAll(err.Error(), "deep", "quick") {
		t.Errorf("expected error to name the requested and available profiles, got: %s", err)
	}
}

// -config and -template are mutually exclusive: both target goflags' single
// config file slot and cannot be chained through it.
func TestConfigAndTemplateAreMutuallyExclusive(t *testing.T) {
	cases := [][]string{
		{"-config", "/some/path.yaml", "-template", "recon"},
		{"-template", "recon", "-profile", "quick"},
	}
	for _, args := range cases {
		if _, _, err := resolveConfigInput(args); err == nil {
			t.Errorf("expected an error combining %v", args)
		}
	}
}

// an explicit -config naming a file that does not exist is a hard error; it
// must not silently fall back to the ambient default.
func TestMissingExplicitConfigFileErrors(t *testing.T) {
	if _, _, err := resolveConfigInput([]string{"-config", "/does/not/exist.yaml"}); err == nil {
		t.Fatal("expected an error for a missing -config file")
	}
}

// malformed yaml in an explicit -config file must be a hard error, matching
// the error the -profile branch already produces (its overlay logic routes
// through loadConfigMap, which validates). without -profile, resolveConfigInput
// used to return the raw path unparsed, skipping validation entirely; goflags
// then silently discarded the decode error, dropping every real setting in
// the file with no diagnostic and exit 0.
func TestMalformedConfigNoProfileErrors(t *testing.T) {
	path := writeConfigFile(t, "timeout: \"unterminated\n")

	_, _, err := resolveConfigInput([]string{"-config", path})
	if err == nil {
		t.Fatal("expected an error for malformed yaml with no -profile")
	}
	if !strings.Contains(err.Error(), "is not valid yaml") {
		t.Errorf("expected a %q error, got: %s", "is not valid yaml", err)
	}
}

// same malformed file, this time with -profile set, to confirm both branches
// now share one error message.
func TestMalformedConfigWithProfileErrors(t *testing.T) {
	path := writeConfigFile(t, "timeout: \"unterminated\n")

	_, _, err := resolveConfigInput([]string{"-config", path, "-profile", "quick"})
	if err == nil {
		t.Fatal("expected an error for malformed yaml with -profile")
	}
	if !strings.Contains(err.Error(), "is not valid yaml") {
		t.Errorf("expected a %q error, got: %s", "is not valid yaml", err)
	}
}

// a well-formed -config file with no -profile must still apply normally;
// routing it through the shared validator must not change this.
func TestWellFormedConfigNoProfileStillApplies(t *testing.T) {
	path := writeConfigFile(t, "threads: 25\n")
	settings := parseWith(t, "-u", "x", "-config", path)

	if settings.Threads != 25 {
		t.Errorf("expected well-formed no-profile config threads=25, got %d", settings.Threads)
	}
}

func TestRawFlagValue(t *testing.T) {
	cases := []struct {
		name string
		args []string
		flag string
		want string
	}{
		{"long with space", []string{"-config", "a.yaml"}, "config", "a.yaml"},
		{"double dash with space", []string{"--config", "b.yaml"}, "config", "b.yaml"},
		{"long with equals", []string{"-config=c.yaml"}, "config", "c.yaml"},
		{"double dash with equals", []string{"--config=d.yaml"}, "config", "d.yaml"},
		{"absent", []string{"-u", "x"}, "config", ""},
		{"trailing without value", []string{"-u", "x", "-config"}, "config", ""},
		{"profile long with space", []string{"-profile", "quick"}, "profile", "quick"},
		{"profile with equals", []string{"-profile=quick"}, "profile", "quick"},
		{"profile absent", []string{"-config", "a.yaml"}, "profile", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawFlagValue(tc.args, tc.flag); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
