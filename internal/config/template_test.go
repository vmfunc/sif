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
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/goflags"
	"gopkg.in/yaml.v3"
)

// writeTemplate drops a yaml template in a temp dir and returns its path.
func writeTemplate(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tmpl.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write template: %s", err)
	}
	return path
}

// loadPreset registers the real flags, merges the named embedded preset, and
// returns the resulting settings (no cli scan flags set).
func loadPreset(t *testing.T, name string) *Settings {
	t.Helper()
	goflags.DisableAutoConfigMigration = true
	path, cleanup, err := resolveTemplate(name)
	if err != nil {
		t.Fatalf("resolve %s: %s", name, err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	settings := &Settings{}
	flagSet := registerFlags(settings)
	flagSet.SetConfigFilePath(path)
	if err := flagSet.Parse("-silent"); err != nil {
		t.Fatalf("parse %s: %s", name, err)
	}
	return settings
}

// every key in an embedded preset must be a real flag long-name. goflags drops
// unknown config keys silently, so a typo would otherwise ship as a dead no-op.
func TestPresetKeysAreRegisteredFlags(t *testing.T) {
	valid := map[string]bool{}
	registerFlags(&Settings{}).CommandLine.VisitAll(func(f *flag.Flag) {
		valid[f.Name] = true
	})

	for _, name := range presetNames {
		data, ok := embeddedPreset(name)
		if !ok {
			t.Errorf("preset %q is not embedded", name)
			continue
		}
		var keys map[string]any
		if err := yaml.Unmarshal(data, &keys); err != nil {
			t.Errorf("preset %q is not valid yaml: %s", name, err)
			continue
		}
		for key := range keys {
			if !valid[key] {
				t.Errorf("preset %q references unknown flag %q", name, key)
			}
		}
	}
}

func TestPresetMinimal(t *testing.T) {
	s := loadPreset(t, "minimal")
	if !s.Probe || !s.Headers || !s.Favicon {
		t.Errorf("minimal should enable probe/headers/favicon, got probe=%v headers=%v favicon=%v",
			s.Probe, s.Headers, s.Favicon)
	}
	if s.XSS || s.SQL || s.Nuclei {
		t.Error("minimal should not enable heavy or intrusive scans")
	}
}

func TestPresetReconIsNonIntrusive(t *testing.T) {
	s := loadPreset(t, "recon")
	if !s.Passive || !s.Whois || !s.CMS || !s.Probe {
		t.Errorf("recon should enable passive/whois/cms/probe, got %v/%v/%v/%v",
			s.Passive, s.Whois, s.CMS, s.Probe)
	}
	if s.XSS || s.SQL || s.LFI || s.Redirect {
		t.Errorf("recon must not enable payload-injecting scans: xss=%v sql=%v lfi=%v redirect=%v",
			s.XSS, s.SQL, s.LFI, s.Redirect)
	}
}

func TestPresetFull(t *testing.T) {
	s := loadPreset(t, "full")
	if !s.XSS || !s.SQL || !s.LFI || !s.Redirect {
		t.Error("full should enable the intrusive scans")
	}
	if s.Dirlist != "large" || s.Ports != "full" {
		t.Errorf("full should set dirlist=large ports=full, got dirlist=%q ports=%q",
			s.Dirlist, s.Ports)
	}
}

// the template merges as the goflags config: it fills flags left at their
// default, an explicit cli flag still wins, and an untouched flag stays put.
func TestTemplateConfigPrecedence(t *testing.T) {
	goflags.DisableAutoConfigMigration = true
	tmpl := writeTemplate(t, "cms: true\nthreads: 99\n")

	var cms, sql bool
	var threads int
	flagSet := goflags.NewFlagSet()
	flagSet.BoolVar(&cms, "cms", false, "")
	flagSet.BoolVar(&sql, "sql", false, "")
	flagSet.IntVar(&threads, "threads", 10, "")

	flagSet.SetConfigFilePath(tmpl)
	if err := flagSet.Parse("-threads", "5"); err != nil {
		t.Fatalf("parse: %s", err)
	}

	if !cms {
		t.Error("expected template to set cms=true")
	}
	if threads != 5 {
		t.Errorf("expected cli threads 5 to win over template, got %d", threads)
	}
	if sql {
		t.Error("expected sql left untouched to stay false")
	}
}

func TestTemplateFlagValue(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"long with space", []string{"-template", "a.yaml"}, "a.yaml"},
		{"double dash with space", []string{"--template", "b.yaml"}, "b.yaml"},
		{"long with equals", []string{"-template=c.yaml"}, "c.yaml"},
		{"double dash with equals", []string{"--template=d.yaml"}, "d.yaml"},
		{"absent", []string{"-u", "x"}, ""},
		{"trailing without value", []string{"-u", "x", "-template"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := templateFlagValue(tc.args); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestResolveTemplateExistingFile(t *testing.T) {
	path := writeTemplate(t, "cms: true\n")
	got, cleanup, err := resolveTemplate(path)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("resolveTemplate: %s", err)
	}
	if got != path {
		t.Errorf("expected %q, got %q", path, got)
	}
}

func TestResolveTemplateNamedPreset(t *testing.T) {
	path, cleanup, err := resolveTemplate("recon")
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("recon preset should resolve: %s", err)
	}
	if path == "" {
		t.Fatal("expected a materialized preset path")
	}
}

func TestResolveTemplateMissingFile(t *testing.T) {
	if _, _, err := resolveTemplate("./does-not-exist.yaml"); err == nil {
		t.Fatal("expected an error for a missing template file")
	}
}

func TestResolveTemplateDirectory(t *testing.T) {
	if _, _, err := resolveTemplate(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory")
	}
}

func TestResolveTemplateUnknownName(t *testing.T) {
	if _, _, err := resolveTemplate("bogus"); err == nil {
		t.Fatal("expected an error for an unknown template name")
	}
}
