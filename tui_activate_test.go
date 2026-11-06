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

package sif

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/tui"
)

func TestHasScanSelection(t *testing.T) {
	cases := []struct {
		name string
		s    *config.Settings
		want bool
	}{
		{"empty", &config.Settings{Dirlist: "none", Dnslist: "none", Ports: "none"}, false},
		{"a toggle", &config.Settings{CORS: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true},
		{"a sized scan", &config.Settings{Dirlist: "none", Dnslist: "small", Ports: "none"}, true},
		{"modules by tag", &config.Settings{ModuleTags: "owasp", Dirlist: "none", Dnslist: "none", Ports: "none"}, true},
		{"all-modules", &config.Settings{AllModules: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasScanSelection(tc.s); got != tc.want {
				t.Errorf("HasScanSelection = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldPicker(t *testing.T) {
	empty := func() *config.Settings {
		return &config.Settings{Dirlist: "none", Dnslist: "none", Ports: "none"}
	}
	cases := []struct {
		name                string
		s                   *config.Settings
		stdoutTTY, stdinTTY bool
		want                bool
	}{
		{"newcomer: tty, no scans", empty(), true, true, true},
		{"scans already chosen", &config.Settings{CORS: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true, true, false},
		{"force with -i even with scans", &config.Settings{CORS: true, Interactive: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true, true, true},
		{"force with -pick", &config.Settings{Pick: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true, true, true},
		{"stdout piped", empty(), false, true, false},
		{"stdin piped", empty(), true, false, false},
		{"-no-tui wins", &config.Settings{NoTUI: true, Interactive: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true, true, false},
		{"-silent", &config.Settings{Silent: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true, true, false},
		{"-api", &config.Settings{ApiMode: true, Dirlist: "none", Dnslist: "none", Ports: "none"}, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldPicker(tc.s, tc.stdoutTTY, tc.stdinTTY); got != tc.want {
				t.Errorf("shouldPicker = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldDashboard(t *testing.T) {
	tty := termInfo{stdoutTTY: true, stdinTTY: true, width: 120, height: 40, term: "xterm-256color"}
	with := func(f func(*termInfo)) termInfo { c := tty; f(&c); return c }
	cases := []struct {
		name string
		s    *config.Settings
		t    termInfo
		want bool
	}{
		{"default on an interactive tty", &config.Settings{}, tty, true},
		{"on a tty with scan flags", &config.Settings{CORS: true}, tty, true},
		{"stdout piped", &config.Settings{}, with(func(t *termInfo) { t.stdoutTTY = false }), false},
		{"stdin piped", &config.Settings{}, with(func(t *termInfo) { t.stdinTTY = false }), false},
		{"zero-size pty", &config.Settings{}, with(func(t *termInfo) { t.width, t.height = 0, 0 }), false},
		{"TERM=dumb", &config.Settings{}, with(func(t *termInfo) { t.term = "dumb" }), false},
		{"-no-tui", &config.Settings{NoTUI: true}, tty, false},
		{"-silent", &config.Settings{Silent: true}, tty, false},
		{"-api", &config.Settings{ApiMode: true}, tty, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldDashboard(tc.s, tc.t); got != tc.want {
				t.Errorf("shouldDashboard = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyScanSelection(t *testing.T) {
	s := &config.Settings{Dirlist: "none", Dnslist: "none", Ports: "none"}
	sel := tui.NewSelection()
	sel.Toggles["cors"] = true
	sel.Toggles["xss"] = false // explicitly off, must stay off
	sel.Toggles["framework"] = true
	sel.Sizes["dnslist"] = "medium"
	sel.Sizes["ports"] = "" // off, must not change default

	applyScanSelection(s, &sel)

	if !s.CORS {
		t.Error("cors should be applied")
	}
	if s.XSS {
		t.Error("xss was off in the selection; must stay off")
	}
	if !s.Framework {
		t.Error("framework should be applied")
	}
	if s.Dnslist != "medium" {
		t.Errorf("dnslist = %q, want medium", s.Dnslist)
	}
	if s.Ports != "none" {
		t.Errorf("ports = %q, want unchanged none", s.Ports)
	}
}

func TestPickerSpecFlagsMapToSettings(t *testing.T) {
	// every toggle/sized flag the picker offers must be appliable, or a user
	// could select a scan that silently never runs.
	spec := pickerSpec("https://example.com")
	sel := tui.NewSelection()
	for _, g := range spec.Groups {
		for _, it := range g.Items {
			switch it.Kind {
			case tui.KindToggle:
				sel.Toggles[it.Flag] = true
			case tui.KindSized:
				sel.Sizes[it.Flag] = it.Levels[0]
			}
		}
	}
	s := &config.Settings{Dirlist: "none", Dnslist: "none", Ports: "none"}
	applyScanSelection(s, &sel)

	// spot-check one flag from each group reached a field.
	if !s.Git || !s.XSS || !s.Headers || !s.Shodan {
		t.Errorf("a picker flag did not map to its setting: git=%v xss=%v headers=%v shodan=%v",
			s.Git, s.XSS, s.Headers, s.Shodan)
	}
	if s.Dnslist != "small" || s.Ports != "common" {
		t.Errorf("sized flags did not map: dnslist=%q ports=%q", s.Dnslist, s.Ports)
	}
}

func TestDashboardReportWritesFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	app := &App{settings: &config.Settings{JSONReport: path}}

	got, err := app.dashboardReport([]finding.Finding{{Target: "https://a.com", Module: "cors", Title: "reflected origin", Severity: finding.SeverityHigh}})
	if err != nil {
		t.Fatalf("dashboardReport: %v", err)
	}
	if got != path {
		t.Errorf("path = %q, want %q", got, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "reflected origin") {
		t.Errorf("report missing finding:\n%s", data)
	}
}
