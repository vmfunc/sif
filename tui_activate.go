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
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/mattn/go-isatty"
	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/event"
	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/tui"
	"golang.org/x/term"
)

// pickerItems is the catalog the picker presents, grouped the way the roadmap
// describes. Each item's Flag matches the CLI flag it drives, so the picker's
// equivalent-command line and applyScanSelection stay in lockstep with the real
// flag set.
func pickerSpec(target string) tui.PickerSpec {
	sizes := []string{"small", "medium", "large"}
	return tui.PickerSpec{
		Target: target,
		Groups: []tui.Group{
			{Name: "Recon", Items: []tui.Item{
				{Flag: "dnslist", Label: "DNS brute", Desc: "subdomain fuzzing", Kind: tui.KindSized, Levels: sizes},
				{Flag: "ports", Label: "Port scan", Desc: "tcp port scan", Kind: tui.KindSized, Levels: []string{"common", "full"}},
				{Flag: "crawl", Label: "Crawl", Desc: "spider same-host links/scripts/forms", Kind: tui.KindToggle},
				{Flag: "passive", Label: "Passive", Desc: "zero-traffic subdomain/url discovery", Kind: tui.KindToggle},
				{Flag: "probe", Label: "Probe", Desc: "liveness: status/title/server", Kind: tui.KindToggle},
				{Flag: "whois", Label: "WHOIS", Desc: "whois lookup", Kind: tui.KindToggle},
				{Flag: "git", Label: "Git", Desc: "exposed .git repo scan", Kind: tui.KindToggle},
			}},
			{Name: "Web vulns", Items: []tui.Item{
				{Flag: "xss", Label: "XSS", Desc: "reflected xss probe", Kind: tui.KindToggle},
				{Flag: "cors", Label: "CORS", Desc: "cors misconfiguration probe", Kind: tui.KindToggle},
				{Flag: "redirect", Label: "Open redirect", Desc: "open redirect probe", Kind: tui.KindToggle},
				{Flag: "sql", Label: "SQL recon", Desc: "admin panels, error disclosure", Kind: tui.KindToggle},
				{Flag: "lfi", Label: "LFI", Desc: "local file inclusion recon", Kind: tui.KindToggle},
			}},
			{Name: "Info / panels", Items: []tui.Item{
				{Flag: "cms", Label: "CMS", Desc: "cms detection", Kind: tui.KindToggle},
				{Flag: "framework", Label: "Framework", Desc: "web framework detection", Kind: tui.KindToggle},
				{Flag: "headers", Label: "Headers", Desc: "http header analysis", Kind: tui.KindToggle},
				{Flag: "sh", Label: "Sec headers", Desc: "missing/weak security headers", Kind: tui.KindToggle},
				{Flag: "favicon", Label: "Favicon", Desc: "favicon hash fingerprinting", Kind: tui.KindToggle},
				{Flag: "openapi", Label: "OpenAPI", Desc: "swagger/openapi spec exposure", Kind: tui.KindToggle},
				{Flag: "jwt", Label: "JWT", Desc: "jwt discovery + offline analysis", Kind: tui.KindToggle},
			}},
			{Name: "Intel", Items: []tui.Item{
				{Flag: "shodan", Label: "Shodan", Desc: "shodan lookup (needs SHODAN_API_KEY)", Kind: tui.KindToggle},
				{Flag: "securitytrails", Label: "SecurityTrails", Desc: "domain discovery (needs api key)", Kind: tui.KindToggle},
				{Flag: "dork", Label: "Dorking", Desc: "google dorking", Kind: tui.KindToggle},
			}},
		},
		Presets: []tui.Preset{
			{Name: "quick", Values: map[string]string{"headers": "on", "framework": "on"}},
			{Name: "recon", Values: map[string]string{"dnslist": "small", "ports": "common", "crawl": "on", "passive": "on"}},
			{Name: "web", Values: map[string]string{"cors": "on", "xss": "on", "redirect": "on", "sql": "on", "lfi": "on"}},
			{Name: "full", Values: map[string]string{
				"dirlist": "small", "dnslist": "small", "ports": "common",
				"headers": "on", "sh": "on", "cms": "on", "framework": "on", "git": "on", "whois": "on",
			}},
			{Name: "passive", Values: map[string]string{"passive": "on"}},
		},
	}
}

// HasScanSelection reports whether the user explicitly asked for any scan
// (toggle, sized scan, or modules). The default base scan does not count: the
// picker is for the newcomer who ran sif with no scan flags at all.
func HasScanSelection(s *config.Settings) bool {
	if s.Nuclei || s.AllModules || s.Modules != "" || s.ModuleTags != "" {
		return true
	}
	for _, on := range []bool{
		s.Crawl, s.Passive, s.Probe, s.Whois, s.Git,
		s.XSS, s.CORS, s.Redirect, s.SQL, s.LFI,
		s.CMS, s.Framework, s.Headers, s.SecurityHeaders, s.Favicon, s.OpenAPI, s.JWT,
		s.Shodan, s.SecurityTrails, s.Dorking,
		s.CloudStorage, s.SubdomainTakeover, s.TLSCert, s.JavaScript,
	} {
		if on {
			return true
		}
	}
	for _, sz := range []string{s.Dirlist, s.Dnslist, s.Ports} {
		if sz != "" && sz != "none" {
			return true
		}
	}
	return false
}

// applyScanSelection folds a picker Selection into the scan settings, mapping
// each flag name to its field. It is the inverse of pickerSpec and the
// equivalent-command line.
func applyScanSelection(s *config.Settings, sel *tui.Selection) {
	set := map[string]*bool{
		"crawl": &s.Crawl, "passive": &s.Passive, "probe": &s.Probe, "whois": &s.Whois, "git": &s.Git,
		"xss": &s.XSS, "cors": &s.CORS, "redirect": &s.Redirect, "sql": &s.SQL, "lfi": &s.LFI,
		"cms": &s.CMS, "framework": &s.Framework, "headers": &s.Headers, "sh": &s.SecurityHeaders,
		"favicon": &s.Favicon, "openapi": &s.OpenAPI, "jwt": &s.JWT,
		"shodan": &s.Shodan, "securitytrails": &s.SecurityTrails, "dork": &s.Dorking,
	}
	for flag, on := range sel.Toggles {
		if p, ok := set[flag]; ok && on {
			*p = true
		}
	}
	for flag, lvl := range sel.Sizes {
		if lvl == "" {
			continue
		}
		switch flag {
		case "dirlist":
			s.Dirlist = lvl
		case "dnslist":
			s.Dnslist = lvl
		case "ports":
			s.Ports = lvl
		}
	}
}

// shouldPicker decides whether to open the interactive picker, given the
// settings and whether stdin/stdout are interactive terminals. Pure, so the
// decision is unit-testable without a real tty.
func shouldPicker(s *config.Settings, stdoutTTY, stdinTTY bool) bool {
	if s.NoTUI || s.ApiMode || s.Silent {
		return false
	}
	if !stdoutTTY || !stdinTTY {
		return false // piped in or out: never take over the terminal
	}
	if s.Interactive || s.Pick {
		return true
	}
	// otherwise, only when the user picked no scans — the newcomer path.
	return !HasScanSelection(s)
}

// maybePick opens the picker when the conditions are met, applies the chosen
// scans to the settings, and reports whether the user cancelled (so the caller
// can exit without scanning). When the picker does not open it is a no-op.
func (app *App) maybePick(ctx context.Context) (cancelled bool) {
	stdinTTY := isatty.IsTerminal(os.Stdin.Fd())
	if !shouldPicker(app.settings, output.IsTTY, stdinTTY) {
		return false
	}
	if len(app.targets) == 0 {
		return false
	}

	sel, run, err := tui.Pick(ctx, Version, pickerSpec(app.targets[0]))
	if err != nil {
		log.Warnf("picker failed, continuing with current flags: %v", err)
		return false
	}
	if !run {
		return true // user quit the picker
	}
	applyScanSelection(app.settings, &sel)
	return false
}

// shouldDashboard decides whether the scan runs under the live dashboard. It is
// the default only on a genuinely interactive terminal: stdin and stdout both
// ttys, a usable window size, and not TERM=dumb. -no-tui, -api and -silent opt
// out. Anything else falls back to the plain console stream. Pure, so the
// decision is unit-testable without a real tty.
func shouldDashboard(s *config.Settings, t termInfo) bool {
	if s.NoTUI || s.ApiMode || s.Silent {
		return false
	}
	if !t.stdoutTTY || !t.stdinTTY {
		return false
	}
	if t.term == "dumb" {
		return false
	}
	// a tty that reports no size (some ptys, CI shells) can't lay out the
	// dashboard; it would sit on its init screen forever.
	return t.width > 0 && t.height > 0
}

// termInfo is the terminal state shouldDashboard decides on.
type termInfo struct {
	stdoutTTY, stdinTTY bool
	width, height       int
	term                string
}

// useDashboard applies shouldDashboard to the real terminal.
func (app *App) useDashboard() bool {
	t := termInfo{
		stdoutTTY: output.IsTTY,
		stdinTTY:  isatty.IsTerminal(os.Stdin.Fd()),
		term:      os.Getenv("TERM"),
	}
	if t.stdoutTTY {
		// stdout's fd is a small non-negative descriptor, so the uintptr->int
		// conversion cannot overflow.
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil { //nolint:gosec // G115: fd fits in int
			t.width, t.height = w, h
		}
	}
	return shouldDashboard(app.settings, t)
}

// runDashboard runs scan under the live dashboard. While the alt screen owns the
// terminal the engine's console chrome is discarded (the dashboard renders the
// same findings from the event stream) and log output is buffered, then
// replayed once the terminal is restored so warnings and errors aren't lost.
// It returns tui.ErrQuit when the user quit before the scan finished.
func (app *App) runDashboard(collector *event.Collector, scan func(event.Sink) ([]targetScan, error)) ([]targetScan, error) {
	prevOut := output.SetWriter(io.Discard)
	logs := &syncBuffer{}
	log.SetOutput(logs)
	defer func() {
		output.SetWriter(prevOut)
		log.SetOutput(os.Stderr)
		if logs.Len() > 0 {
			_, _ = os.Stderr.Write(logs.Bytes())
		}
	}()

	var results []targetScan
	cfg := tui.Config{Version: Version, Targets: app.targets, WriteReport: app.dashboardReport}
	err := tui.Run(context.Background(), cfg, func(_ context.Context, sink event.Sink) error {
		var err error
		results, err = scan(event.NewMultiplexer(collector, sink))
		return err
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// dashboardReport backs the dashboard's `w` key: it writes the findings seen so
// far as a JSON report to the -json path when one was given, else to a
// timestamped file in the working directory, and returns the path written.
func (app *App) dashboardReport(findings []finding.Finding) (string, error) {
	path := app.settings.JSONReport
	if path == "" {
		path = "sif-report-" + time.Now().Format("20060102-150405") + ".json"
	}
	if err := app.writeJSONReport(path, findings); err != nil {
		return "", err
	}
	return path, nil
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes -concurrency
// workers make through the shared logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Bytes()
}
