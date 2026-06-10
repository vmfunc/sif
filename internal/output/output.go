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

package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Clean, subtle color palette
var (
	ColorGreen  = lipgloss.Color("#22c55e") // success green
	ColorBlue   = lipgloss.Color("#3b82f6") // info blue
	ColorYellow = lipgloss.Color("#eab308") // warning yellow
	ColorRed    = lipgloss.Color("#ef4444") // error red
	ColorGray   = lipgloss.Color("#6b7280") // muted gray
	ColorWhite  = lipgloss.Color("#f3f4f6") // bright text
)

// Prefix styles
var (
	prefixInfo    = lipgloss.NewStyle().Foreground(ColorBlue).Bold(true)
	prefixSuccess = lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)
	prefixWarning = lipgloss.NewStyle().Foreground(ColorYellow).Bold(true)
	prefixError   = lipgloss.NewStyle().Foreground(ColorRed).Bold(true)
)

// Text styles
var (
	Highlight = lipgloss.NewStyle().Bold(true).Foreground(ColorWhite)
	Muted     = lipgloss.NewStyle().Foreground(ColorGray)
	Status    = lipgloss.NewStyle().Bold(true).Foreground(ColorGreen)
)

// Box style for banners
var Box = lipgloss.NewStyle().
	Bold(true).
	Foreground(ColorWhite).
	BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(ColorGray).
	Align(lipgloss.Center).
	PaddingRight(15).
	PaddingLeft(15).
	Width(60)

// Subheading style
var Subheading = lipgloss.NewStyle().
	Foreground(ColorGray).
	Align(lipgloss.Center).
	PaddingRight(15).
	PaddingLeft(15).
	Width(60)

// Severity styles
var (
	SeverityLow      = lipgloss.NewStyle().Foreground(ColorGreen)
	SeverityMedium   = lipgloss.NewStyle().Foreground(ColorYellow)
	SeverityHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("#f97316")) // orange
	SeverityCritical = lipgloss.NewStyle().Foreground(ColorRed).Bold(true)
)

// Module color palette - visually distinct, nice colors
var moduleColors = []lipgloss.Color{
	lipgloss.Color("#6366f1"), // indigo
	lipgloss.Color("#8b5cf6"), // violet
	lipgloss.Color("#ec4899"), // pink
	lipgloss.Color("#f97316"), // orange
	lipgloss.Color("#14b8a6"), // teal
	lipgloss.Color("#06b6d4"), // cyan
	lipgloss.Color("#84cc16"), // lime
	lipgloss.Color("#a855f7"), // purple
	lipgloss.Color("#f43f5e"), // rose
	lipgloss.Color("#0ea5e9"), // sky
}

// getModuleColor returns a consistent color for a module name
func getModuleColor(name string) lipgloss.Color {
	// Simple hash to pick a color
	hash := 0
	for _, c := range name {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return moduleColors[hash%len(moduleColors)]
}

// moduleStyleFor returns a styled prefix for a module
func moduleStyleFor(name string) lipgloss.Style {
	return lipgloss.NewStyle().
		Background(getModuleColor(name)).
		Foreground(lipgloss.Color("#ffffff")).
		Bold(true).
		Padding(0, 1)
}

// IsTTY returns true if stdout is a terminal
var IsTTY = checkTTY()

func checkTTY() bool {
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		return true
	}
	return false
}

// apiMode disables visual output when true
var apiMode bool

// SetAPIMode enables or disables API mode
func SetAPIMode(enabled bool) {
	apiMode = enabled
}

// sink is where all banner/spinner/log chrome is written. it defaults to stdout
// so normal runs are unchanged; -silent repoints it at stderr so stdout carries
// nothing but the machine-readable findings a downstream pipe consumes.
var sink io.Writer = os.Stdout

// silent is the plain-sink mode: chrome goes to stderr and interactive widgets
// (spinners, live progress) are suppressed so a piped consumer never sees them.
var silent bool

// SetSilent routes all chrome to stderr and marks the run non-interactive.
// findings are printed to stdout by the caller via Finding/PrintFinding; the
// output package itself never touches stdout once silent is on.
func SetSilent(enabled bool) {
	silent = enabled
	if enabled {
		sink = os.Stderr
		return
	}
	sink = os.Stdout
}

// Silent reports whether plain-sink mode is active. callers gate interactive
// behaviour (spinners, prompts) on this.
func Silent() bool {
	return silent
}

// Writer is the current chrome sink (stdout normally, stderr under -silent).
// callers that render their own chrome (the startup banner) write here so it
// follows the same routing as everything else.
func Writer() io.Writer {
	return sink
}

// Info prints an informational message with [*] prefix
func Info(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s\n", prefixInfo.Render("[*]"), msg)
}

// Success prints a success message with [+] prefix
func Success(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s\n", prefixSuccess.Render("[+]"), msg)
}

// Warn prints a warning message with [!] prefix
func Warn(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s\n", prefixWarning.Render("[!]"), msg)
}

// Error prints an error message with [-] prefix
func Error(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s\n", prefixError.Render("[-]"), msg)
}

// ScanStart prints a styled scan start message
func ScanStart(scanName string) {
	if apiMode {
		return
	}
	fmt.Fprintf(sink, "%s starting %s\n", prefixInfo.Render("[*]"), scanName)
}

// ScanComplete prints a styled scan completion message
func ScanComplete(scanName string, resultCount int, resultType string) {
	if apiMode {
		return
	}
	fmt.Fprintf(sink, "%s %s complete (%d %s)\n", prefixInfo.Render("[*]"), scanName, resultCount, resultType)
}

// Module creates a prefixed logger for a specific module/tool
func Module(name string) *ModuleLogger {
	return &ModuleLogger{
		name:  name,
		style: moduleStyleFor(name),
	}
}

// ModuleLogger provides prefixed logging for a specific module
type ModuleLogger struct {
	name  string
	style lipgloss.Style
}

func (m *ModuleLogger) prefix() string {
	return m.style.Render(m.name)
}

// Info prints an info message with module prefix
func (m *ModuleLogger) Info(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s\n", m.prefix(), msg)
}

// Success prints a success message with module prefix
func (m *ModuleLogger) Success(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s %s\n", m.prefix(), prefixSuccess.Render("✓"), msg)
}

// Warn prints a warning message with module prefix
func (m *ModuleLogger) Warn(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s %s\n", m.prefix(), prefixWarning.Render("!"), msg)
}

// Error prints an error message with module prefix
func (m *ModuleLogger) Error(format string, args ...interface{}) {
	if apiMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(sink, "%s %s %s\n", m.prefix(), prefixError.Render("✗"), msg)
}

// Start prints a scan start message with module prefix (adds newline before for separation)
func (m *ModuleLogger) Start() {
	if apiMode {
		return
	}
	fmt.Fprintf(sink, "\n%s starting scan\n", m.prefix())
}

// Complete prints a scan complete message with module prefix
func (m *ModuleLogger) Complete(resultCount int, resultType string) {
	if apiMode {
		return
	}
	fmt.Fprintf(sink, "%s complete (%d %s)\n", m.prefix(), resultCount, resultType)
}

// ClearLine clears the current line (for progress bar updates). silent mode is
// non-interactive, so there's no live line to clear and stdout stays untouched.
func ClearLine() {
	if !IsTTY || silent {
		return
	}
	fmt.Fprint(sink, "\033[2K\r")
}

// Summary styles
var (
	summaryHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWhite).
			Background(lipgloss.Color("#22c55e")).
			Padding(0, 2)

	summaryLine = lipgloss.NewStyle().
			Foreground(ColorGray)
)

// PrintSummary prints a clean scan completion summary
func PrintSummary(scans []string, logFiles []string) {
	if apiMode {
		return
	}

	fmt.Fprintln(sink)
	fmt.Fprintln(sink, summaryLine.Render("────────────────────────────────────────────────────────────"))
	fmt.Fprintln(sink)
	fmt.Fprintf(sink, "  %s\n", summaryHeader.Render("SCAN COMPLETE"))
	fmt.Fprintln(sink)

	// Print scans
	scanList := strings.Join(scans, ", ")
	fmt.Fprintf(sink, "  %s %s\n", Muted.Render("Scans:"), scanList)

	// Print log files if any
	if len(logFiles) > 0 {
		fmt.Fprintf(sink, "  %s %s\n", Muted.Render("Output:"), strings.Join(logFiles, ", "))
	}

	fmt.Fprintln(sink)
	fmt.Fprintln(sink, summaryLine.Render("────────────────────────────────────────────────────────────"))
	fmt.Fprintln(sink)
}
