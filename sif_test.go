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
	"io"
	"os"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/store"
)

// TestMain neutralizes the stdin seam for the whole package so tests that build
// an App via New() never block on the test runner's real stdin (a pipe under
// `go test`). tests that exercise ingestion set the seams explicitly.
func TestMain(m *testing.M) {
	stdinPipedFn = func() (bool, error) { return false, nil }
	stdinReader = strings.NewReader("")
	os.Exit(m.Run())
}

// mockResult is a test implementation of ScanResult
type mockResult struct {
	name string
	data string
}

func (m *mockResult) ResultType() string {
	return m.name
}

func TestNewModuleResult(t *testing.T) {
	tests := []struct {
		name   string
		result *mockResult
		wantID string
	}{
		{
			name:   "basic result",
			result: &mockResult{name: "test", data: "test data"},
			wantID: "test",
		},
		{
			name:   "empty name",
			result: &mockResult{name: "", data: "data"},
			wantID: "",
		},
		{
			name:   "complex name",
			result: &mockResult{name: "framework-detection", data: "Laravel 8.0"},
			wantID: "framework-detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := NewModuleResult(tt.result)
			if mr.Id != tt.wantID {
				t.Errorf("NewModuleResult() Id = %q, want %q", mr.Id, tt.wantID)
			}
			if mr.Data != tt.result {
				t.Errorf("NewModuleResult() Data = %v, want %v", mr.Data, tt.result)
			}
		})
	}
}

func TestNew_NoTargets(t *testing.T) {
	settings := &config.Settings{
		URLs: []string{},
		File: "",
	}

	_, err := New(settings)
	if err == nil {
		t.Error("New() should return error when no targets provided")
	}
}

func TestNew_WithURLs(t *testing.T) {
	settings := &config.Settings{
		URLs:    []string{"https://example.com"},
		ApiMode: true,
	}

	app, err := New(settings)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if app == nil {
		t.Fatal("New() returned nil app")
	}

	if len(app.targets) != 1 {
		t.Errorf("New() targets = %d, want 1", len(app.targets))
	}

	if app.targets[0] != "https://example.com" {
		t.Errorf("New() target = %q, want %q", app.targets[0], "https://example.com")
	}
}

func TestNew_URLValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid https url",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "valid http url",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			// naked host is now accepted and normalized, not rejected
			name:    "missing protocol",
			url:     "example.com",
			wantErr: false,
		},
		{
			name:    "invalid protocol",
			url:     "ftp://example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &config.Settings{
				URLs:    []string{tt.url},
				ApiMode: true,
			}

			_, err := New(settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "naked host defaults https", in: "example.com", want: "https://example.com"},
		{name: "naked host with port", in: "example.com:8443", want: "https://example.com:8443"},
		{name: "naked host with path", in: "example.com/admin", want: "https://example.com/admin"},
		{name: "https kept", in: "https://example.com", want: "https://example.com"},
		{name: "http kept", in: "http://example.com", want: "http://example.com"},
		{name: "surrounding whitespace trimmed", in: "  example.com\t", want: "https://example.com"},
		{name: "empty rejected", in: "", wantErr: true},
		{name: "blank rejected", in: "   ", wantErr: true},
		{name: "ftp scheme rejected", in: "ftp://example.com", wantErr: true},
		{name: "file scheme rejected", in: "file:///etc/passwd", wantErr: true},
		{name: "embedded space rejected", in: "foo bar", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTarget(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeTarget(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("normalizeTarget(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNew_StdinIngestion(t *testing.T) {
	// feed a pipe of targets and assert they're parsed and normalized alongside
	// the explicit -u target. the seams stand in for a real stdin pipe.
	origPiped, origReader := stdinPipedFn, stdinReader
	t.Cleanup(func() { stdinPipedFn, stdinReader = origPiped, origReader })

	stdinPipedFn = func() (bool, error) { return true, nil }
	stdinReader = strings.NewReader("sub1.example.com\nhttps://sub2.example.com\n\n  sub3.example.com  \n")

	settings := &config.Settings{
		URLs:    []string{"https://flag.example.com"},
		ApiMode: true,
	}

	app, err := New(settings)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	want := []string{
		"https://flag.example.com",
		"https://sub1.example.com",
		"https://sub2.example.com",
		"https://sub3.example.com",
	}
	if len(app.targets) != len(want) {
		t.Fatalf("targets = %v (%d), want %d", app.targets, len(app.targets), len(want))
	}
	for i := range want {
		if app.targets[i] != want[i] {
			t.Errorf("target[%d] = %q, want %q", i, app.targets[i], want[i])
		}
	}
}

func TestNew_StdinOnly(t *testing.T) {
	// no -u/-f: a piped stream alone must satisfy the target requirement.
	origPiped, origReader := stdinPipedFn, stdinReader
	t.Cleanup(func() { stdinPipedFn, stdinReader = origPiped, origReader })

	stdinPipedFn = func() (bool, error) { return true, nil }
	stdinReader = strings.NewReader("only.example.com\n")

	app, err := New(&config.Settings{ApiMode: true})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if len(app.targets) != 1 || app.targets[0] != "https://only.example.com" {
		t.Errorf("targets = %v, want [https://only.example.com]", app.targets)
	}
}

func TestNew_NoTargets_StdinEmpty(t *testing.T) {
	// an empty pipe with no flags is still "no targets" and must error.
	origPiped, origReader := stdinPipedFn, stdinReader
	t.Cleanup(func() { stdinPipedFn, stdinReader = origPiped, origReader })

	stdinPipedFn = func() (bool, error) { return true, nil }
	stdinReader = strings.NewReader("\n  \n")

	if _, err := New(&config.Settings{ApiMode: true}); err == nil {
		t.Error("New() should error when stdin yields no targets and no flags set")
	}
}

func TestReadTargets(t *testing.T) {
	got, err := readTargets(strings.NewReader("a.com\n\n  b.com \nc.com\n"))
	if err != nil {
		t.Fatalf("readTargets() error: %v", err)
	}
	want := []string{"a.com", "b.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("readTargets() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("readTargets()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// errReader fails on first read; used to assert stdin scan errors propagate.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestReadTargets_Error(t *testing.T) {
	if _, err := readTargets(errReader{}); err == nil {
		t.Error("readTargets() should propagate a reader error")
	}
}

func TestPrintFindings(t *testing.T) {
	findings := []finding.Finding{
		{Target: "https://a.com", Module: "sql", Severity: finding.SeverityHigh, Title: "admin panel"},
		{Target: "https://b.com", Module: "headers", Severity: finding.SeverityInfo, Title: "Server"},
	}

	out := captureStdout(t, func() { printFindings(findings) })

	wantLines := []string{
		"[high] https://a.com sql admin panel",
		"[info] https://b.com headers Server",
	}
	got := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(got) != len(wantLines) {
		t.Fatalf("printFindings wrote %d lines, want %d:\n%s", len(got), len(wantLines), out)
	}
	for i := range wantLines {
		if got[i] != wantLines[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], wantLines[i])
		}
	}
}

func TestPrintFindings_Empty(t *testing.T) {
	out := captureStdout(t, func() { printFindings(nil) })
	if out != "" {
		t.Errorf("printFindings(nil) wrote %q, want empty", out)
	}
}

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, rerr := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if rerr != nil {
				break
			}
		}
		done <- string(buf)
	}()

	fn()
	os.Stdout = saved
	w.Close()
	return <-done
}

func TestModuleResult_JSON(t *testing.T) {
	mr := ModuleResult{
		Id:   "test",
		Data: map[string]string{"key": "value"},
	}

	// Verify the struct can be used (basic sanity check)
	if mr.Id != "test" {
		t.Errorf("ModuleResult.Id = %q, want %q", mr.Id, "test")
	}
}

func TestUrlResult_JSON(t *testing.T) {
	ur := UrlResult{
		Url: "https://example.com",
		Results: []ModuleResult{
			{Id: "test", Data: "data"},
		},
	}

	if ur.Url != "https://example.com" {
		t.Errorf("UrlResult.Url = %q, want %q", ur.Url, "https://example.com")
	}

	if len(ur.Results) != 1 {
		t.Errorf("UrlResult.Results = %d, want 1", len(ur.Results))
	}
}

func TestResolveStoreDir(t *testing.T) {
	// explicit -store wins over everything.
	explicit := &App{settings: &config.Settings{Store: "/tmp/snaps", LogDir: "/tmp/logs"}}
	if dir, err := explicit.resolveStoreDir(); err != nil || dir != "/tmp/snaps" {
		t.Fatalf("explicit store: got (%q, %v), want (/tmp/snaps, nil)", dir, err)
	}

	// no -store: reuse the log dir.
	logged := &App{settings: &config.Settings{LogDir: "/tmp/logs"}}
	if dir, err := logged.resolveStoreDir(); err != nil || dir != "/tmp/logs" {
		t.Fatalf("log dir fallback: got (%q, %v), want (/tmp/logs, nil)", dir, err)
	}

	// neither set: fall through to the per-user default (non-empty, no error).
	bare := &App{settings: &config.Settings{}}
	dir, err := bare.resolveStoreDir()
	if err != nil {
		t.Fatalf("default store dir: %v", err)
	}
	if dir == "" {
		t.Fatal("default store dir resolved empty")
	}
}

func TestDiffTargetSnapshotsAndDiffs(t *testing.T) {
	dir := t.TempDir()
	const target = "https://diff.example.com"
	app := &App{settings: &config.Settings{Diff: true, Store: dir}}

	first := []finding.Finding{
		{Target: target, Module: "headers", Severity: finding.SeverityInfo, Key: "headers:Server", Title: "Server", Raw: "nginx"},
	}

	// first run: no prior snapshot, everything is new; the snapshot must persist.
	app.diffTarget(dir, target, first)

	saved, err := store.Load(dir, target)
	if err != nil {
		t.Fatalf("load after first run: %v", err)
	}
	if len(saved) != 1 || saved[0].Key != "headers:Server" {
		t.Fatalf("snapshot after first run = %#v, want the headers finding", saved)
	}

	// second run with a different set: the snapshot must advance to the new set so
	// a third run would diff against it.
	second := []finding.Finding{
		{Target: target, Module: "cors", Severity: finding.SeverityMedium, Key: "cors:x", Title: "null origin", Raw: "null"},
	}
	app.diffTarget(dir, target, second)

	saved, err = store.Load(dir, target)
	if err != nil {
		t.Fatalf("load after second run: %v", err)
	}
	if len(saved) != 1 || saved[0].Key != "cors:x" {
		t.Fatalf("snapshot after second run = %#v, want the cors finding", saved)
	}

	// the delta between the two snapshots is exactly: headers gone, cors new.
	added, removed := store.Diff(first, second)
	if len(added) != 1 || added[0].Key != "cors:x" {
		t.Fatalf("added = %#v, want cors:x", added)
	}
	if len(removed) != 1 || removed[0].Key != "headers:Server" {
		t.Fatalf("removed = %#v, want headers:Server", removed)
	}
}
