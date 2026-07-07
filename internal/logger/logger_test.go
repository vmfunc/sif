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

package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInit(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	if err := Init(logDir); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Fatal("Init did not create log directory")
	}

	// Second call should be a no-op
	if err := Init(logDir); err != nil {
		t.Fatalf("Init failed on existing directory: %v", err)
	}
}

func TestWriteAndFlush(t *testing.T) {
	tmpDir := t.TempDir()

	// Write some data
	if err := Write("test", tmpDir, "hello world\n"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Flush to ensure data is written
	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Read back and verify
	content, err := os.ReadFile(filepath.Join(tmpDir, "test.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if string(content) != "hello world\n" {
		t.Errorf("Expected 'hello world\\n', got %q", content)
	}

	// Cleanup
	Close()
}

func TestWriteHeader(t *testing.T) {
	tmpDir := t.TempDir()

	if err := WriteHeader("test", tmpDir, "TestScan"); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "test.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "Starting TestScan") {
		t.Errorf("Expected header to contain 'Starting TestScan', got %q", content)
	}

	Close()
}

func TestCreateFile(t *testing.T) {
	tmpDir := t.TempDir()

	var logFiles []string
	if err := CreateFile(&logFiles, "https://example.com", tmpDir); err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if len(logFiles) != 1 {
		t.Fatalf("Expected 1 log file, got %d", len(logFiles))
	}

	content, err := os.ReadFile(logFiles[0])
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "sif log file for https://example.com") {
		t.Errorf("Expected header content, got %q", content)
	}

	Close()
}

// TestCreateFileURLWithPathDoesNotFail proves a target with a URL path (e.g.
// http://127.0.0.1:8931/) gets a writable log file. Before the fix, the
// scheme-stripped sanitized URL kept the '/' verbatim, so CreateFile tried to
// open "<dir>/127.0.0.1:8931/.log" - a path whose parent directory was never
// created - and OpenFile failed, aborting the whole target's scan.
func TestCreateFileURLWithPathDoesNotFail(t *testing.T) {
	tmpDir := t.TempDir()

	var logFiles []string
	url := "http://127.0.0.1:8931/"
	if err := CreateFile(&logFiles, url, tmpDir); err != nil {
		t.Fatalf("CreateFile with path-bearing url: %v", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if len(logFiles) != 1 {
		t.Fatalf("expected 1 log file, got %d", len(logFiles))
	}

	if filepath.Dir(logFiles[0]) != tmpDir {
		t.Fatalf("expected log file directly under %q, got %q", tmpDir, logFiles[0])
	}

	content, err := os.ReadFile(logFiles[0])
	if err != nil {
		t.Fatalf("log file not readable: %v", err)
	}
	if !strings.Contains(string(content), "sif log file for "+url) {
		t.Errorf("expected header content, got %q", content)
	}

	Close()
}

// TestCreateFileURLWithMultiSlashAndQueryDoesNotFail covers a messier target:
// multiple path segments (and a doubled slash) plus query characters. None of
// it should ever produce a nested directory or a failed OpenFile.
func TestCreateFileURLWithMultiSlashAndQueryDoesNotFail(t *testing.T) {
	tmpDir := t.TempDir()

	var logFiles []string
	url := "https://example.com:8443//a/b/c?x=1&y=2"
	if err := CreateFile(&logFiles, url, tmpDir); err != nil {
		t.Fatalf("CreateFile with multi-slash/query url: %v", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if len(logFiles) != 1 {
		t.Fatalf("expected 1 log file, got %d", len(logFiles))
	}
	if filepath.Dir(logFiles[0]) != tmpDir {
		t.Fatalf("expected log file directly under %q, got %q", tmpDir, logFiles[0])
	}
	if _, err := os.Stat(logFiles[0]); err != nil {
		t.Fatalf("log file not created: %v", err)
	}

	Close()
}

// TestWriteURLWithPathUsesSameFlatFile proves Write (used for every line after
// the header) resolves to the exact same path CreateFile wrote the header to,
// for a URL with a path component. Before the fix, both functions kept the raw
// '/' verbatim and would have hit the same missing-subdirectory error.
func TestWriteURLWithPathUsesSameFlatFile(t *testing.T) {
	tmpDir := t.TempDir()
	sanitizedURL := "127.0.0.1:8931/some/path"

	if err := WriteHeader(sanitizedURL, tmpDir, "test"); err != nil {
		t.Fatalf("WriteHeader with path-bearing url: %v", err)
	}
	if err := Write(sanitizedURL, tmpDir, "line two\n"); err != nil {
		t.Fatalf("Write with path-bearing url: %v", err)
	}
	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 flat log file under %q, got %d entries", tmpDir, len(entries))
	}
	if entries[0].IsDir() {
		t.Fatalf("expected a flat file, got a directory: %s", entries[0].Name())
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if !strings.Contains(string(content), "line two") {
		t.Errorf("Write did not land in the same file WriteHeader created: %q", content)
	}

	Close()
}

func TestConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()

	var wg sync.WaitGroup
	numWriters := 10
	writesPerWriter := 100

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerWriter; j++ {
				if err := Write("concurrent", tmpDir, "data\n"); err != nil {
					t.Errorf("Write failed: %v", err)
				}
			}
		}(i)
	}

	wg.Wait()

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "concurrent.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Count(string(content), "data\n")
	expected := numWriters * writesPerWriter
	if lines != expected {
		t.Errorf("Expected %d lines, got %d", expected, lines)
	}

	Close()
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()

	if err := Write("close_test", tmpDir, "before close\n"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if err := Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify data was flushed on close
	content, err := os.ReadFile(filepath.Join(tmpDir, "close_test.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if string(content) != "before close\n" {
		t.Errorf("Expected 'before close\\n', got %q", content)
	}

	// Write after close should create new file handle
	if err := Write("close_test", tmpDir, "after close\n"); err != nil {
		t.Fatalf("Write after close failed: %v", err)
	}

	if err := Close(); err != nil {
		t.Fatalf("Second close failed: %v", err)
	}

	content, err = os.ReadFile(filepath.Join(tmpDir, "close_test.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if string(content) != "before close\nafter close\n" {
		t.Errorf("Expected both writes, got %q", content)
	}
}
