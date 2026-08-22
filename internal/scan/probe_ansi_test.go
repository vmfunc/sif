package scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/output"
)

// extractTitle deliberately returns the raw <title> text unmodified: it's a
// data-extraction helper, and the JSON/log record of a probe result should be
// byte-accurate. sanitization happens downstream, at the point the title is
// printed to the terminal (see TestProbeTitleANSIStrippedFromTerminal below).
func TestExtractTitlePreservesRawBytes(t *testing.T) {
	body := []byte("<html><head><title>\x1b]0;PWNED\x07\x1b[2Jinnocent</title></head></html>")
	got := extractTitle(body)
	if !strings.Contains(got, "\x1b]0;PWNED\x07") || !strings.Contains(got, "\x1b[2J") {
		t.Fatalf("expected extractTitle to preserve raw bytes for the result record, got %q", got)
	}
}

// regression guard: a hostile <title> containing OSC/CSI control bytes must
// not reach the operator's terminal when Probe logs the result. probe.go
// prints output.Highlight.Render(result.Title); Highlight sanitizes its
// argument before styling it, so the escape sequences never reach the sink.
func TestProbeTitleANSIStrippedFromTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>\x1b]0;PWNED\x07\x1b[2Jinnocent</title></head></html>"))
	}))
	defer srv.Close()

	// output's sink is bound to os.Stdout/os.Stderr at the time SetSilent
	// runs, not read fresh per-write, so swap os.Stderr *then* flip silent on
	// (mirrors internal/output's own captureStdoutStderr test helper).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	output.SetSilent(true)

	outCh := make(chan string, 1)
	go func() {
		buf, _ := io.ReadAll(r)
		outCh <- string(buf)
	}()

	result, err := Probe(srv.URL, 5*time.Second, "")

	output.SetSilent(false)
	os.Stderr = oldStderr
	w.Close()
	captured := <-outCh

	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !strings.Contains(result.Title, "\x1b]0;PWNED\x07") {
		t.Fatalf("expected ProbeResult.Title to keep the raw bytes for the JSON record, got %q", result.Title)
	}

	if strings.Contains(captured, "\x1b]0;PWNED\x07") {
		t.Fatalf("expected OSC title-rewrite to be stripped from terminal output, got %q", captured)
	}
	if strings.Contains(captured, "\x1b[2J") {
		t.Fatalf("expected clear-screen sequence to be stripped from terminal output, got %q", captured)
	}
	if !strings.Contains(captured, "innocent") {
		t.Fatalf("expected legitimate title text to survive, got %q", captured)
	}
}
