package output

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// regression guard: Info (and by extension Success/Warn/Error/ModuleLogger.*)
// must strip raw ANSI/OSC control bytes from the formatted message before it
// reaches the sink, even when a caller forgets to route dynamic content
// through a Style first.
func TestInfoStripsRawANSI(t *testing.T) {
	var buf bytes.Buffer
	old := sink
	sink = &buf
	defer func() { sink = old }()

	// ESC]0;PWNED BEL -> rewrites the terminal title; ESC[2J clears screen.
	evil := "\x1b]0;PWNED\x07\x1b[2Jheader-value"
	Info("%s", evil)

	got := buf.String()
	if strings.Contains(got, "\x1b]0;PWNED\x07") {
		t.Fatalf("expected OSC title sequence to be stripped, got %q", got)
	}
	if strings.Contains(got, "\x1b[2J") {
		t.Fatalf("expected clear-screen sequence to be stripped, got %q", got)
	}
	if !strings.Contains(got, "header-value") {
		t.Fatalf("expected legitimate content to survive, got %q", got)
	}
	t.Logf("CONFIRMED: Info sanitizes control bytes before printing: %q", got)
}

// SGR color sequences (what lipgloss emits) must survive sanitization:
// Sanitize is meant to strip attacker control bytes, not legitimate styling.
func TestSanitizeKeepsSGRColor(t *testing.T) {
	styled := "\x1b[1;38;5;231mhello\x1b[0m"
	got := Sanitize(styled)
	if got != styled {
		t.Fatalf("expected SGR sequence to survive sanitize, got %q want %q", got, styled)
	}
}

// documents an existing protection: Go's net/http rejects control bytes in
// response header values at the transport layer, so headers.go's print path
// can't carry a raw ESC through a header value.
func TestHTTPHeaderRejectsESC(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		resp := "HTTP/1.1 200 OK\r\n" +
			"X-Evil: \x1b]0;PWNED\x07pwn\r\n" +
			"Content-Length: 0\r\n\r\n"
		_, _ = c.Write([]byte(resp))
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	r, err := client.Get("http://" + ln.Addr().String())
	if err == nil {
		defer r.Body.Close()
		t.Fatalf("expected Go http to reject control chars in header value, got %q", r.Header.Get("X-Evil"))
	}
	if !strings.Contains(err.Error(), "malformed MIME header") {
		t.Fatalf("unexpected error: %v", err)
	}
}
