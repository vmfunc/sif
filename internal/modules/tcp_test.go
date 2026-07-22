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

package modules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeTCPServer answers from a fixture over an in-memory pipe and records the
// probe the executor wrote and the address it dialed.
type fakeTCPServer struct {
	reply string
	addr  string
	sent  chan []byte
}

// serve drains any probe the client sends (so a synchronous pipe write does not
// deadlock) and replies with the fixture.
func (s *fakeTCPServer) serve(conn net.Conn) {
	defer conn.Close()
	go func() {
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		s.sent <- append([]byte(nil), buf[:n]...)
	}()
	if s.reply != "" {
		_, _ = conn.Write([]byte(s.reply))
	}
}

// withFakeTCP installs a fake dialer that hands the executor one pipe end and
// streams the reply over the other, then returns the fake so a test can read
// back the dialed address and the probe bytes.
func withFakeTCP(t *testing.T, reply string) *fakeTCPServer {
	t.Helper()
	s := &fakeTCPServer{reply: reply, sent: make(chan []byte, 1)}
	orig := newTCPConn
	newTCPConn = func(_ context.Context, addr string, _ time.Duration) (net.Conn, error) {
		s.addr = addr
		client, server := net.Pipe()
		go s.serve(server)
		return client, nil
	}
	t.Cleanup(func() { newTCPConn = orig })
	return s
}

func tcpWord(words ...string) Matcher {
	return Matcher{Type: "word", Words: words}
}

func tcpDef(cfg *TCPConfig) *YAMLModule {
	return &YAMLModule{ID: "tcp-test", Type: TypeTCP, Info: YAMLModuleInfo{Severity: "info"}, TCP: cfg}
}

func TestExecuteTCPModuleMatchAndExtract(t *testing.T) {
	withFakeTCP(t, "+OK Redis 7.2.4 ready\r\n")

	def := tcpDef(&TCPConfig{
		Port:     6379,
		Data:     "PING\r\n",
		Matchers: []Matcher{tcpWord("+OK", "Redis")},
		Extractors: []Extractor{
			{Type: "regex", Name: "version", Regex: []string{`Redis (\d+\.\d+\.\d+)`}, Group: 1},
		},
	})

	res, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteTCPModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Extracted["version"]; got != "7.2.4" {
		t.Errorf("extracted version = %q, want 7.2.4", got)
	}
	if res.Findings[0].Evidence == "" {
		t.Error("evidence is empty")
	}
}

func TestExecuteTCPModuleNoMatch(t *testing.T) {
	withFakeTCP(t, "+OK ready\r\n")
	def := tcpDef(&TCPConfig{Port: 6379, Matchers: []Matcher{tcpWord("absent-token")}})

	res, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteTCPModule: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(res.Findings))
	}
}

func TestExecuteTCPModuleSendsProbe(t *testing.T) {
	s := withFakeTCP(t, "PONG\r\n")
	def := tcpDef(&TCPConfig{Port: 6379, Data: "PING\r\n", Matchers: []Matcher{tcpWord("PONG")}})

	if _, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{}); err != nil {
		t.Fatalf("ExecuteTCPModule: %v", err)
	}
	if got := string(<-s.sent); got != "PING\r\n" {
		t.Errorf("server received probe %q, want %q", got, "PING\r\n")
	}
	if s.addr != "example.com:6379" {
		t.Errorf("dialed %q, want example.com:6379", s.addr)
	}
}

func TestExecuteTCPModuleDecodesProbeEscapes(t *testing.T) {
	// data written with literal backslashes (a single-quoted or plain yaml scalar)
	// is decoded to real control bytes before it goes on the wire.
	s := withFakeTCP(t, "PONG\r\n")
	def := tcpDef(&TCPConfig{Port: 6379, Data: `PING\r\n`, Matchers: []Matcher{tcpWord("PONG")}})

	if _, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{}); err != nil {
		t.Fatalf("ExecuteTCPModule: %v", err)
	}
	if got := string(<-s.sent); got != "PING\r\n" {
		t.Errorf("server received probe %q, want PING followed by CRLF", got)
	}
}

func TestDecodeTCPData(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no backslash is unchanged", "PING", "PING"},
		{"crlf", `PING\r\n`, "PING\r\n"},
		{"tab then null via hex", `a\tb\x00`, "a\tb\x00"},
		{"hex pair", `\x41\x42`, "AB"},
		{"escaped backslash", `a\\b`, `a\b`},
		{"unknown escape kept verbatim", `a\zb`, `a\zb`},
		{"trailing backslash kept", `abc\`, `abc\`},
		{"malformed hex kept", `\xZZ`, `\xZZ`},
		{"short hex kept", `\x4`, `\x4`},
		{"every simple escape", `\a\b\f\n\r\t\v`, "\a\b\f\n\r\t\v"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeTCPData(tt.in); got != tt.want {
				t.Errorf("decodeTCPData(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExecuteTCPModulePassiveBanner(t *testing.T) {
	// no data probe: the service speaks first (ssh, ftp, smtp).
	withFakeTCP(t, "SSH-2.0-OpenSSH_9.6\r\n")
	def := tcpDef(&TCPConfig{Port: 22, Matchers: []Matcher{tcpWord("SSH-2.0")}})

	res, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteTCPModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
}

func TestCheckTCPMatchers(t *testing.T) {
	data := "SSH-2.0-OpenSSH_9.6 Ubuntu"

	tests := []struct {
		name     string
		matchers []Matcher
		want     bool
	}{
		{"no matchers is false", nil, false},
		{"single word hit", []Matcher{tcpWord("OpenSSH")}, true},
		{"single word miss", []Matcher{tcpWord("Dropbear")}, false},
		{"and across matchers all hit", []Matcher{tcpWord("SSH-2.0"), tcpWord("Ubuntu")}, true},
		{"and across matchers one miss", []Matcher{tcpWord("SSH-2.0"), tcpWord("Debian")}, false},
		{"negative inverts a miss to a hit", []Matcher{{Type: "word", Words: []string{"Dropbear"}, Negative: true}}, true},
		{"negative inverts a hit to a miss", []Matcher{{Type: "word", Words: []string{"OpenSSH"}, Negative: true}}, false},
		{"regex hit", []Matcher{{Type: "regex", Regex: []string{`OpenSSH_\d+\.\d+`}}}, true},
		{"size hit", []Matcher{{Type: "size", Size: []int{len(data)}}}, true},
		{"size miss", []Matcher{{Type: "size", Size: []int{1}}}, false},
		{"status type never matches in tcp", []Matcher{{Type: "status", Status: []int{0}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkTCPMatchers(tt.matchers, "", data); got != tt.want {
				t.Errorf("checkTCPMatchers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckTCPMatchersOr(t *testing.T) {
	data := "SSH-2.0-OpenSSH_9.6 Ubuntu"

	tests := []struct {
		name     string
		matchers []Matcher
		want     bool
	}{
		{"one of two hits", []Matcher{tcpWord("Dropbear"), tcpWord("OpenSSH")}, true},
		{"none hit", []Matcher{tcpWord("Dropbear"), tcpWord("Debian")}, false},
		{"first hit short-circuits", []Matcher{tcpWord("OpenSSH"), tcpWord("Dropbear")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkTCPMatchers(tt.matchers, "or", data); got != tt.want {
				t.Errorf("checkTCPMatchers(or) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunTCPExtractors(t *testing.T) {
	data := "220 mail.example.com ESMTP Postfix 3.7.2"

	t.Run("regex group 1", func(t *testing.T) {
		ex := []Extractor{{Type: "regex", Name: "mta", Regex: []string{`ESMTP (\w+)`}, Group: 1}}
		if got := runTCPExtractors(ex, data)["mta"]; got != "Postfix" {
			t.Errorf("group 1 = %q, want Postfix", got)
		}
	})
	t.Run("group 0 full match", func(t *testing.T) {
		ex := []Extractor{{Type: "regex", Name: "ver", Regex: []string{`Postfix [\d.]+`}, Group: 0}}
		if got := runTCPExtractors(ex, data)["ver"]; got != "Postfix 3.7.2" {
			t.Errorf("group 0 = %q", got)
		}
	})
	t.Run("miss sets nothing", func(t *testing.T) {
		ex := []Extractor{{Type: "regex", Name: "x", Regex: []string{`nope(\d+)`}, Group: 1}}
		if _, ok := runTCPExtractors(ex, data)["x"]; ok {
			t.Error("a non-matching extractor set a value")
		}
	})
	t.Run("non-regex type skipped", func(t *testing.T) {
		ex := []Extractor{{Type: "kv", Name: "k"}}
		if _, ok := runTCPExtractors(ex, data)["k"]; ok {
			t.Error("a non-regex extractor produced a value")
		}
	})
	t.Run("uncompilable pattern skipped", func(t *testing.T) {
		// the bad pattern is skipped, the next one still matches.
		ex := []Extractor{{Type: "regex", Name: "x", Regex: []string{"[", `(ESMTP)`}, Group: 1}}
		if got := runTCPExtractors(ex, data)["x"]; got != "ESMTP" {
			t.Errorf("after skipping an invalid regex, got %q, want ESMTP", got)
		}
	})
	t.Run("no extractors is nil", func(t *testing.T) {
		if runTCPExtractors(nil, data) != nil {
			t.Error("want nil for no extractors")
		}
	})
}

func TestExecuteTCPModuleContextCancel(t *testing.T) {
	// a server that never replies: the read blocks until the context cancels and
	// the deadline-trip unblocks it.
	orig := newTCPConn
	newTCPConn = func(_ context.Context, _ string, _ time.Duration) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { server.Close() })
		return client, nil
	}
	t.Cleanup(func() { newTCPConn = orig })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	def := tcpDef(&TCPConfig{Port: 22, Matchers: []Matcher{tcpWord("x")}})
	start := time.Now()
	res, err := ExecuteTCPModule(ctx, "example.com", def, Options{Timeout: 5 * time.Second})
	// the cancel must trip the deadline and unblock the read promptly, well
	// before the 5s read budget would have expired on its own.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("returned after %v, want a prompt cancel (the deadline trip did not fire)", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("got %d findings on cancel, want 0", len(res.Findings))
	}
}

func TestExecuteTCPModuleDialError(t *testing.T) {
	orig := newTCPConn
	newTCPConn = func(context.Context, string, time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}
	t.Cleanup(func() { newTCPConn = orig })

	def := tcpDef(&TCPConfig{Port: 22, Matchers: []Matcher{tcpWord("x")}})
	if _, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected error when the dial fails")
	}
}

func TestExecuteTCPModuleWriteError(t *testing.T) {
	// a pipe whose far end is already closed fails the probe write.
	orig := newTCPConn
	newTCPConn = func(context.Context, string, time.Duration) (net.Conn, error) {
		client, server := net.Pipe()
		server.Close()
		return client, nil
	}
	t.Cleanup(func() { newTCPConn = orig })

	def := tcpDef(&TCPConfig{Port: 6379, Data: "PING\r\n", Matchers: []Matcher{tcpWord("x")}})
	if _, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{Timeout: time.Second}); err == nil {
		t.Fatal("expected error when the probe write fails")
	}
}

// TestExecuteTCPModuleRealListener drives the executor over the real net.Dialer
// against a live 127.0.0.1 listener (no newTCPConn stub), so the actual dial,
// probe write, and banner read path is exercised end to end. A matching banner
// yields a finding with the extracted version; a different banner yields none.
func TestExecuteTCPModuleRealListener(t *testing.T) {
	serve := func(banner string) (port int, stop func()) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 4096)
					_ = c.SetReadDeadline(time.Now().Add(time.Second))
					_, _ = c.Read(buf)
					_, _ = c.Write([]byte(banner))
				}(conn)
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close(); <-done }
	}

	t.Run("positive", func(t *testing.T) {
		port, stop := serve("+OK Redis 7.2.4 ready\r\n")
		defer stop()
		def := tcpDef(&TCPConfig{
			Port:     port,
			Data:     "INFO\r\n",
			Matchers: []Matcher{tcpWord("+OK", "Redis")},
			Extractors: []Extractor{
				{Type: "regex", Name: "version", Regex: []string{`Redis (\d+\.\d+\.\d+)`}, Group: 1},
			},
		})
		res, err := ExecuteTCPModule(context.Background(), "127.0.0.1", def, Options{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("ExecuteTCPModule: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(res.Findings))
		}
		if got := res.Findings[0].Extracted["version"]; got != "7.2.4" {
			t.Errorf("extracted version = %q, want 7.2.4", got)
		}
	})

	t.Run("negative", func(t *testing.T) {
		port, stop := serve("-NOAUTH Authentication required\r\n")
		defer stop()
		def := tcpDef(&TCPConfig{
			Port:     port,
			Data:     "INFO\r\n",
			Matchers: []Matcher{tcpWord("redis_version:")},
		})
		res, err := ExecuteTCPModule(context.Background(), "127.0.0.1", def, Options{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("ExecuteTCPModule: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings, want 0", len(res.Findings))
		}
	})
}

func TestExecuteTCPModuleNoConfig(t *testing.T) {
	def := &YAMLModule{ID: "x", Type: TypeTCP}
	if _, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected error when TCP config is nil")
	}
}

func TestExecuteTCPModuleNoHost(t *testing.T) {
	def := tcpDef(&TCPConfig{Port: 22, Matchers: []Matcher{tcpWord("x")}})
	if _, err := ExecuteTCPModule(context.Background(), "", def, Options{}); err == nil {
		t.Fatal("expected error when the target has no host")
	}
}

func TestReadTCPCapsAtLimit(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		chunk := make([]byte, 8192)
		for i := 0; i < 12; i++ { // 96 KiB offered, past the 64 KiB cap
			if _, err := server.Write(chunk); err != nil {
				return
			}
		}
	}()
	defer client.Close()

	got := readTCP(client, time.Second)
	if len(got) < tcpReadLimit {
		t.Fatalf("read %d bytes, want at least the %d cap", len(got), tcpReadLimit)
	}
	if len(got) > tcpReadLimit+4096 {
		t.Fatalf("read %d bytes, want no more than the cap plus one buffer", len(got))
	}
}

func TestTCPHost(t *testing.T) {
	cases := map[string]string{
		"example.com":                       "example.com",
		"https://example.com:8443/path?q=1": "example.com",
		"redis://user:pass@host.tld:6379":   "host.tld",
		"1.2.3.4:6379":                      "1.2.3.4",
		"[2606:4700::1111]:6379":            "2606:4700::1111",
		"/justpath":                         "/justpath",
		"":                                  "",
	}
	for in, want := range cases {
		if got := tcpHost(in); got != want {
			t.Errorf("tcpHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTCPAddress(t *testing.T) {
	t.Run("strips target port for the configured one", func(t *testing.T) {
		got, err := tcpAddress("example.com:80", 6379)
		if err != nil {
			t.Fatalf("tcpAddress: %v", err)
		}
		if got != "example.com:6379" {
			t.Errorf("address = %q, want example.com:6379", got)
		}
	})
	t.Run("empty host errors", func(t *testing.T) {
		if _, err := tcpAddress("", 6379); err == nil {
			t.Fatal("expected error for an empty host")
		}
	})
}

func TestValidateTCP(t *testing.T) {
	tests := []struct {
		name string
		cfg  *TCPConfig
		ok   bool
	}{
		{"valid port and matchers", &TCPConfig{Port: 6379, Matchers: []Matcher{{Type: "word"}, {Type: "regex"}, {Type: "size"}}}, true},
		{"no matchers is allowed", &TCPConfig{Port: 22}, true},
		{"port zero rejected", &TCPConfig{Port: 0}, false},
		{"port too high rejected", &TCPConfig{Port: 70000}, false},
		{"status matcher rejected", &TCPConfig{Port: 22, Matchers: []Matcher{{Type: "status"}}}, false},
		{"favicon matcher rejected", &TCPConfig{Port: 22, Matchers: []Matcher{{Type: "favicon"}}}, false},
		{"or condition allowed", &TCPConfig{Port: 6379, MatchersCondition: "or"}, true},
		{"and condition allowed", &TCPConfig{Port: 6379, MatchersCondition: "and"}, true},
		{"unknown condition rejected", &TCPConfig{Port: 6379, MatchersCondition: "xor"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTCP(tt.cfg)
			if (err == nil) != tt.ok {
				t.Errorf("validateTCP = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestParseTCPValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.yaml", "id: ok\ntype: tcp\ntcp:\n  port: 6379\n  matchers:\n    - type: word\n      words: [PONG]\n")
	if _, err := ParseYAMLModule(good); err != nil {
		t.Fatalf("valid tcp module rejected: %v", err)
	}

	badPort := write("badport.yaml", "id: bp\ntype: tcp\ntcp:\n  port: 0\n")
	if _, err := ParseYAMLModule(badPort); err == nil {
		t.Fatal("port zero accepted")
	}

	badMatcher := write("badmatcher.yaml", "id: bm\ntype: tcp\ntcp:\n  port: 22\n  matchers:\n    - type: status\n      status: [0]\n")
	if _, err := ParseYAMLModule(badMatcher); err == nil {
		t.Fatal("status matcher on tcp accepted")
	}

	badCond := write("badcond.yaml", "id: bc\ntype: tcp\ntcp:\n  port: 6379\n  matchers-condition: xor\n  matchers:\n    - type: word\n      words: [PONG]\n")
	if _, err := ParseYAMLModule(badCond); err == nil {
		t.Fatal("invalid matchers-condition on tcp accepted")
	}
}
