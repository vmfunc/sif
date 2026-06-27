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
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultTCPTimeout bounds the dial and the banner read when the caller passes
// no timeout, so a silent service cannot block the scan forever.
const defaultTCPTimeout = 10 * time.Second

// tcpReadLimit caps how many bytes a banner read keeps, guarding against a
// chatty or hostile service exhausting memory.
const tcpReadLimit = 64 * 1024

// newTCPConn dials the address over TCP. It is a package var so tests can supply
// a fake connection (e.g. a net.Pipe end) without touching the network.
var newTCPConn = func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// validateTCP rejects, at load time, a tcp config the executor cannot run: a
// port outside 1-65535, or a matcher type other than word, regex, or size
// (status and favicon are http only).
func validateTCP(cfg *TCPConfig) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("tcp port %d out of range (use 1-65535)", cfg.Port)
	}
	for i := range cfg.Matchers {
		switch cfg.Matchers[i].Type {
		case "word", "regex", "size":
		default:
			return fmt.Errorf("tcp matcher type %q is not supported (use word, regex, or size)", cfg.Matchers[i].Type)
		}
	}
	return nil
}

// ExecuteTCPModule connects to the target host on the configured port, sends the
// optional data probe, then applies the module's matchers and extractors to the
// bytes the service returns.
func ExecuteTCPModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	if def.TCP == nil {
		return nil, fmt.Errorf("no TCP configuration")
	}
	cfg := def.TCP
	result := &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: make([]Finding, 0),
	}

	addr, err := tcpAddress(target, cfg.Port)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTCPTimeout
	}

	conn, err := newTCPConn(ctx, addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %q: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// retryabledns-style context handling: TCP I/O does not take a context, so
	// trip the deadline when the caller cancels to unblock a pending read/write.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	if cfg.Data != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte(cfg.Data)); err != nil {
			return nil, fmt.Errorf("tcp write %q: %w", addr, err)
		}
	}

	data := readTCP(conn, timeout)
	if err := ctx.Err(); err != nil {
		return result, err
	}

	if !checkTCPMatchers(cfg.Matchers, data) {
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		Severity:  def.Info.Severity,
		Evidence:  truncateEvidence(data),
		Extracted: runTCPExtractors(cfg.Extractors, data),
	})
	return result, nil
}

// readTCP reads from the connection until tcpReadLimit bytes accumulate, the
// timeout elapses, or the service closes, and returns what arrived. The byte
// cap bounds memory to roughly the limit plus one buffer. A timeout or EOF ends
// the read normally: a silent or half-open service yields the bytes seen so far
// rather than an error, leaving the verdict to the matchers.
func readTCP(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var out []byte
	buf := make([]byte, 4096)
	for len(out) < tcpReadLimit {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(out)
}

// checkTCPMatchers evaluates all matchers against the response with AND logic.
func checkTCPMatchers(matchers []Matcher, data string) bool {
	if len(matchers) == 0 {
		return false
	}

	for i := range matchers {
		matched := checkTCPMatcher(&matchers[i], data)
		if matchers[i].Negative {
			matched = !matched
		}
		if !matched {
			return false // AND logic
		}
	}

	return true
}

// checkTCPMatcher evaluates a single matcher against the response bytes. TCP
// exposes one response stream, so there is no part selection; status and favicon
// are http only and validateTCP rejects them at load.
func checkTCPMatcher(m *Matcher, data string) bool {
	switch m.Type {
	case "word":
		return checkWords(data, m.Words, m.Condition)
	case "regex":
		return checkRegex(data, m.Regex, m.Condition)
	case "size":
		for _, n := range m.Size {
			if len(data) == n {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// runTCPExtractors pulls regex captures from the response bytes. A banner is raw
// text, so regex is the available extractor; other types are skipped.
func runTCPExtractors(extractors []Extractor, data string) map[string]string {
	if len(extractors) == 0 {
		return nil
	}

	result := make(map[string]string)
	for _, e := range extractors {
		if e.Type != "regex" {
			continue
		}
		for _, pattern := range e.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			matches := re.FindStringSubmatch(data)
			if len(matches) > e.Group {
				result[e.Name] = matches[e.Group]
				break
			}
		}
	}

	return result
}

// tcpAddress reduces target to its hostname and joins it with the configured
// port. Any scheme, port, path, or userinfo on the target is stripped: the
// module's port selects the service, not the target string.
func tcpAddress(target string, port int) (string, error) {
	host := tcpHost(target)
	if host == "" {
		return "", fmt.Errorf("tcp target %q has no host", target)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// tcpHost extracts the hostname from a target that may be a bare host, host:port,
// or a full URL.
func tcpHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return target
	}
	// url.Parse only populates Host when a scheme is present; add one for a bare
	// host or host:port so the same parse handles every form.
	parse := target
	if !strings.Contains(parse, "://") {
		parse = "//" + parse
	}
	if u, err := url.Parse(parse); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return target
}
