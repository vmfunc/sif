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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultSSLTimeout bounds the dial plus handshake when the caller passes no
// timeout, so a silent host cannot block the scan forever.
const defaultSSLTimeout = 10 * time.Second

// newSSLRawConn dials the address over tcp for the tls handshake to run on. It
// is a package var so tests can supply an in-memory pipe without touching the
// network.
var newSSLRawConn = func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// validateSSL rejects, at load time, an ssl config the executor cannot run: a
// port outside 1-65535, an unknown matchers-condition, a matcher type other
// than word, regex, size, range, or dsl (status and favicon are http only),
// or a range matcher with source=status (status is http only; ssl has none).
func validateSSL(cfg *SSLConfig) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("ssl port %d out of range (use 1-65535)", cfg.Port)
	}
	if err := validateMatchersCondition(cfg.MatchersCondition); err != nil {
		return err
	}
	for i := range cfg.Matchers {
		switch cfg.Matchers[i].Type {
		case "word", "regex", "size", "dsl":
		case "range":
			if strings.EqualFold(cfg.Matchers[i].Source, "status") {
				return fmt.Errorf("ssl range matcher source %q is not supported (status is http only; use size)", cfg.Matchers[i].Source)
			}
		default:
			return fmt.Errorf("ssl matcher type %q is not supported (use word, regex, size, range, or dsl)", cfg.Matchers[i].Type)
		}
	}
	return nil
}

// ExecuteSSLModule handshakes with InsecureSkipVerify and a TLS 1.0 floor, then
// matches against a summary of the peer certificate: the module inspects a
// possibly self-signed or expired cert rather than trusting the connection, so
// verification must not block the handshake before sif sees it.
func ExecuteSSLModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	if def.SSL == nil {
		return nil, fmt.Errorf("no SSL configuration")
	}
	cfg := def.SSL
	result := &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: make([]Finding, 0),
	}

	host := tcpHost(target)
	if host == "" {
		return nil, fmt.Errorf("ssl target %q has no host", target)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(cfg.Port))

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultSSLTimeout
	}

	// One deadline covers the dial and the handshake: HandshakeContext honors
	// ctx cancellation directly, so there is no separate watchdog goroutine
	// needed the way tcp.go needs one for its context-less net.Conn read.
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := newSSLRawConn(hctx, addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("ssl dial %q: %w", addr, err)
	}
	defer func() { _ = raw.Close() }()

	serverName := cfg.ServerName
	if serverName == "" {
		serverName = host
	}

	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner inspects the cert itself; it does not trust the connection
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	})
	defer func() { _ = conn.Close() }()

	if err := conn.HandshakeContext(hctx); err != nil {
		return nil, fmt.Errorf("ssl handshake %q: %w", addr, err)
	}

	state := conn.ConnectionState()
	info, ok := newSSLCertInfo(&state)
	if !ok {
		// Handshake succeeded but the peer offered no certificate: nothing to
		// match against, not an error.
		return result, nil
	}

	text := sslEvidenceText(&info)
	extracted := runSSLExtractors(cfg.Extractors, text)

	mc := &MatchContext{
		Body:      text,
		URL:       addr,
		Extracted: extracted,
		Extra:     sslDSLVars(&info),
	}

	if !checkSSLMatchers(cfg.Matchers, cfg.MatchersCondition, text, mc) {
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		Severity:  def.Info.Severity,
		Evidence:  truncateEvidence(text),
		Extracted: extracted,
	})
	return result, nil
}

// sslCertInfo holds the matcher/extractor-relevant facts pulled out of a
// completed handshake: the negotiated parameters plus the leaf certificate.
type sslCertInfo struct {
	versionName string
	cipherName  string
	cn          string
	san         []string
	notAfter    time.Time
	selfSigned  bool
	expired     bool
}

// newSSLCertInfo derives sslCertInfo from a completed handshake's state. ok is
// false when the peer presented no certificate, which a plain tls-psk or
// anonymous cipher suite can leave empty.
func newSSLCertInfo(state *tls.ConnectionState) (sslCertInfo, bool) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return sslCertInfo{}, false
	}
	leaf := state.PeerCertificates[0]

	san := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	san = append(san, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		san = append(san, ip.String())
	}

	return sslCertInfo{
		versionName: tls.VersionName(state.Version),
		cipherName:  tls.CipherSuiteName(state.CipherSuite),
		cn:          leaf.Subject.CommonName,
		san:         san,
		notAfter:    leaf.NotAfter,
		selfSigned:  isSelfSignedCert(leaf),
		expired:     time.Now().After(leaf.NotAfter),
	}, true
}

// isSelfSignedCert reports whether cert's own public key verifies its own
// signature and its issuer equals its subject. Deliberately uses
// CheckSignature (bare cryptographic verification) rather than
// CheckSignatureFrom(cert): the latter also enforces CA basic-constraints and
// key-usage, which a typical hand-rolled self-signed leaf certificate (the
// kind this check exists to flag) usually does not set, and would then read
// as not self-signed.
func isSelfSignedCert(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// sslDSLVars is the ssl module's contribution to MatchContext.Extra: the
// lowercase vars a dsl matcher/extractor references, per docs/modules.md.
// expired and self_signed are real bools (not strings) so a bare `expired` in
// a dsl expression works the way a bare nuclei bool var does.
func sslDSLVars(info *sslCertInfo) map[string]interface{} {
	return map[string]interface{}{
		"tls_version": info.versionName,
		"cipher":      info.cipherName,
		"cn":          info.cn,
		"san":         strings.Join(info.san, ","),
		"not_after":   info.notAfter.UTC().Format(time.RFC3339),
		"self_signed": info.selfSigned,
		"expired":     info.expired,
	}
}

// sslEvidenceText renders info as the "banner" ssl's word/regex/size/range
// matchers and extractors run against, and what a finding's Evidence holds.
func sslEvidenceText(info *sslCertInfo) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "tls_version: %s\n", info.versionName)
	fmt.Fprintf(&sb, "cipher: %s\n", info.cipherName)
	fmt.Fprintf(&sb, "cn: %s\n", info.cn)
	fmt.Fprintf(&sb, "san: %s\n", strings.Join(info.san, ","))
	fmt.Fprintf(&sb, "not_after: %s\n", info.notAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "self_signed: %t\n", info.selfSigned)
	fmt.Fprintf(&sb, "expired: %t\n", info.expired)
	return sb.String()
}

// checkSSLMatchers evaluates all matchers against the response, combining
// them with AND (default) or OR per the matchers-condition.
func checkSSLMatchers(matchers []Matcher, condition string, text string, mc *MatchContext) bool {
	if len(matchers) == 0 {
		return false
	}

	or := strings.EqualFold(condition, "or")
	for i := range matchers {
		matched := checkSSLMatcher(&matchers[i], text, mc)
		if matchers[i].Negative {
			matched = !matched
		}
		if or && matched {
			return true
		}
		if !or && !matched {
			return false
		}
	}

	return !or
}

// checkSSLMatcher evaluates a single matcher. ssl exposes one summary text, so
// there is no part selection for word/regex/size/range; dsl reads the typed
// vars from mc.Extra via evalDSL, shared with the http module.
func checkSSLMatcher(m *Matcher, text string, mc *MatchContext) bool {
	switch m.Type {
	case "word":
		return checkWords(text, m.Words, m.Condition, m.CaseInsensitive)
	case "regex":
		return checkRegex(text, m.Regex, m.Condition)
	case "size":
		for _, n := range m.Size {
			if len(text) == n {
				return true
			}
		}
		return false
	case "range":
		return inRange(len(text), m.Min, m.Max)
	case "dsl":
		return evalDSL(m, mc)
	default:
		return false
	}
}

// runSSLExtractors pulls regex captures from the summary text. It is text, so
// regex is the available extractor; other types are skipped.
func runSSLExtractors(extractors []Extractor, text string) map[string]string {
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
			matches := re.FindStringSubmatch(text)
			if len(matches) > e.Group {
				result[e.Name] = matches[e.Group]
				break
			}
		}
	}

	return result
}
