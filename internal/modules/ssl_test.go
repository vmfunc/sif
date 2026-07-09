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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSignedTestCert builds a self-signed leaf certificate (issuer == subject,
// signed by its own key) valid over [notBefore, notAfter], for exercising the
// expired and self-signed dsl vars.
func selfSignedTestCert(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              sans,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// caSignedTestCert builds a two-certificate chain (CA + leaf) where the leaf's
// issuer differs from its subject and the leaf itself carries no CA key usage,
// for exercising the not-self-signed case.
func caSignedTestCert(t *testing.T, cn string, sans []string) tls.Certificate {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              sans,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafPriv}
}

// withFakeSSL installs a fake dialer that hands the executor one net.Pipe end
// and runs a tls server handshake with serverCfg on the other, so
// ExecuteSSLModule performs a real tls handshake without touching the network.
// After the handshake, the server side keeps reading and discarding: the
// client's deferred conn.Close() sends a close_notify alert that blocks
// (crypto/tls gives it a hard 5s write deadline) until something reads it, and
// nothing else in this fake server ever will.
func withFakeSSL(t *testing.T, serverCfg *tls.Config) {
	t.Helper()
	orig := newSSLRawConn
	newSSLRawConn = func(_ context.Context, _ string, _ time.Duration) (net.Conn, error) {
		clientEnd, serverEnd := net.Pipe()
		go func() {
			srv := tls.Server(serverEnd, serverCfg)
			if err := srv.Handshake(); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, srv)
		}()
		return clientEnd, nil
	}
	t.Cleanup(func() { newSSLRawConn = orig })
}

func sslDef(cfg *SSLConfig) *YAMLModule {
	return &YAMLModule{ID: "ssl-test", Type: TypeSSL, Info: YAMLModuleInfo{Severity: "info"}, SSL: cfg}
}

func sslDSLMatcher(expr string) Matcher {
	return Matcher{Type: "dsl", DSL: []string{expr}}
}

func TestValidateSSL(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SSLConfig
		wantErr bool
	}{
		{"valid", &SSLConfig{Port: 443, Matchers: []Matcher{sslDSLMatcher("expired")}}, false},
		{"port zero", &SSLConfig{Port: 0}, true},
		{"port too high", &SSLConfig{Port: 70000}, true},
		{"status matcher rejected", &SSLConfig{Port: 443, Matchers: []Matcher{{Type: "status", Status: []int{200}}}}, true},
		{"favicon matcher rejected", &SSLConfig{Port: 443, Matchers: []Matcher{{Type: "favicon", Hash: []int64{1}}}}, true},
		{"range source status rejected", &SSLConfig{Port: 443, Matchers: []Matcher{{Type: "range", Source: "status", Min: intPtr(1)}}}, true},
		{"bad matchers-condition", &SSLConfig{Port: 443, MatchersCondition: "xor"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSL(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSSL() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func intPtr(v int) *int { return &v }

func TestExecuteSSLModule_HealthyCert(t *testing.T) {
	cert := selfSignedTestCert(t, "good.example.com", []string{"good.example.com", "alt.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	withFakeSSL(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	def := sslDef(&SSLConfig{
		Port: 443,
		Matchers: []Matcher{
			sslDSLMatcher(`!expired && tls_version == "TLS 1.3"`),
		},
		Extractors: []Extractor{
			{Type: "regex", Name: "cert_cn", Regex: []string{`cn: (\S+)`}, Group: 1},
		},
	})

	res, err := ExecuteSSLModule(context.Background(), "good.example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteSSLModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Extracted["cert_cn"] != "good.example.com" {
		t.Errorf("cert_cn = %q, want good.example.com", f.Extracted["cert_cn"])
	}
	if !strings.Contains(f.Evidence, "self_signed: true") {
		t.Errorf("evidence missing self_signed: true: %q", f.Evidence)
	}
}

func TestExecuteSSLModule_ExpiredCert(t *testing.T) {
	cert := selfSignedTestCert(t, "expired.example.com", []string{"expired.example.com"},
		time.Now().Add(-365*24*time.Hour), time.Now().Add(-24*time.Hour))
	withFakeSSL(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	def := sslDef(&SSLConfig{
		Port:     443,
		Matchers: []Matcher{sslDSLMatcher("expired")},
	})

	res, err := ExecuteSSLModule(context.Background(), "expired.example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteSSLModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for expired cert, got %d", len(res.Findings))
	}
}

func TestExecuteSSLModule_HealthyCertDoesNotFlagExpired(t *testing.T) {
	cert := selfSignedTestCert(t, "good.example.com", []string{"good.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	withFakeSSL(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	def := sslDef(&SSLConfig{
		Port:     443,
		Matchers: []Matcher{sslDSLMatcher("expired")},
	})

	res, err := ExecuteSSLModule(context.Background(), "good.example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteSSLModule: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings for a healthy cert, got %d", len(res.Findings))
	}
}

func TestExecuteSSLModule_WeakTLSVersion(t *testing.T) {
	cert := selfSignedTestCert(t, "legacy.example.com", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	withFakeSSL(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
	})

	def := sslDef(&SSLConfig{
		Port:     443,
		Matchers: []Matcher{sslDSLMatcher(`tls_version == "TLS 1.0" || tls_version == "TLS 1.1"`)},
	})

	res, err := ExecuteSSLModule(context.Background(), "legacy.example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteSSLModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding for a legacy tls version, got %d", len(res.Findings))
	}
}

func TestExecuteSSLModule_CASignedCertIsNotSelfSigned(t *testing.T) {
	cert := caSignedTestCert(t, "leaf.example.com", []string{"leaf.example.com"})
	withFakeSSL(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	def := sslDef(&SSLConfig{
		Port:     443,
		Matchers: []Matcher{sslDSLMatcher("self_signed")},
	})

	res, err := ExecuteSSLModule(context.Background(), "leaf.example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteSSLModule: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings for a ca-signed leaf, got %d", len(res.Findings))
	}
}

func TestExecuteSSLModule_SANExtraction(t *testing.T) {
	cert := selfSignedTestCert(t, "primary.example.com", []string{"primary.example.com", "secondary.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	withFakeSSL(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	def := sslDef(&SSLConfig{
		Port:     443,
		Matchers: []Matcher{sslDSLMatcher(`contains(san, "secondary.example.com")`)},
	})

	res, err := ExecuteSSLModule(context.Background(), "primary.example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteSSLModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding matching a SAN entry, got %d", len(res.Findings))
	}
}

// TestExecuteSSLModule_DialRefused proves a closed port fails closed with an
// error instead of panicking or hanging.
func TestExecuteSSLModule_DialRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	def := sslDef(&SSLConfig{Port: port, Matchers: []Matcher{sslDSLMatcher("expired")}})

	_, err = ExecuteSSLModule(context.Background(), "127.0.0.1", def, Options{Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("expected a dial error against a closed port, got nil")
	}
}

// TestExecuteSSLModule_HandshakeFailurePlainTCP proves a non-tls service on
// the port (plain http here) fails closed at the handshake instead of
// panicking or hanging.
func TestExecuteSSLModule_HandshakeFailurePlainTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	def := sslDef(&SSLConfig{Port: port, Matchers: []Matcher{sslDSLMatcher("expired")}})

	_, err = ExecuteSSLModule(context.Background(), "127.0.0.1", def, Options{Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("expected a handshake error against a plain-tcp service, got nil")
	}
}

// TestExecuteSSLModule_ContextCanceled proves an already-canceled context
// fails fast rather than blocking for the full timeout.
func TestExecuteSSLModule_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	def := sslDef(&SSLConfig{Port: 1, Matchers: []Matcher{sslDSLMatcher("expired")}})

	start := time.Now()
	_, err := ExecuteSSLModule(ctx, "127.0.0.1", def, Options{Timeout: 5 * time.Second})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error from a canceled context, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ExecuteSSLModule took %v against a canceled context, want a fast failure", elapsed)
	}
}

func TestExecuteSSLModule_NoConfig(t *testing.T) {
	def := &YAMLModule{ID: "ssl-test", Type: TypeSSL}
	if _, err := ExecuteSSLModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected an error when SSL config is nil")
	}
}

func TestParseYAMLModuleBytes_SSL(t *testing.T) {
	data := []byte(`
id: tls-weak-version
info:
  name: Weak TLS Version
  severity: medium
type: ssl
ssl:
  port: 443
  matchers:
    - type: dsl
      dsl:
        - 'tls_version == "TLS 1.0" || tls_version == "TLS 1.1"'
  extractors:
    - type: regex
      name: cn
      regex:
        - "cn: (\\S+)"
      group: 1
`)
	mod, err := ParseYAMLModuleBytes(data)
	if err != nil {
		t.Fatalf("ParseYAMLModuleBytes: %v", err)
	}
	if mod.Type != TypeSSL {
		t.Fatalf("Type = %q, want ssl", mod.Type)
	}
	if mod.SSL == nil || mod.SSL.Port != 443 {
		t.Fatalf("SSL config not parsed: %+v", mod.SSL)
	}
}

func TestParseYAMLModuleBytes_SSLMissingBlock(t *testing.T) {
	data := []byte(`
id: bad-ssl
info:
  severity: info
type: ssl
`)
	if _, err := ParseYAMLModuleBytes(data); err == nil {
		t.Fatal("expected an error for an ssl module with no ssl block")
	}
}

// TestCheckSSLMatcher covers every matcher type ssl accepts against one
// summary text, plus the negative and or-condition paths. the per-type switch
// was reachable only through a live handshake before this, so a type wired to
// the wrong helper (or a new type silently defaulting to false) would not have
// failed a test.
func TestCheckSSLMatcher(t *testing.T) {
	const text = "tls_version: TLS 1.3\ncn: example.com\nself_signed: true\n"
	mc := &MatchContext{Body: text, URL: "https://example.com:443", Extra: map[string]interface{}{
		"self_signed": true,
		"expired":     false,
		"cn":          "example.com",
	}}

	size := len(text)
	minSize, maxSize := size-1, size+1
	tooSmall := size - 10

	tests := []struct {
		name   string
		m      Matcher
		expect bool
	}{
		{"word hit", Matcher{Type: "word", Words: []string{"cn: example.com"}}, true},
		{"word miss", Matcher{Type: "word", Words: []string{"cn: other.com"}}, false},
		{"word case-insensitive", Matcher{Type: "word", Words: []string{"CN: EXAMPLE.COM"}, CaseInsensitive: true}, true},
		{"regex hit", Matcher{Type: "regex", Regex: []string{`tls_version: TLS 1\.\d`}}, true},
		{"regex miss", Matcher{Type: "regex", Regex: []string{`tls_version: SSL`}}, false},
		{"size hit", Matcher{Type: "size", Size: []int{size}}, true},
		{"size miss", Matcher{Type: "size", Size: []int{size + 1}}, false},
		{"range hit", Matcher{Type: "range", Min: &minSize, Max: &maxSize}, true},
		{"range miss", Matcher{Type: "range", Max: &tooSmall}, false},
		{"dsl typed bool", Matcher{Type: "dsl", DSL: []string{"self_signed && !expired"}}, true},
		{"dsl miss", Matcher{Type: "dsl", DSL: []string{"expired"}}, false},
		{"unknown type fails closed", Matcher{Type: "favicon", Hash: []int64{1}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkSSLMatcher(&tt.m, text, mc); got != tt.expect {
				t.Errorf("checkSSLMatcher(%s) = %v, want %v", tt.m.Type, got, tt.expect)
			}
		})
	}

	// negative inverts, and "or" fires on the second matcher alone.
	neg := []Matcher{{Type: "word", Words: []string{"absent"}, Negative: true}}
	if !checkSSLMatchers(neg, "", text, mc) {
		t.Error("negative word matcher on absent text should match")
	}
	pair := []Matcher{{Type: "word", Words: []string{"absent"}}, {Type: "word", Words: []string{"cn: example.com"}}}
	if !checkSSLMatchers(pair, "or", text, mc) {
		t.Error("or condition should fire on the second matcher")
	}
	if checkSSLMatchers(pair, "", text, mc) {
		t.Error("default and condition should not fire when the first matcher misses")
	}
	if checkSSLMatchers(nil, "", text, mc) {
		t.Error("no matchers should not match")
	}
}
