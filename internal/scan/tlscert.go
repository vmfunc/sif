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

package scan

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// tlsCertExpirySoonWindow flags a leaf certificate as "expiring soon" inside
// this window, mirroring the threshold nmap's ssl-cert and testssl.sh use.
const tlsCertExpirySoonWindow = 30 * 24 * time.Hour

// TLSCertResult holds what the target's leaf certificate reveals: extra
// hostnames from the SAN list, issuer/validity metadata, and posture flags a
// human would want surfaced without reading the cert by hand.
type TLSCertResult struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	SANs          []string `json:"sans"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	SerialNumber  string   `json:"serial_number"`
	SelfSigned    bool     `json:"self_signed"`
	Expired       bool     `json:"expired"`
	ExpiringSoon  bool     `json:"expiring_soon"`
	Wildcard      bool     `json:"wildcard"`
	NewSubdomains []string `json:"new_subdomains"` // SANs not already known to be the target host
	ChainLength   int      `json:"chain_length"`
}

func (r *TLSCertResult) ResultType() string { return "tlscert" }

var _ ScanResult = (*TLSCertResult)(nil)

// tlsDial is a var so tests can substitute a fake dialer without touching the
// network.
var tlsDial = func(addr string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	// InsecureSkipVerify is deliberate: this module mines whatever certificate
	// the target presents, self-signed or expired included, rather than only
	// certs that pass validation like the main http client requires.
	return tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // recon target, not a trust decision
}

// TLSCert connects to the target on the given port (443 when unset) and mines
// its leaf certificate: SANs become candidate subdomains, issuer/validity feed
// posture flags (self-signed, expired, expiring soon). Unlike Passive's crt.sh
// and certspotter feeds this is an active probe against the target itself, so
// it catches certs that were never logged to a public CT log (short-lived
// certs not yet propagated, internal CAs) at the cost of touching the target.
func TLSCert(targetURL string, port int, timeout time.Duration, logdir string) (*TLSCertResult, error) {
	log := output.Module("TLSCERT")
	log.Start()

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target url %q: %w", targetURL, err)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("target url %q has no host", targetURL)
	}
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	sanitizedURL := stripScheme(targetURL)
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "tls certificate recon"); err != nil {
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create tlscert log: %w", err)
		}
	}

	conn, err := tlsDial(addr, timeout)
	if err != nil {
		log.Warn("tls dial %s failed: %v", addr, err)
		return nil, fmt.Errorf("tls dial %q: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("tls handshake with %q presented no certificates", addr)
	}
	leaf := state.PeerCertificates[0]

	result := buildTLSCertResult(leaf, state.PeerCertificates, host)

	logTLSCertResult(log, sanitizedURL, logdir, result)

	log.Complete(len(result.SANs), "san entries")
	return result, nil
}

// buildTLSCertResult turns a parsed leaf certificate into the recon-facing
// result: SAN-derived hostnames, issuer/validity, and posture flags.
func buildTLSCertResult(leaf *x509.Certificate, chain []*x509.Certificate, targetHost string) *TLSCertResult {
	now := time.Now()

	sanSet := make(map[string]struct{}, len(leaf.DNSNames))
	for _, name := range leaf.DNSNames {
		sanSet[normalizeHost(name)] = struct{}{}
	}
	sans := sortedKeys(sanSet)

	var newSubs []string
	for _, san := range sans {
		if san != normalizeHost(targetHost) {
			newSubs = append(newSubs, san)
		}
	}

	wildcard := false
	for _, name := range leaf.DNSNames {
		if len(name) > 1 && name[0] == '*' {
			wildcard = true
			break
		}
	}

	// self-signed: issuer == subject (raw DER, not the human-readable string)
	// and the cert's own signature verifies against its own TBS bytes.
	// CheckSignatureFrom(leaf) is the wrong tool here - it additionally
	// requires CA key-usage/basic-constraints bits a self-signed leaf usually
	// doesn't set, so it false-negatives on exactly the certs this flag exists
	// to catch.
	selfSigned := bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil

	return &TLSCertResult{
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		SANs:          sans,
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		SerialNumber:  leaf.SerialNumber.String(),
		SelfSigned:    selfSigned,
		Expired:       now.After(leaf.NotAfter),
		ExpiringSoon:  !now.After(leaf.NotAfter) && leaf.NotAfter.Sub(now) < tlsCertExpirySoonWindow,
		Wildcard:      wildcard,
		NewSubdomains: newSubs,
		ChainLength:   len(chain),
	}
}

func logTLSCertResult(log *output.ModuleLogger, sanitizedURL, logdir string, result *TLSCertResult) {
	log.Info("subject: %s", result.Subject)
	log.Info("issuer: %s", result.Issuer)
	if result.SelfSigned {
		log.Warn("certificate is self-signed")
	}
	if result.Expired {
		log.Warn("certificate expired %s", result.NotAfter)
	} else if result.ExpiringSoon {
		log.Warn("certificate expires soon: %s", result.NotAfter)
	}
	for _, san := range result.NewSubdomains {
		log.Success("san: %s", output.Highlight.Render(san))
	}

	if logdir == "" {
		return
	}

	sb := fmt.Sprintf("Subject: %s\nIssuer: %s\nNotBefore: %s\nNotAfter: %s\nSelfSigned: %v\nExpired: %v\nWildcard: %v\n",
		result.Subject, result.Issuer, result.NotBefore, result.NotAfter, result.SelfSigned, result.Expired, result.Wildcard)
	if len(result.SANs) > 0 {
		sb += "\nSANs:\n"
		for _, san := range result.SANs {
			sb += "  " + san + "\n"
		}
	}
	_ = logger.Write(sanitizedURL, logdir, sb)
}
