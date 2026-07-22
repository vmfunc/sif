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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeLeaf builds a self-signed leaf cert with the given SANs and validity so
// the posture flags can be exercised without a live tls handshake.
func makeLeaf(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return leaf
}

func TestBuildTLSCertResult(t *testing.T) {
	now := time.Now()
	leaf := makeLeaf(t, "example.com",
		[]string{"example.com", "api.example.com", "*.cdn.example.com"},
		now.Add(-24*time.Hour), now.Add(365*24*time.Hour))

	res := buildTLSCertResult(leaf, []*x509.Certificate{leaf}, "example.com")

	if !res.SelfSigned {
		t.Error("self-signed leaf not flagged as self-signed")
	}
	if !res.Wildcard {
		t.Error("*.cdn.example.com SAN not flagged as wildcard")
	}
	if res.Expired || res.ExpiringSoon {
		t.Errorf("year-long cert flagged expired=%v soon=%v", res.Expired, res.ExpiringSoon)
	}
	// the target host itself must not appear as a "new" subdomain; the wildcard
	// SAN is normalized to its base (the *. prefix is stripped) and Wildcard is
	// flagged separately.
	want := map[string]bool{"api.example.com": true, "cdn.example.com": true}
	if len(res.NewSubdomains) != len(want) {
		t.Fatalf("new subdomains = %v, want the two non-target SANs", res.NewSubdomains)
	}
	for _, s := range res.NewSubdomains {
		if !want[s] {
			t.Errorf("unexpected new subdomain %q", s)
		}
	}
}

func TestBuildTLSCertResultExpiry(t *testing.T) {
	now := time.Now()

	expired := buildTLSCertResult(
		makeLeaf(t, "old.example.com", []string{"old.example.com"}, now.Add(-48*time.Hour), now.Add(-1*time.Hour)),
		nil, "old.example.com")
	if !expired.Expired || expired.ExpiringSoon {
		t.Errorf("past-NotAfter cert: expired=%v soon=%v, want expired", expired.Expired, expired.ExpiringSoon)
	}

	soon := buildTLSCertResult(
		makeLeaf(t, "soon.example.com", []string{"soon.example.com"}, now.Add(-1*time.Hour), now.Add(72*time.Hour)),
		nil, "soon.example.com")
	if soon.Expired || !soon.ExpiringSoon {
		t.Errorf("cert inside the soon window: expired=%v soon=%v, want soon", soon.Expired, soon.ExpiringSoon)
	}
}
