/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                 :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// an unset fingerprint must leave the TLS stack exactly as it was: no hook, h2
// still attempted. this is the "off by default" half of the contract.
func TestBuildTransportFingerprintOffByDefault(t *testing.T) {
	tr, err := buildTransport("", 8, "")
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}

	if tr.DialTLSContext != nil {
		t.Error("DialTLSContext set with no fingerprint; want the default TLS stack")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false with no fingerprint; want the default true")
	}
}

// a set fingerprint installs the uTLS dialer and, because net/http can no longer
// negotiate h2 through it, clears both h2 switches. this is the documented gap:
// if it ever stops being true the comment in buildTransport is a lie.
func TestBuildTransportFingerprintInstalled(t *testing.T) {
	tr, err := buildTransport("", 8, "chrome")
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}

	if tr.DialTLSContext == nil {
		t.Fatal("DialTLSContext nil with a fingerprint; the hello would stay go's")
	}
	if tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = true; h2 cannot be negotiated through DialTLSContext")
	}
	if len(tr.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto has %d entries; want it cleared so h2 is not advertised", len(tr.TLSNextProto))
	}
}

// an http proxy runs the origin handshake itself from tls.Config, where
// DialTLSContext is never consulted. fingerprinting there would be a silent
// no-op, so it must be refused at Configure time with a reason.
func TestBuildTransportFingerprintRefusesHTTPProxy(t *testing.T) {
	_, err := buildTransport("http://127.0.0.1:8080", 8, "chrome")
	if err == nil {
		t.Fatal("expected an error combining an http proxy with a fingerprint")
	}
	if !strings.Contains(err.Error(), "socks5") {
		t.Errorf("error %q does not name the working alternative", err)
	}

	// socks5 is the supported combination: the proxy dialer opens the tunnel and
	// the uTLS layer sits on top of it.
	tr, err := buildTransport("socks5://127.0.0.1:1080", 8, "chrome")
	if err != nil {
		t.Fatalf("socks5 + fingerprint should be allowed: %v", err)
	}
	if tr.DialTLSContext == nil {
		t.Error("DialTLSContext nil through socks5")
	}
}

func TestClientHelloID(t *testing.T) {
	for _, name := range TLSFingerprintNames {
		if _, err := clientHelloID(name); err != nil {
			t.Errorf("clientHelloID(%q): %v", name, err)
		}
	}
	if _, err := clientHelloID("chrome"); err != nil {
		t.Errorf("matching should be case-insensitive: %v", err)
	}
	if _, err := clientHelloID("netscape"); err == nil {
		t.Error("unknown profile accepted")
	}
}

// Configure must fail before installing anything: a bad profile name should not
// leave the package pointing at a half-built transport.
func TestConfigureRejectsUnknownFingerprint(t *testing.T) {
	mu.Lock()
	before := configured
	mu.Unlock()

	if err := Configure(Options{Threads: 4, Fingerprint: "netscape"}); err == nil {
		t.Fatal("Configure accepted an unknown fingerprint")
	}

	mu.RLock()
	after := configured
	mu.RUnlock()
	if after != before {
		t.Error("configured transport changed despite the error")
	}
}

// the real proof: a TLS server, a request through the fingerprinted transport,
// and a completed uTLS handshake on the other end. If uTLS cannot drive the
// connection this fails rather than erroring somewhere quiet.
func TestFingerprintHandshakeReachesServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tr, err := buildTransport("", 4, "chrome")
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	// the test server's certificate is self-signed; trust is not what this test is
	// about, so skip verification in place - the dialer holds this pointer.
	tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // self-signed test server

	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request through fingerprinted transport: %v", err)
	}
	defer DrainClose(resp)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	// http/1.1 is the documented consequence of taking over the handshake.
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("proto = %s, want HTTP/1.1", resp.Proto)
	}
}
