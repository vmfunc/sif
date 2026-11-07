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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// TLSFingerprintNames lists the ClientHello profiles -fingerprint accepts, for
// help text and for the error an unknown value produces.
var TLSFingerprintNames = []string{"chrome", "firefox", "safari", "edge", "ios", "android"}

// clientHelloID resolves a -fingerprint value to a uTLS profile. An empty name
// never reaches here: callers check for "" first, because that means "leave the
// transport alone", not "unknown profile".
func clientHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf(
			"unknown tls fingerprint %q (want one of: %s)", name, strings.Join(TLSFingerprintNames, ", "))
	}
}

// dialFunc matches the shape of http.Transport.DialContext and
// DialTLSContext, so one function can serve either slot.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// newTLSDialer wraps a plain dialer: base opens the TCP connection (and so may
// be a proxy dialer), then uTLS drives the handshake with the given profile.
//
// The handshake has to happen here, before net/http sees the conn. uTLS works
// on net.Conn and cannot ride in through tls.Config, and http.Transport offers
// no hook between "conn open" and "hello sent" other than DialTLSContext.
//
// The cost is ALPN: net/http only negotiates h2 when it drives the handshake
// itself, so this path is HTTP/1.1 only. Callers are told so in buildTransport.
func newTLSDialer(base dialFunc, id utls.ClientHelloID, baseCfg *tls.Config) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := base(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		serverName, _, err := net.SplitHostPort(addr)
		if err != nil {
			// addr comes from the transport, so this is a programming error
			// rather than hostile input; close what we opened rather than leak.
			_ = raw.Close()
			return nil, fmt.Errorf("split dial addr %q: %w", addr, err)
		}

		// carry over whatever the caller already configured (roots, min version,
		// insecure skip) so fingerprinting changes the hello, not the trust
		// policy. only ServerName and ALPN are ours to set.
		var cfg *utls.Config
		if baseCfg != nil {
			cfg = &utls.Config{
				RootCAs:            baseCfg.RootCAs,
				InsecureSkipVerify: baseCfg.InsecureSkipVerify, //nolint:gosec // mirrors the caller's decision
				MinVersion:         baseCfg.MinVersion,
				MaxVersion:         baseCfg.MaxVersion,
				CipherSuites:       baseCfg.CipherSuites,
			}
		} else {
			cfg = &utls.Config{}
		}
		cfg.ServerName = serverName
		// Advertise http/1.1 only, matching the transport. Advertising h2 here
		// without then sending h2 SETTINGS frames would make the handshake
		// claim something the connection cannot do.
		cfg.NextProtos = []string{"http/1.1"}
		conn := utls.UClient(raw, cfg, id)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls handshake with %q as %s: %w", serverName, id.Client, err)
		}

		return conn, nil
	}
}
