/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

/*

   BSD 3-Clause License
   (c) 2022-2026 vmfunc, xyzeva & contributors

*/

package builtin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
	// import the detectors package for its init() so the CDN detector pool
	// is registered when the module runs.
	_ "github.com/vmfunc/sif/internal/scan/frameworks/detectors"
)

func TestCDNModule_DetectsCloudflare(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-RAY", "7d1f4a2b3c4d5e6f-LAX")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body>Hello</body></html>`))
	}))
	defer server.Close()

	m := &CDNModule{}
	result, err := m.Execute(context.Background(), server.URL, modules.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected a result, got nil")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if got := result.Findings[0].Extracted["cdn"]; got != "Cloudflare" {
		t.Errorf("expected cdn 'Cloudflare', got %q", got)
	}
	if sev := result.Findings[0].Severity; sev != "info" {
		t.Errorf("expected severity 'info' (a cdn is a pure fingerprint), got %q", sev)
	}
}

func TestCDNModule_NoCDN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// generic origin headers, no edge-injected vendor marker.
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body>Plain origin</body></html>`))
	}))
	defer server.Close()

	m := &CDNModule{}
	result, err := m.Execute(context.Background(), server.URL, modules.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected a result, got nil")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings on a plain origin, got %d (%+v)", len(result.Findings), result.Findings)
	}
}
