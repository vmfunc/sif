package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runVaultwardenModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/vaultwarden-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse vaultwarden module: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute vaultwarden module: %v", err)
	}
	return res
}

func vaultwardenExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestVaultwardenVersionExposureModule(t *testing.T) {
	// shape taken directly from dani-garcia/vaultwarden src/api/core/mod.rs fn config()
	vaultwardenBody := `{"version":"2025.12.0","gitHash":"a1b2c3d",` +
		`"server":{"name":"Vaultwarden","url":"https://github.com/dani-garcia/vaultwarden"},` +
		`"settings":{"disableUserRegistration":false},` +
		`"environment":{"vault":"https://vault.example.com"}}`

	t.Run("an exposed vaultwarden config endpoint is flagged and versioned", func(t *testing.T) {
		res := runVaultwardenModule(t, 200, vaultwardenBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a vaultwarden finding")
		}
		if v := vaultwardenExtract(res, "vaultwarden_version"); v != "2025.12.0" {
			t.Errorf("vaultwarden_version=%q, want 2025.12.0", v)
		}
	})

	t.Run("an official bitwarden server config is not flagged as vaultwarden", func(t *testing.T) {
		// the official bitwarden server config endpoint shares the same json
		// shape (clients are built against both) but reports its own server name
		body := `{"version":"2025.12.0","gitHash":"deadbee",` +
			`"server":{"name":"Bitwarden","url":"https://github.com/bitwarden/server"},` +
			`"settings":{"disableUserRegistration":true}}`
		if res := runVaultwardenModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("an official bitwarden config should not match vaultwarden, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic json with a version field is not vaultwarden", func(t *testing.T) {
		body := `{"version":"1.0.0","server":{"name":"SomeOtherApp"}}`
		if res := runVaultwardenModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic json should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runVaultwardenModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
