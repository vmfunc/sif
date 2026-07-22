package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runAuthentikModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/authentik-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse authentik module: %v", err)
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
		t.Fatalf("execute authentik module: %v", err)
	}
	return res
}

func authentikExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestAuthentikVersionExposureModule(t *testing.T) {
	// shape taken from authentik/core/templates/base/header_js.html, rendered
	// unauthenticated on the default authentication flow page
	authentikBody := `<html><head><title>authentik</title></head><body>
	<script data-id="authentik-config">
	"use strict";
	window.authentik = {
		locale: "en",
		config: JSON.parse('{}'),
		brand: JSON.parse('{}'),
		versionFamily: "2025.12",
		versionSubdomain: "version-2025-12",
		build: "abc123",
		api: { base: "/", relBase: "/" },
	};
	</script>
	</body></html>`

	t.Run("an exposed authentik login flow page is flagged and versioned", func(t *testing.T) {
		res := runAuthentikModule(t, 200, authentikBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected an authentik finding")
		}
		if v := authentikExtract(res, "authentik_version_family"); v != "2025.12" {
			t.Errorf("authentik_version_family=%q, want 2025.12", v)
		}
	})

	t.Run("a blog post mentioning authentik is not flagged", func(t *testing.T) {
		body := `<html><body><h1>Migrating to authentik for SSO</h1>
		<p>We recently switched our identity provider to authentik and could not be happier.</p>
		</body></html>`
		if res := runAuthentikModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose mentioning authentik should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic sso login page with a version field is not authentik", func(t *testing.T) {
		body := `<html><body><script>window.myApp = { versionFamily: "9.9" };</script></body></html>`
		if res := runAuthentikModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic sso page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runAuthentikModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
