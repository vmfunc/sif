package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runForgejoModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/forgejo-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse forgejo module: %v", err)
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
		t.Fatalf("execute forgejo module: %v", err)
	}
	return res
}

func forgejoExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestForgejoVersionExposureModule(t *testing.T) {
	t.Run("an exposed forgejo version endpoint is flagged and versioned", func(t *testing.T) {
		// real body from codeberg.org/api/v1/version
		body := `{"version":"15.0.0-156-02d7aaa8+gitea-1.22.0"}`
		res := runForgejoModule(t, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a forgejo finding")
		}
		if v := forgejoExtract(res, "forgejo_version"); v != "15.0.0-156-02d7aaa8+gitea-1.22.0" {
			t.Errorf("forgejo_version=%q, want 15.0.0-156-02d7aaa8+gitea-1.22.0", v)
		}
	})

	t.Run("a second forgejo instance is flagged", func(t *testing.T) {
		// real body from git.private.coffee/api/v1/version
		body := `{"version":"15.0.3+gitea-1.22.0"}`
		res := runForgejoModule(t, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a forgejo finding")
		}
		if v := forgejoExtract(res, "forgejo_version"); v != "15.0.3+gitea-1.22.0" {
			t.Errorf("forgejo_version=%q, want 15.0.3+gitea-1.22.0", v)
		}
	})

	t.Run("a vanilla gitea dev build is not flagged as forgejo", func(t *testing.T) {
		// real body from gitea.com/api/v1/version, no +gitea- compat suffix
		body := `{"version":"1.27.0+dev-521-g840e7c6a54"}`
		if res := runForgejoModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a vanilla gitea dev build should not match forgejo, got %d findings", len(res.Findings))
		}
	})

	t.Run("a vanilla gitea release is not flagged as forgejo", func(t *testing.T) {
		// real body from opendev.org/api/v1/version, no suffix at all
		body := `{"version":"v1.26.2"}`
		if res := runForgejoModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a vanilla gitea release should not match forgejo, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runForgejoModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
