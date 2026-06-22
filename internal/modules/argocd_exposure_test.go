package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runArgocdModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/argocd-api-exposure.yaml")
	if err != nil {
		t.Fatalf("parse argocd module: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute argocd module: %v", err)
	}
	return res
}

func argocdExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestArgocdExposureModule(t *testing.T) {
	argocdVersion := `{"Version":"v2.9.3+a1b2c3d","BuildDate":"2024-01-15T12:00:00Z","GitCommit":"a1b2c3d",` +
		`"GitTreeState":"clean","GoVersion":"go1.21.5","Compiler":"gc","Platform":"linux/amd64",` +
		`"KustomizeVersion":"v5.2.1 2023-10-19","HelmVersion":"v3.13.2+gadc03ef",` +
		`"KubectlVersion":"v0.26.11","JsonnetVersion":"v0.20.0"}`

	t.Run("an exposed argocd version endpoint is flagged and versioned", func(t *testing.T) {
		res := runArgocdModule(t, 200, argocdVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected an argocd finding")
		}
		if v := argocdExtract(res, "argocd_version"); v != "v2.9.3+a1b2c3d" {
			t.Errorf("argocd_version=%q, want v2.9.3+a1b2c3d", v)
		}
	})

	t.Run("an argocd kustomize version without a helm version is not flagged", func(t *testing.T) {
		body := `{"Version":"v2.9.3","KustomizeVersion":"v5.2.1 2023-10-19"}`
		if res := runArgocdModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a kustomize version alone should not match argocd, got %d findings", len(res.Findings))
		}
	})

	t.Run("an argocd helm version without a kustomize version is not flagged", func(t *testing.T) {
		body := `{"Version":"v2.9.3","HelmVersion":"v3.13.2+gadc03ef"}`
		if res := runArgocdModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a helm version alone should not match argocd, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic version endpoint is not argocd", func(t *testing.T) {
		body := `{"Version":"v1.0.0","GitCommit":"abc"}`
		if res := runArgocdModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic version json should not match argocd, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runArgocdModule(t, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runArgocdModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
