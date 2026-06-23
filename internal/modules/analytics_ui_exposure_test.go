package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runAnalyticsModule(t *testing.T, file string, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
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
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

func analyticsExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestAnalyticsUIExposureModules(t *testing.T) {
	const metabase = "../../modules/recon/metabase-api-exposure.yaml"
	const zeppelin = "../../modules/recon/zeppelin-api-exposure.yaml"
	const jupyter = "../../modules/recon/jupyter-api-exposure.yaml"

	metabaseProps := `{"engines":{"postgres":{"driver-name":"PostgreSQL"}},` +
		`"setup-token":"245f5f7c-8f0b-4c20-9a1e-6b2d7e1f0a33","anon-tracking-enabled":true,` +
		`"available-locales":[["en","English"]],"password-complexity":{"total":6},` +
		`"version":{"date":"2023-10-01","tag":"v0.47.2","branch":"release-x.47.x","hash":"abc1234"}}`

	zeppelinVersion := `{"status":"OK","message":"Zeppelin version",` +
		`"body":{"version":"0.10.1","git-commit-id":"a1b2c3d4e5","git-timestamp":"2022-01-15 10:00:00"}}`

	jupyterStatus := `{"started":"2024-01-01T00:00:00.000000Z",` +
		`"last_activity":"2024-01-01T01:23:45.000000Z","connections":2,"kernels":3}`

	t.Run("an exposed metabase properties api is flagged and versioned", func(t *testing.T) {
		res := runAnalyticsModule(t, metabase, 200, metabaseProps)
		if len(res.Findings) == 0 {
			t.Fatal("expected a metabase finding")
		}
		if v := analyticsExtract(res, "metabase_version"); v != "v0.47.2" {
			t.Errorf("metabase_version=%q, want v0.47.2", v)
		}
	})

	t.Run("an exposed zeppelin server is flagged and versioned", func(t *testing.T) {
		res := runAnalyticsModule(t, zeppelin, 200, zeppelinVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a zeppelin finding")
		}
		if v := analyticsExtract(res, "zeppelin_version"); v != "0.10.1" {
			t.Errorf("zeppelin_version=%q, want 0.10.1", v)
		}
	})

	t.Run("an exposed jupyter status api is flagged with the kernel count", func(t *testing.T) {
		res := runAnalyticsModule(t, jupyter, 200, jupyterStatus)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jupyter finding")
		}
		if v := analyticsExtract(res, "jupyter_active_kernels"); v != "3" {
			t.Errorf("jupyter_active_kernels=%q, want 3", v)
		}
	})

	t.Run("a live metabase token without the tracking setting is not flagged", func(t *testing.T) {
		body := `{"setup-token":"245f5f7c-8f0b-4c20-9a1e-6b2d7e1f0a33","name":"app"}`
		if res := runAnalyticsModule(t, metabase, 200, body); len(res.Findings) > 0 {
			t.Errorf("a setup token alone should not match metabase, got %d findings", len(res.Findings))
		}
	})

	t.Run("a metabase tracking setting without a setup token is not flagged", func(t *testing.T) {
		body := `{"anon-tracking-enabled":true,"name":"app"}`
		if res := runAnalyticsModule(t, metabase, 200, body); len(res.Findings) > 0 {
			t.Errorf("a tracking setting alone should not match metabase, got %d findings", len(res.Findings))
		}
	})

	t.Run("a patched metabase with a null setup token is not flagged", func(t *testing.T) {
		body := `{"setup-token":null,"anon-tracking-enabled":true,` +
			`"version":{"tag":"v0.47.2"}}`
		if res := runAnalyticsModule(t, metabase, 200, body); len(res.Findings) > 0 {
			t.Errorf("a null setup token should not match metabase, got %d findings", len(res.Findings))
		}
	})

	t.Run("a zeppelin banner without a git commit id is not flagged", func(t *testing.T) {
		body := `{"status":"OK","message":"Zeppelin version","body":{}}`
		if res := runAnalyticsModule(t, zeppelin, 200, body); len(res.Findings) > 0 {
			t.Errorf("a banner alone should not match zeppelin, got %d findings", len(res.Findings))
		}
	})

	t.Run("a git commit id without the zeppelin banner is not flagged", func(t *testing.T) {
		body := `{"git-commit-id":"a1b2c3d","name":"app"}`
		if res := runAnalyticsModule(t, zeppelin, 200, body); len(res.Findings) > 0 {
			t.Errorf("a commit id alone should not match zeppelin, got %d findings", len(res.Findings))
		}
	})

	t.Run("a jupyter status without a kernels field is not flagged", func(t *testing.T) {
		body := `{"started":"2024-01-01T00:00:00Z","last_activity":"2024-01-01T01:00:00Z","connections":2}`
		if res := runAnalyticsModule(t, jupyter, 200, body); len(res.Findings) > 0 {
			t.Errorf("a status without kernels should not match jupyter, got %d findings", len(res.Findings))
		}
	})

	t.Run("a jupyter status without a connections field is not flagged", func(t *testing.T) {
		body := `{"started":"2024-01-01T00:00:00Z","last_activity":"2024-01-01T01:00:00Z","kernels":3}`
		if res := runAnalyticsModule(t, jupyter, 200, body); len(res.Findings) > 0 {
			t.Errorf("a status without connections should not match jupyter, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic version json is not an analytics service", func(t *testing.T) {
		body := `{"version":"1.0.0","name":"app"}`
		for _, file := range []string{metabase, zeppelin, jupyter} {
			if res := runAnalyticsModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a generic version should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{metabase, zeppelin, jupyter} {
			if res := runAnalyticsModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{metabase, zeppelin, jupyter} {
			if res := runAnalyticsModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
