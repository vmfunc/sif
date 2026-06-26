package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDataOrchModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func dataOrchExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDataOrchestrationExposureModules(t *testing.T) {
	const dagster = "../../modules/recon/dagster-webserver-exposure.yaml"
	const mage = "../../modules/recon/mage-status-exposure.yaml"

	t.Run("a dagster server_info is flagged with its version", func(t *testing.T) {
		body := `{"dagster_webserver_version":"1.7.0","dagster_version":"1.7.0","dagster_graphql_version":"1.7.0"}`
		res := runDataOrchModule(t, dagster, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a dagster finding")
		}
		if v := dataOrchExtract(res, "dagster_version"); v != "1.7.0" {
			t.Errorf("dagster_version=%q, want 1.7.0", v)
		}
	})

	t.Run("a bare core-version body is not flagged as dagster", func(t *testing.T) {
		if res := runDataOrchModule(t, dagster, 200, `{"dagster_version":"1.7.0"}`); len(res.Findings) > 0 {
			t.Errorf("a body without dagster_webserver_version should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a mage status is flagged with its repo path", func(t *testing.T) {
		body := `{"statuses":[{"is_instance_manager":false,"repo_path":"/home/src/default_repo",` +
			`"repo_path_relative":"default_repo","scheduler_status":"running","project_type":"standalone",` +
			`"project_uuid":"abc-123"}]}`
		res := runDataOrchModule(t, mage, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a mage finding")
		}
		if v := dataOrchExtract(res, "mage_repo_path"); v != "/home/src/default_repo" {
			t.Errorf("mage_repo_path=%q, want /home/src/default_repo", v)
		}
	})

	t.Run("a statuses collection without scheduler fields is not flagged as mage", func(t *testing.T) {
		if res := runDataOrchModule(t, mage, 200, `{"statuses":[{"id":1,"name":"ok"}]}`); len(res.Findings) > 0 {
			t.Errorf("a generic statuses array should not match mage, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{dagster, mage} {
			if res := runDataOrchModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{dagster, mage} {
			if res := runDataOrchModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
