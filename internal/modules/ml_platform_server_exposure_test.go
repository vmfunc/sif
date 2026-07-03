package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runMLPlatformServerModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func mlPlatformServerExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestMLPlatformServerExposureModules(t *testing.T) {
	const h2o = "../../modules/recon/h2o-cluster-exposure.yaml"
	const mindsdb = "../../modules/recon/mindsdb-api-exposure.yaml"
	const zenml = "../../modules/recon/zenml-server-exposure.yaml"

	h2oCloud := `{"__meta":{"schema_name":"CloudV3"},"version":"3.46.0.6","branch_name":"rel-x",` +
		`"cloud_name":"H2O_started_from_python","cloud_size":1,"cloud_uptime_millis":123456,` +
		`"cloud_healthy":true,"build_too_old":false}`

	mindsdbStatus := `{"environment":"local","mindsdb_version":"25.13.1",` +
		`"auth":{"confirmed":false,"required":false,"provider":"disabled"}}`

	zenmlInfo := `{"id":"abc","version":"0.70.0","deployment_type":"docker","database_type":"sqlite",` +
		`"secrets_store_type":"sql","auth_scheme":"OAUTH2_PASSWORD_BEARER","analytics_enabled":true}`

	t.Run("an h2o cloud is flagged with its version", func(t *testing.T) {
		res := runMLPlatformServerModule(t, h2o, 200, h2oCloud)
		if len(res.Findings) == 0 {
			t.Fatal("expected an h2o finding")
		}
		if v := mlPlatformServerExtract(res, "h2o_version"); v != "3.46.0.6" {
			t.Errorf("h2o_version=%q, want 3.46.0.6", v)
		}
	})

	t.Run("a body without cloud_name is not flagged as h2o", func(t *testing.T) {
		body := `{"cloud_uptime_millis":1,"build_too_old":false,"version":"3.46"}`
		if res := runMLPlatformServerModule(t, h2o, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without cloud_name should not match h2o, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without build_too_old is not flagged as h2o", func(t *testing.T) {
		body := `{"cloud_name":"x","cloud_uptime_millis":1}`
		if res := runMLPlatformServerModule(t, h2o, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without build_too_old should not match h2o, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic cloud status is not flagged as h2o", func(t *testing.T) {
		body := `{"cloud_name":"x","build_too_old":false}`
		if res := runMLPlatformServerModule(t, h2o, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without cloud_uptime_millis should not match h2o, got %d findings", len(res.Findings))
		}
	})

	t.Run("a mindsdb status is flagged with its version", func(t *testing.T) {
		res := runMLPlatformServerModule(t, mindsdb, 200, mindsdbStatus)
		if len(res.Findings) == 0 {
			t.Fatal("expected a mindsdb finding")
		}
		if v := mlPlatformServerExtract(res, "mindsdb_version"); v != "25.13.1" {
			t.Errorf("mindsdb_version=%q, want 25.13.1", v)
		}
	})

	t.Run("a body without mindsdb_version is not flagged", func(t *testing.T) {
		body := `{"environment":"local","auth":{"provider":"disabled"}}`
		if res := runMLPlatformServerModule(t, mindsdb, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without mindsdb_version should not match mindsdb, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without an auth provider is not flagged as mindsdb", func(t *testing.T) {
		body := `{"environment":"local","mindsdb_version":"25.13.1","auth":{"required":false}}`
		if res := runMLPlatformServerModule(t, mindsdb, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without provider should not match mindsdb, got %d findings", len(res.Findings))
		}
	})

	t.Run("a zenml info is flagged with its version", func(t *testing.T) {
		res := runMLPlatformServerModule(t, zenml, 200, zenmlInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a zenml finding")
		}
		if v := mlPlatformServerExtract(res, "zenml_version"); v != "0.70.0" {
			t.Errorf("zenml_version=%q, want 0.70.0", v)
		}
	})

	t.Run("a body without deployment_type is not flagged as zenml", func(t *testing.T) {
		body := `{"secrets_store_type":"sql","auth_scheme":"OAUTH2","version":"0.70.0"}`
		if res := runMLPlatformServerModule(t, zenml, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without deployment_type should not match zenml, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without secrets_store_type is not flagged as zenml", func(t *testing.T) {
		body := `{"deployment_type":"docker","auth_scheme":"OAUTH2"}`
		if res := runMLPlatformServerModule(t, zenml, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without secrets_store_type should not match zenml, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without auth_scheme is not flagged as zenml", func(t *testing.T) {
		body := `{"deployment_type":"docker","secrets_store_type":"sql"}`
		if res := runMLPlatformServerModule(t, zenml, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without auth_scheme should not match zenml, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{h2o, mindsdb, zenml} {
			if res := runMLPlatformServerModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{h2o, mindsdb, zenml} {
			if res := runMLPlatformServerModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
