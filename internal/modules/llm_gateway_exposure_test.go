package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runGatewayModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func gatewayExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLLMGatewayExposureModules(t *testing.T) {
	const oneapi = "../../modules/recon/oneapi-status-exposure.yaml"

	oneapiStatus := `{"success":true,"message":"","data":{"version":"v0.8.4","start_time":1719100000,` +
		`"system_name":"New API","quota_per_unit":500000,"github_oauth":false}}`

	t.Run("a oneapi status is flagged with its version", func(t *testing.T) {
		res := runGatewayModule(t, oneapi, 200, oneapiStatus)
		if len(res.Findings) == 0 {
			t.Fatal("expected a oneapi finding")
		}
		if v := gatewayExtract(res, "oneapi_version"); v != "v0.8.4" {
			t.Errorf("oneapi_version=%q, want v0.8.4", v)
		}
	})

	t.Run("a body without system_name is not flagged as oneapi", func(t *testing.T) {
		body := `{"data":{"start_time":1,"quota_per_unit":500000}}`
		if res := runGatewayModule(t, oneapi, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without system_name should not match oneapi, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without quota_per_unit is not flagged as oneapi", func(t *testing.T) {
		body := `{"data":{"system_name":"X","start_time":1}}`
		if res := runGatewayModule(t, oneapi, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without quota_per_unit should not match oneapi, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runGatewayModule(t, oneapi, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match oneapi, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runGatewayModule(t, oneapi, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match oneapi, got %d findings", len(res.Findings))
		}
	})
}
