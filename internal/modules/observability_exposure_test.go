package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runObservabilityModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func observExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestObservabilityExposureModules(t *testing.T) {
	const loki = "../../modules/recon/loki-api-exposure.yaml"
	const jaeger = "../../modules/recon/jaeger-query-exposure.yaml"
	const zipkin = "../../modules/recon/zipkin-exposure.yaml"

	t.Run("an open loki labels response is flagged with a label", func(t *testing.T) {
		body := `{"status":"success","data":["app","filename","job","namespace","pod"]}`
		res := runObservabilityModule(t, loki, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a loki finding")
		}
		if v := observExtract(res, "loki_label"); v != "app" {
			t.Errorf("loki_label=%q, want app", v)
		}
	})

	t.Run("an open loki with no ingested labels is still flagged", func(t *testing.T) {
		if res := runObservabilityModule(t, loki, 200, `{"status":"success","data":[]}`); len(res.Findings) == 0 {
			t.Error("expected a loki finding for an empty-but-open instance")
		}
	})

	t.Run("a multi-tenant loki returns 401 and is not flagged", func(t *testing.T) {
		if res := runObservabilityModule(t, loki, 401, `no org id\n`); len(res.Findings) > 0 {
			t.Errorf("a 401 from a secured loki should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a non-loki success envelope is not flagged as loki", func(t *testing.T) {
		if res := runObservabilityModule(t, loki, 200, `{"ok":true,"items":[]}`); len(res.Findings) > 0 {
			t.Errorf("a body without the loki shape should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a jaeger service list is flagged with a service name", func(t *testing.T) {
		body := `{"data":["customer","driver","frontend","route"],"total":0,"limit":0,"offset":0,"errors":null}`
		res := runObservabilityModule(t, jaeger, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jaeger finding")
		}
		if v := observExtract(res, "jaeger_service"); v != "customer" {
			t.Errorf("jaeger_service=%q, want customer", v)
		}
	})

	t.Run("a generic pagination envelope without errors is not flagged as jaeger", func(t *testing.T) {
		body := `{"data":["a","b"],"total":2,"limit":10,"offset":0}`
		if res := runObservabilityModule(t, jaeger, 200, body); len(res.Findings) > 0 {
			t.Errorf("an envelope without errors should not match jaeger, got %d findings", len(res.Findings))
		}
	})

	t.Run("a bare data array is not flagged as jaeger", func(t *testing.T) {
		if res := runObservabilityModule(t, jaeger, 200, `{"data":["x"]}`); len(res.Findings) > 0 {
			t.Errorf("a bare data array should not match jaeger, got %d findings", len(res.Findings))
		}
	})

	t.Run("a zipkin config is flagged with its environment", func(t *testing.T) {
		body := `{"environment":"prod","queryLimit":10,"defaultLookback":900000,"searchEnabled":true,` +
			`"dependency":{"enabled":true,"lowErrorRate":0.5,"highErrorRate":0.75}}`
		res := runObservabilityModule(t, zipkin, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a zipkin finding")
		}
		if v := observExtract(res, "zipkin_environment"); v != "prod" {
			t.Errorf("zipkin_environment=%q, want prod", v)
		}
	})

	t.Run("a config with searchEnabled alone is not flagged as zipkin", func(t *testing.T) {
		if res := runObservabilityModule(t, zipkin, 200, `{"searchEnabled":true,"foo":1}`); len(res.Findings) > 0 {
			t.Errorf("a partial config should not match zipkin, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{loki, jaeger, zipkin} {
			if res := runObservabilityModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{loki, jaeger, zipkin} {
			if res := runObservabilityModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
