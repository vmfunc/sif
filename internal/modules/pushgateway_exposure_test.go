package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runPushgatewayModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/pushgateway-exposure.yaml")
	if err != nil {
		t.Fatalf("parse pushgateway module: %v", err)
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
		t.Fatalf("execute pushgateway module: %v", err)
	}
	return res
}

func pushgatewayExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestPushgatewayExposureModule(t *testing.T) {
	// /api/v1/status envelope shape from pushgateway's api/v1/api.go
	statusBody := `{"status":"success","data":{"build_information":{"branch":"HEAD",` +
		`"buildDate":"20240101-00:00:00","goVersion":"go1.21.5","revision":"abcdef",` +
		`"version":"1.7.0"},"flags":{"web.listen-address":":9091"},` +
		`"start_time":"2026-07-01T10:00:00Z"}}`

	t.Run("an exposed pushgateway status is flagged and versioned", func(t *testing.T) {
		res := runPushgatewayModule(t, 200, statusBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a pushgateway finding")
		}
		if v := pushgatewayExtract(res, "pushgateway_version"); v != "1.7.0" {
			t.Errorf("pushgateway_version=%q, want 1.7.0", v)
		}
	})

	t.Run("a reverse-proxy 401 challenge is not a leak", func(t *testing.T) {
		body := `<html><head><title>401 Authorization Required</title></head>` +
			`<body><center><h1>401 Authorization Required</h1></center></body></html>`
		if res := runPushgatewayModule(t, 401, body); len(res.Findings) > 0 {
			t.Errorf("a 401 challenge should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a prometheus server status is not a pushgateway", func(t *testing.T) {
		// prometheus itself answers /api/v1/status/* with a success envelope but no build_information/start_time keys
		body := `{"status":"success","data":{"startTime":"2026-07-01T10:00:00Z",` +
			`"CWD":"/prometheus","version":"2.53.0"}}`
		if res := runPushgatewayModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prometheus status envelope should not match pushgateway, got %d findings", len(res.Findings))
		}
	})

	t.Run("a status envelope without build_information is not enough", func(t *testing.T) {
		// shares start_time and the success envelope but drops build_information
		body := `{"status":"success","data":{"start_time":"2026-07-01T10:00:00Z"}}`
		if res := runPushgatewayModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a status without build_information should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runPushgatewayModule(t, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})
}
