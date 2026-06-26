package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runServerAdminModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func serverAdminExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestServerAdminExposureModules(t *testing.T) {
	const caddy = "../../modules/recon/caddy-admin-exposure.yaml"
	const envoy = "../../modules/recon/envoy-admin-exposure.yaml"

	t.Run("a caddy config dump is flagged with a handler", func(t *testing.T) {
		body := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":` +
			`["example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"localhost:8080"}]}]}]}}},` +
			`"tls":{"automation":{"policies":[{"issuers":[{"module":"acme"}]}]}}},"admin":{"listen":"0.0.0.0:2019"}}`
		res := runServerAdminModule(t, caddy, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a caddy finding")
		}
		if v := serverAdminExtract(res, "caddy_handler"); v != "reverse_proxy" {
			t.Errorf("caddy_handler=%q, want reverse_proxy", v)
		}
	})

	t.Run("an apps block without servers or handler is not flagged as caddy", func(t *testing.T) {
		if res := runServerAdminModule(t, caddy, 200, `{"apps":{"tls":{"automation":{}}}}`); len(res.Findings) > 0 {
			t.Errorf("an apps-only tls block should not match caddy, got %d findings", len(res.Findings))
		}
	})

	t.Run("an envoy server_info is flagged with its version", func(t *testing.T) {
		body := `{"version":"1.28.0/abcd/Clean/RELEASE/BoringSSL","state":"LIVE","uptime_current_epoch":"3600s",` +
			`"uptime_all_epochs":"3600s","hot_restart_version":"11.104","command_line_options":{"base_id":"0",` +
			`"concurrency":4,"config_path":"/etc/envoy/envoy.yaml"},"node":{"id":"node-1","cluster":"prod"}}`
		res := runServerAdminModule(t, envoy, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an envoy finding")
		}
		if v := serverAdminExtract(res, "envoy_version"); v != "1.28.0/abcd/Clean/RELEASE/BoringSSL" {
			t.Errorf("envoy_version=%q, want the build string", v)
		}
	})

	t.Run("a bare version+state body is not flagged as envoy", func(t *testing.T) {
		if res := runServerAdminModule(t, envoy, 200, `{"version":"1.0","state":"LIVE"}`); len(res.Findings) > 0 {
			t.Errorf("a bare version+state should not match envoy, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{caddy, envoy} {
			if res := runServerAdminModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{caddy, envoy} {
			if res := runServerAdminModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
