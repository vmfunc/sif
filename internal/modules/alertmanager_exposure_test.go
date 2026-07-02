package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runAlertmanagerModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func alertmanagerExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestAlertmanagerExposureModule(t *testing.T) {
	const am = "../../modules/recon/alertmanager-status-exposure.yaml"

	t.Run("an alertmanager status is flagged with its version", func(t *testing.T) {
		body := `{"cluster":{"name":"01HXYZ","status":"ready","peers":[{"name":"01HX","address":"10.0.0.7:9094"}]},` +
			`"versionInfo":{"branch":"HEAD","buildDate":"20240228","buildUser":"root@host","goVersion":"go1.21.7",` +
			`"revision":"0aa3c2a","version":"0.27.0"},"config":{"original":"global:\n  smtp_smarthost: 'smtp:587'\n  ` +
			`smtp_auth_password: 'hunter2'\nreceivers:\n- name: team\n  slack_configs:\n  - api_url: 'https://hooks.slack.com/services/T/B/X'\n"},` +
			`"uptime":"2024-06-01T10:00:00.000Z"}`
		res := runAlertmanagerModule(t, am, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an alertmanager finding")
		}
		if v := alertmanagerExtract(res, "alertmanager_version"); v != "0.27.0" {
			t.Errorf("alertmanager_version=%q, want 0.27.0", v)
		}
	})

	t.Run("a versionInfo+cluster body without config is not flagged", func(t *testing.T) {
		body := `{"cluster":{"name":"01HXYZ","status":"ready"},"versionInfo":{"version":"0.27.0"},"uptime":"x"}`
		if res := runAlertmanagerModule(t, am, 200, body); len(res.Findings) > 0 {
			t.Errorf("a configless status should not match alertmanager, got %d findings", len(res.Findings))
		}
	})

	t.Run("a config+versionInfo body without cluster is not flagged", func(t *testing.T) {
		body := `{"versionInfo":{"version":"0.27.0"},"config":{"original":"global:\n"},"uptime":"x"}`
		if res := runAlertmanagerModule(t, am, 200, body); len(res.Findings) > 0 {
			t.Errorf("a clusterless status should not match alertmanager, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runAlertmanagerModule(t, am, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runAlertmanagerModule(t, am, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
