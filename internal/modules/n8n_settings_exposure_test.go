package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runN8nModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func n8nExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestN8nSettingsExposureModule(t *testing.T) {
	const n8n = "../../modules/recon/n8n-settings-exposure.yaml"

	t.Run("an n8n settings response is flagged with the version", func(t *testing.T) {
		body := `{"data":{"endpointWebhook":"webhook","endpointWebhookTest":"webhook-test",` +
			`"urlBaseWebhook":"https://n8n.example.com/","urlBaseEditor":"https://n8n.example.com/",` +
			`"versionCli":"1.45.1","releaseChannel":"stable","instanceId":"abc123def","n8nMetadata":{},` +
			`"userManagement":{"showSetupOnFirstLoad":false,"smtpSetup":true,"authenticationMethod":"email"}}}`
		res := runN8nModule(t, n8n, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an n8n finding")
		}
		if v := n8nExtract(res, "n8n_version"); v != "1.45.1" {
			t.Errorf("n8n_version=%q, want 1.45.1", v)
		}
	})

	t.Run("a settings blob without instanceId is not flagged", func(t *testing.T) {
		if res := runN8nModule(t, n8n, 200, `{"data":{"endpointWebhook":"webhook","versionCli":"1.45.1"}}`); len(res.Findings) > 0 {
			t.Errorf("an instanceless settings blob should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a settings blob without endpointWebhook is not flagged", func(t *testing.T) {
		if res := runN8nModule(t, n8n, 200, `{"data":{"versionCli":"1.45.1","instanceId":"abc"}}`); len(res.Findings) > 0 {
			t.Errorf("a webhookless settings blob should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runN8nModule(t, n8n, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runN8nModule(t, n8n, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
