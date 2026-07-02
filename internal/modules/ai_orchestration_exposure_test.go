package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runOrchestrationModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func orchestrationExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestAIOrchestrationExposureModules(t *testing.T) {
	const langflow = "../../modules/recon/langflow-exposure.yaml"
	const dify = "../../modules/recon/dify-console-exposure.yaml"
	const ray = "../../modules/recon/ray-dashboard-exposure.yaml"
	const skypilot = "../../modules/recon/skypilot-api-exposure.yaml"

	langflowVersion := `{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`

	difyFeatures := `{"enable_app_deploy":true,"sso_enforced_for_signin":false,` +
		`"sso_enforced_for_signin_protocol":"","enable_marketplace":true,"enable_email_code_login":false,` +
		`"enable_email_password_login":true,"enable_social_oauth_login":false,"is_allow_register":true,` +
		`"is_allow_create_workspace":false,"is_email_setup":true,"license":{"status":"none","expired_at":""}}`

	rayVersion := `{"version":"4","ray_version":"2.9.3","ray_commit":"a1b2c3d4e5","session_name":"session_2024"}`

	skypilotHealth := `{"status":"healthy","api_version":"14","version":"0.9.3","version_on_disk":"0.9.3",` +
		`"commit":"abc1234def","basic_auth_enabled":false}`

	t.Run("a langflow version api is flagged", func(t *testing.T) {
		res := runOrchestrationModule(t, langflow, 200, langflowVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a langflow finding")
		}
		if v := orchestrationExtract(res, "langflow_version"); v != "1.0.19" {
			t.Errorf("langflow_version=%q, want 1.0.19", v)
		}
	})

	t.Run("a langflow base build is still flagged", func(t *testing.T) {
		body := `{"version":"1.0.19","main_version":"1.0.19","package":"Langflow Base"}`
		if res := runOrchestrationModule(t, langflow, 200, body); len(res.Findings) == 0 {
			t.Fatal("expected a finding for a langflow base build")
		}
	})

	t.Run("a version api from another package is not flagged as langflow", func(t *testing.T) {
		body := `{"version":"1.0","main_version":"1.0","package":"SomeApp"}`
		if res := runOrchestrationModule(t, langflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("another package should not match langflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a langflow package without main_version is not flagged", func(t *testing.T) {
		if res := runOrchestrationModule(t, langflow, 200, `{"package":"Langflow"}`); len(res.Findings) > 0 {
			t.Errorf("a package-only body should not match langflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a dify system-features is flagged and reports open registration", func(t *testing.T) {
		res := runOrchestrationModule(t, dify, 200, difyFeatures)
		if len(res.Findings) == 0 {
			t.Fatal("expected a dify finding")
		}
		if v := orchestrationExtract(res, "dify_allow_register"); v != "true" {
			t.Errorf("dify_allow_register=%q, want true", v)
		}
	})

	t.Run("a body without sso_enforced_for_signin is not flagged as dify", func(t *testing.T) {
		body := `{"enable_email_password_login":true,"is_allow_create_workspace":false,"is_allow_register":true}`
		if res := runOrchestrationModule(t, dify, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without sso_enforced_for_signin should not match dify, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without enable_email_password_login is not flagged as dify", func(t *testing.T) {
		body := `{"sso_enforced_for_signin":false,"is_allow_create_workspace":false}`
		if res := runOrchestrationModule(t, dify, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without enable_email_password_login should not match dify, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without is_allow_create_workspace is not flagged as dify", func(t *testing.T) {
		body := `{"sso_enforced_for_signin":false,"enable_email_password_login":true}`
		if res := runOrchestrationModule(t, dify, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without is_allow_create_workspace should not match dify, got %d findings", len(res.Findings))
		}
	})

	t.Run("a dify with registration disabled is not flagged", func(t *testing.T) {
		body := `{"sso_enforced_for_signin":false,"enable_email_password_login":true,"is_allow_create_workspace":true,"is_allow_register":false}`
		if res := runOrchestrationModule(t, dify, 200, body); len(res.Findings) > 0 {
			t.Errorf("a closed-registration dify should not be flagged, got %d findings", len(res.Findings))
		}
	})

	t.Run("a ray dashboard version is flagged", func(t *testing.T) {
		res := runOrchestrationModule(t, ray, 200, rayVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a ray finding")
		}
		if v := orchestrationExtract(res, "ray_version"); v != "2.9.3" {
			t.Errorf("ray_version=%q, want 2.9.3", v)
		}
	})

	t.Run("a generic version api is not flagged as ray", func(t *testing.T) {
		body := `{"version":"4","api_version":"v1","build":"123"}`
		if res := runOrchestrationModule(t, ray, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic version api should not match ray, got %d findings", len(res.Findings))
		}
	})

	t.Run("a ray_version without a ray_commit is not flagged", func(t *testing.T) {
		body := `{"version":"4","ray_version":"2.9.3"}`
		if res := runOrchestrationModule(t, ray, 200, body); len(res.Findings) > 0 {
			t.Errorf("ray_version alone should not match ray, got %d findings", len(res.Findings))
		}
	})

	t.Run("a skypilot health is flagged with its version and auth state", func(t *testing.T) {
		res := runOrchestrationModule(t, skypilot, 200, skypilotHealth)
		if len(res.Findings) == 0 {
			t.Fatal("expected a skypilot finding")
		}
		if v := orchestrationExtract(res, "skypilot_version"); v != "0.9.3" {
			t.Errorf("skypilot_version=%q, want 0.9.3", v)
		}
		if v := orchestrationExtract(res, "skypilot_basic_auth"); v != "false" {
			t.Errorf("skypilot_basic_auth=%q, want false", v)
		}
	})

	t.Run("a bare status health is not flagged as skypilot", func(t *testing.T) {
		if res := runOrchestrationModule(t, skypilot, 200, `{"status":"healthy"}`); len(res.Findings) > 0 {
			t.Errorf("an auth-gated bare health should not match skypilot, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without version_on_disk is not flagged as skypilot", func(t *testing.T) {
		body := `{"status":"healthy","api_version":"14","commit":"abc","basic_auth_enabled":false}`
		if res := runOrchestrationModule(t, skypilot, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without version_on_disk should not match skypilot, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without basic_auth_enabled is not flagged as skypilot", func(t *testing.T) {
		body := `{"status":"healthy","version_on_disk":"0.9.3","commit":"abc"}`
		if res := runOrchestrationModule(t, skypilot, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without basic_auth_enabled should not match skypilot, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without commit is not flagged as skypilot", func(t *testing.T) {
		body := `{"status":"healthy","version_on_disk":"0.9.3","basic_auth_enabled":false}`
		if res := runOrchestrationModule(t, skypilot, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without commit should not match skypilot, got %d findings", len(res.Findings))
		}
	})

	t.Run("a skypilot with basic auth enabled is not flagged", func(t *testing.T) {
		body := `{"status":"healthy","version_on_disk":"0.9.3","commit":"abc","basic_auth_enabled":true}`
		if res := runOrchestrationModule(t, skypilot, 200, body); len(res.Findings) > 0 {
			t.Errorf("an auth-enabled skypilot should not be flagged, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{langflow, dify, ray, skypilot} {
			if res := runOrchestrationModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{langflow, dify, ray, skypilot} {
			if res := runOrchestrationModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
