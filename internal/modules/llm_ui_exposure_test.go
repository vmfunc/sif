package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runUIExposureModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func uiExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLLMUIExposureModules(t *testing.T) {
	const openWebUI = "../../modules/recon/open-webui-exposure.yaml"
	const librechat = "../../modules/recon/librechat-exposure.yaml"
	const nextchat = "../../modules/recon/nextchat-config-exposure.yaml"
	const anythingllm = "../../modules/recon/anythingllm-exposure.yaml"

	openWebUIConfig := `{"status":true,"name":"Open WebUI","version":"0.6.15","default_locale":"",` +
		`"oauth":{"providers":{}},"features":{"auth":false,"auth_trusted_header":false,` +
		`"enable_ldap":false,"enable_signup":true,"enable_login_form":true,"enable_websocket":true}}`

	librechatConfig := `{"appTitle":"LibreChat","serverDomain":"https://chat.example.com",` +
		`"emailLoginEnabled":true,"registrationEnabled":true,"socialLogins":["google","github"]}`

	nextchatConfig := `{"needCode":false,"hideUserApiKey":false,"disableGPT4":false,` +
		`"hideBalanceQuery":true,"disableFastLink":false,"customModels":"","defaultModel":"gpt-4o-mini",` +
		`"visionModels":""}`

	anythingllmSetup := `{"results":{"RequiresAuth":false,"MultiUserMode":false,"EmbeddingEngine":"native",` +
		`"VectorDB":"lancedb","LLMProvider":"openai","LLMModel":"gpt-4o","WhisperProvider":"local"}}`

	t.Run("an open webui with auth disabled is flagged with its version", func(t *testing.T) {
		res := runUIExposureModule(t, openWebUI, 200, openWebUIConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected an open webui finding")
		}
		if v := uiExtract(res, "open_webui_version"); v != "0.6.15" {
			t.Errorf("open_webui_version=%q, want 0.6.15", v)
		}
	})

	t.Run("a rebranded open webui with auth disabled is still flagged", func(t *testing.T) {
		body := `{"status":true,"name":"Acme AI Portal","version":"0.6.15",` +
			`"features":{"auth":false,"auth_trusted_header":false,"enable_signup":true}}`
		res := runUIExposureModule(t, openWebUI, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a rebranded open webui")
		}
		if v := uiExtract(res, "open_webui_version"); v != "0.6.15" {
			t.Errorf("open_webui_version=%q, want 0.6.15", v)
		}
	})

	t.Run("a librechat with open registration is flagged with its title", func(t *testing.T) {
		res := runUIExposureModule(t, librechat, 200, librechatConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a librechat finding")
		}
		if v := uiExtract(res, "librechat_title"); v != "LibreChat" {
			t.Errorf("librechat_title=%q, want LibreChat", v)
		}
	})

	t.Run("an open webui with auth enabled is not flagged", func(t *testing.T) {
		body := `{"status":true,"name":"Open WebUI","version":"0.6.15",` +
			`"features":{"auth":true,"auth_trusted_header":false,"enable_signup":true}}`
		if res := runUIExposureModule(t, openWebUI, 200, body); len(res.Findings) > 0 {
			t.Errorf("an auth-enabled open webui should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an open webui auth_trusted_header false does not satisfy the auth regex", func(t *testing.T) {
		body := `{"status":true,"name":"Open WebUI","version":"0.6.15",` +
			`"features":{"auth":true,"auth_trusted_header":false}}`
		if res := runUIExposureModule(t, openWebUI, 200, body); len(res.Findings) > 0 {
			t.Errorf("auth_trusted_header false should not match the auth regex, got %d findings", len(res.Findings))
		}
	})

	t.Run("a librechat with registration disabled is not flagged", func(t *testing.T) {
		body := `{"appTitle":"LibreChat","emailLoginEnabled":true,"registrationEnabled":false,"socialLogins":[]}`
		if res := runUIExposureModule(t, librechat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a closed-registration librechat should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unrelated app with open registration is not flagged as librechat", func(t *testing.T) {
		body := `{"name":"otherapp","registrationEnabled":true}`
		if res := runUIExposureModule(t, librechat, 200, body); len(res.Findings) > 0 {
			t.Errorf("an unrelated app should not match librechat, got %d findings", len(res.Findings))
		}
	})

	t.Run("a nextchat config is flagged and reports its access-code gate", func(t *testing.T) {
		res := runUIExposureModule(t, nextchat, 200, nextchatConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nextchat finding")
		}
		if v := uiExtract(res, "nextchat_needcode"); v != "false" {
			t.Errorf("nextchat_needcode=%q, want false", v)
		}
	})

	t.Run("a body without needCode is not flagged as nextchat", func(t *testing.T) {
		body := `{"hideUserApiKey":false,"hideBalanceQuery":true}`
		if res := runUIExposureModule(t, nextchat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without needCode should not match nextchat, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without hideUserApiKey is not flagged as nextchat", func(t *testing.T) {
		body := `{"needCode":false,"hideBalanceQuery":true}`
		if res := runUIExposureModule(t, nextchat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without hideUserApiKey should not match nextchat, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without hideBalanceQuery is not flagged as nextchat", func(t *testing.T) {
		body := `{"needCode":false,"hideUserApiKey":false}`
		if res := runUIExposureModule(t, nextchat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without hideBalanceQuery should not match nextchat, got %d findings", len(res.Findings))
		}
	})

	t.Run("a code-gated nextchat is not flagged", func(t *testing.T) {
		body := `{"needCode":true,"hideUserApiKey":false,"hideBalanceQuery":true,"disableGPT4":false}`
		if res := runUIExposureModule(t, nextchat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a needCode:true nextchat is access-code gated and should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an anythingllm setup is flagged with its model", func(t *testing.T) {
		res := runUIExposureModule(t, anythingllm, 200, anythingllmSetup)
		if len(res.Findings) == 0 {
			t.Fatal("expected an anythingllm finding")
		}
		if v := uiExtract(res, "anythingllm_model"); v != "gpt-4o" {
			t.Errorf("anythingllm_model=%q, want gpt-4o", v)
		}
	})

	t.Run("a body without LLMProvider is not flagged as anythingllm", func(t *testing.T) {
		body := `{"results":{"VectorDB":"lancedb","EmbeddingEngine":"native"}}`
		if res := runUIExposureModule(t, anythingllm, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without LLMProvider should not match anythingllm, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without a VectorDB is not flagged as anythingllm", func(t *testing.T) {
		body := `{"results":{"LLMProvider":"openai","EmbeddingEngine":"native"}}`
		if res := runUIExposureModule(t, anythingllm, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without VectorDB should not match anythingllm, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{openWebUI, librechat, anythingllm, nextchat} {
			if res := runUIExposureModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{openWebUI, librechat, anythingllm, nextchat} {
			if res := runUIExposureModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
