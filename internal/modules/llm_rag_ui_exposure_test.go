package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runRAGUIModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func ragUIExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLLMRAGUIExposureModules(t *testing.T) {
	const fastgpt = "../../modules/recon/fastgpt-init-exposure.yaml"
	const perplexica = "../../modules/recon/perplexica-config-exposure.yaml"
	const onyx = "../../modules/recon/onyx-auth-exposure.yaml"
	const verba = "../../modules/recon/verba-health-exposure.yaml"

	fastgptInit := `{"code":200,"data":{"bufferId":"unAuth_x","feConfigs":{"systemTitle":"FastGPT",` +
		`"docUrl":"https://doc.fastgpt.io","show_git":true},"modelProviders":[{"provider":"openai"}],` +
		`"aiproxyChannels":[]}}`

	perplexicaConfig := `{"values":{"general":{"theme":"dark","measureUnit":"Metric","autoMediaSearch":true,` +
		`"showWeatherWidget":true},"modelProviders":[{"id":"openai","name":"OpenAI",` +
		`"config":{"apiKey":"sk-secret","baseURL":""},"chatModels":[],"embeddingModels":[]}],` +
		`"search":{"searxngURL":"http://searxng:8080"}},"fields":[{"key":"measureUnit"},{"key":"autoMediaSearch"},` +
		`{"key":"searxngURL"}]}`

	onyxAuth := `{"auth_type":"basic","requires_verification":false,"anonymous_user_enabled":false,` +
		`"password_min_length":8,"has_users":true,"oauth_enabled":false}`

	verbaHealth := `{"message":"Alive!","production":"Local","gtag":"",` +
		`"deployments":{"WEAVIATE_URL_VERBA":"https://my-cluster.weaviate.network",` +
		`"WEAVIATE_API_KEY_VERBA":"sk-weaviate-AbC123secret"},"default_deployment":"Weaviate"}`

	t.Run("a fastgpt init is flagged with its system title", func(t *testing.T) {
		res := runRAGUIModule(t, fastgpt, 200, fastgptInit)
		if len(res.Findings) == 0 {
			t.Fatal("expected a fastgpt finding")
		}
		if v := ragUIExtract(res, "fastgpt_title"); v != "FastGPT" {
			t.Errorf("fastgpt_title=%q, want FastGPT", v)
		}
	})

	t.Run("a body without feConfigs is not flagged as fastgpt", func(t *testing.T) {
		body := `{"data":{"modelProviders":[],"aiproxyChannels":[]}}`
		if res := runRAGUIModule(t, fastgpt, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without feConfigs should not match fastgpt, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without aiproxyChannels is not flagged as fastgpt", func(t *testing.T) {
		body := `{"data":{"feConfigs":{},"modelProviders":[]}}`
		if res := runRAGUIModule(t, fastgpt, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without aiproxyChannels should not match fastgpt, got %d findings", len(res.Findings))
		}
	})

	t.Run("a perplexica config is flagged with its searxng url", func(t *testing.T) {
		res := runRAGUIModule(t, perplexica, 200, perplexicaConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a perplexica finding")
		}
		if v := ragUIExtract(res, "perplexica_searxng"); v != "http://searxng:8080" {
			t.Errorf("perplexica_searxng=%q, want http://searxng:8080", v)
		}
	})

	t.Run("a body without searxngURL is not flagged as perplexica", func(t *testing.T) {
		body := `{"values":{"general":{"measureUnit":"Metric","autoMediaSearch":true}}}`
		if res := runRAGUIModule(t, perplexica, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without searxngURL should not match perplexica, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without autoMediaSearch is not flagged as perplexica", func(t *testing.T) {
		body := `{"values":{"general":{"measureUnit":"Metric"},"search":{"searxngURL":"http://x"}}}`
		if res := runRAGUIModule(t, perplexica, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without autoMediaSearch should not match perplexica, got %d findings", len(res.Findings))
		}
	})

	t.Run("an onyx auth type is flagged with its auth scheme", func(t *testing.T) {
		res := runRAGUIModule(t, onyx, 200, onyxAuth)
		if len(res.Findings) == 0 {
			t.Fatal("expected an onyx finding")
		}
		if v := ragUIExtract(res, "onyx_auth_type"); v != "basic" {
			t.Errorf("onyx_auth_type=%q, want basic", v)
		}
	})

	t.Run("a body without anonymous_user_enabled is not flagged as onyx", func(t *testing.T) {
		body := `{"auth_type":"basic","requires_verification":false,"password_min_length":8}`
		if res := runRAGUIModule(t, onyx, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without anonymous_user_enabled should not match onyx, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without password_min_length is not flagged as onyx", func(t *testing.T) {
		body := `{"auth_type":"basic","requires_verification":false,"anonymous_user_enabled":false}`
		if res := runRAGUIModule(t, onyx, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without password_min_length should not match onyx, got %d findings", len(res.Findings))
		}
	})

	t.Run("a verba health is flagged and leaks the weaviate url", func(t *testing.T) {
		res := runRAGUIModule(t, verba, 200, verbaHealth)
		if len(res.Findings) == 0 {
			t.Fatal("expected a verba finding")
		}
		if v := ragUIExtract(res, "verba_weaviate_url"); v != "https://my-cluster.weaviate.network" {
			t.Errorf("verba_weaviate_url=%q, want https://my-cluster.weaviate.network", v)
		}
	})

	t.Run("a body without WEAVIATE_API_KEY_VERBA is not flagged as verba", func(t *testing.T) {
		body := `{"message":"Alive!","deployments":{"WEAVIATE_URL_VERBA":"http://x"},"default_deployment":""}`
		if res := runRAGUIModule(t, verba, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without WEAVIATE_API_KEY_VERBA should not match verba, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without WEAVIATE_URL_VERBA is not flagged as verba", func(t *testing.T) {
		body := `{"message":"Alive!","deployments":{"WEAVIATE_API_KEY_VERBA":"k"},"default_deployment":""}`
		if res := runRAGUIModule(t, verba, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without WEAVIATE_URL_VERBA should not match verba, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without default_deployment is not flagged as verba", func(t *testing.T) {
		body := `{"message":"Alive!","deployments":{"WEAVIATE_URL_VERBA":"http://x","WEAVIATE_API_KEY_VERBA":"k"}}`
		if res := runRAGUIModule(t, verba, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without default_deployment should not match verba, got %d findings", len(res.Findings))
		}
	})

	t.Run("a verba health with an empty weaviate url is not flagged", func(t *testing.T) {
		body := `{"message":"Alive!","production":"Local","deployments":{"WEAVIATE_URL_VERBA":"",` +
			`"WEAVIATE_API_KEY_VERBA":""},"default_deployment":""}`
		if res := runRAGUIModule(t, verba, 200, body); len(res.Findings) > 0 {
			t.Errorf("an embedded verba that leaks no backend url should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic alive health is not flagged as verba", func(t *testing.T) {
		body := `{"message":"Alive!","status":"ok","uptime":1234}`
		if res := runRAGUIModule(t, verba, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic health should not match verba, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{perplexica, verba, onyx, fastgpt} {
			if res := runRAGUIModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{perplexica, verba, onyx, fastgpt} {
			if res := runRAGUIModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
