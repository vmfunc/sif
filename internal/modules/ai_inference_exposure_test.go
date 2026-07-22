package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runAIInferenceModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func aiInferenceExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLocalAISystemExposureModule(t *testing.T) {
	const localai = "../../modules/recon/localai-system-exposure.yaml"

	t.Run("a localai system api is flagged with its loaded model", func(t *testing.T) {
		body := `{"backends":["llama-cpp","huggingface","diffusers","whisper"],` +
			`"loaded_models":[{"id":"my-llama-model"},{"id":"whisper-1"}]}`
		res := runAIInferenceModule(t, localai, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a localai finding")
		}
		if v := aiInferenceExtract(res, "localai_loaded_model"); v != "my-llama-model" {
			t.Errorf("localai_loaded_model=%q, want my-llama-model", v)
		}
	})

	t.Run("a backends list without loaded_models is not flagged", func(t *testing.T) {
		body := `{"backends":["llama-cpp","diffusers"]}`
		if res := runAIInferenceModule(t, localai, 200, body); len(res.Findings) > 0 {
			t.Errorf("a backends-only body should not match localai, got %d findings", len(res.Findings))
		}
	})

	t.Run("a loaded_models list without backends is not flagged", func(t *testing.T) {
		body := `{"loaded_models":[{"id":"x"}]}`
		if res := runAIInferenceModule(t, localai, 200, body); len(res.Findings) > 0 {
			t.Errorf("a loaded_models-only body should not match localai, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic backend list mentioning loaded_models in prose is not flagged", func(t *testing.T) {
		body := `{"page":"the backends and loaded_models fields are documented in our api reference"}`
		if res := runAIInferenceModule(t, localai, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match localai, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 401 from a secured localai instance is not flagged", func(t *testing.T) {
		body := `{"backends":["llama-cpp"],"loaded_models":[{"id":"x"}]}`
		if res := runAIInferenceModule(t, localai, 401, body); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestInvokeAIRuntimeConfigExposureModule(t *testing.T) {
	const invokeai = "../../modules/recon/invokeai-runtime-config-exposure.yaml"

	t.Run("an invokeai runtime_config api is flagged with its models_dir", func(t *testing.T) {
		body := `{"set_fields":["host","port"],"config":{"host":"0.0.0.0","port":9090,` +
			`"models_dir":"models","outputs_dir":"outputs","db_dir":"databases",` +
			`"legacy_conf_dir":"configs","custom_nodes_dir":"nodes","precision":"auto"}}`
		res := runAIInferenceModule(t, invokeai, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an invokeai finding")
		}
		if v := aiInferenceExtract(res, "invokeai_models_dir"); v != "models" {
			t.Errorf("invokeai_models_dir=%q, want models", v)
		}
	})

	t.Run("a set_fields body without the invokeai-specific dirs is not flagged", func(t *testing.T) {
		body := `{"set_fields":["host"],"config":{"host":"0.0.0.0"}}`
		if res := runAIInferenceModule(t, invokeai, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body missing the invokeai dir keys should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic config mentioning custom_nodes_dir alone is not flagged", func(t *testing.T) {
		body := `{"custom_nodes_dir":"nodes","legacy_conf_dir":"configs"}`
		if res := runAIInferenceModule(t, invokeai, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without set_fields should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain version response is not flagged", func(t *testing.T) {
		if res := runAIInferenceModule(t, invokeai, 200, `{"version":"5.6.1"}`); len(res.Findings) > 0 {
			t.Errorf("a bare version body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 403 from an admin-gated deployment is not flagged", func(t *testing.T) {
		body := `{"set_fields":["host"],"config":{"legacy_conf_dir":"configs","custom_nodes_dir":"nodes"}}`
		if res := runAIInferenceModule(t, invokeai, 403, body); len(res.Findings) > 0 {
			t.Errorf("a 403 should not match, got %d findings", len(res.Findings))
		}
	})
}
