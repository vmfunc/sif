package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runGPUServingModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func gpuServingExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLLMGPUServingExposureModules(t *testing.T) {
	const triton = "../../modules/recon/triton-api-exposure.yaml"
	const sglang = "../../modules/recon/sglang-api-exposure.yaml"
	const torchserve = "../../modules/recon/torchserve-api-exposure.yaml"

	tritonMeta := `{"name":"triton","version":"2.45.0","extensions":["classification","sequence",` +
		`"model_repository","schedule_policy","model_configuration","statistics","trace","logging"]}`

	sglangInfo := `{"model_path":"meta-llama/Llama-3-8B","tokenizer_path":"meta-llama/Llama-3-8B",` +
		`"is_generation":true,"preferred_sampling_params":null,"weight_version":"default",` +
		`"has_image_understanding":false,"has_audio_understanding":false,"model_type":"llama",` +
		`"architectures":["LlamaForCausalLM"]}`

	torchserveModels := `{"nextPageToken":"4","models":[{"modelName":"resnet-18","modelUrl":"resnet-18.mar"},` +
		`{"modelName":"noop","modelUrl":"noop-v1.0"}]}`

	t.Run("a triton metadata api is flagged with its version", func(t *testing.T) {
		res := runGPUServingModule(t, triton, 200, tritonMeta)
		if len(res.Findings) == 0 {
			t.Fatal("expected a triton finding")
		}
		if v := gpuServingExtract(res, "triton_version"); v != "2.45.0" {
			t.Errorf("triton_version=%q, want 2.45.0", v)
		}
	})

	t.Run("a sglang model_info is flagged with its model path", func(t *testing.T) {
		res := runGPUServingModule(t, sglang, 200, sglangInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a sglang finding")
		}
		if v := gpuServingExtract(res, "sglang_model"); v != "meta-llama/Llama-3-8B" {
			t.Errorf("sglang_model=%q, want meta-llama/Llama-3-8B", v)
		}
	})

	t.Run("a torchserve models api is flagged with its model name", func(t *testing.T) {
		res := runGPUServingModule(t, torchserve, 200, torchserveModels)
		if len(res.Findings) == 0 {
			t.Fatal("expected a torchserve finding")
		}
		if v := gpuServingExtract(res, "torchserve_model"); v != "resnet-18" {
			t.Errorf("torchserve_model=%q, want resnet-18", v)
		}
	})

	t.Run("a hugging face config with model_type is not flagged as sglang", func(t *testing.T) {
		body := `{"model_type":"llama","architectures":["LlamaForCausalLM"],"hidden_size":4096}`
		if res := runGPUServingModule(t, sglang, 200, body); len(res.Findings) > 0 {
			t.Errorf("a model config should not match sglang, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generation flag alone is not flagged as sglang", func(t *testing.T) {
		body := `{"is_generation":true,"model":"x"}`
		if res := runGPUServingModule(t, sglang, 200, body); len(res.Findings) > 0 {
			t.Errorf("is_generation alone should not match sglang, got %d findings", len(res.Findings))
		}
	})

	t.Run("an image understanding flag alone is not flagged as sglang", func(t *testing.T) {
		body := `{"has_image_understanding":false,"model_path":"x"}`
		if res := runGPUServingModule(t, sglang, 200, body); len(res.Findings) > 0 {
			t.Errorf("has_image_understanding alone should not match sglang, got %d findings", len(res.Findings))
		}
	})

	t.Run("a model url without a page token is not flagged as torchserve", func(t *testing.T) {
		body := `{"models":[{"modelName":"x","modelUrl":"x.mar"}]}`
		if res := runGPUServingModule(t, torchserve, 200, body); len(res.Findings) > 0 {
			t.Errorf("modelUrl without nextPageToken should not match torchserve, got %d findings", len(res.Findings))
		}
	})

	t.Run("an ollama style models list is not flagged as torchserve", func(t *testing.T) {
		body := `{"models":[{"name":"llama3:latest","model":"llama3:latest"}]}`
		if res := runGPUServingModule(t, torchserve, 200, body); len(res.Findings) > 0 {
			t.Errorf("an ollama model list should not match torchserve, got %d findings", len(res.Findings))
		}
	})

	t.Run("a paginated list without a model url is not flagged as torchserve", func(t *testing.T) {
		body := `{"nextPageToken":"4","items":[{"id":"a"}]}`
		if res := runGPUServingModule(t, torchserve, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic paginated list should not match torchserve, got %d findings", len(res.Findings))
		}
	})

	t.Run("a kserve server that is not triton is not flagged", func(t *testing.T) {
		body := `{"name":"my-model-server","version":"1.0","extensions":["model_repository"]}`
		if res := runGPUServingModule(t, triton, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-triton kserve server should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a triton name without extensions is not flagged", func(t *testing.T) {
		if res := runGPUServingModule(t, triton, 200, `{"name":"triton"}`); len(res.Findings) > 0 {
			t.Errorf("a name-only body should not match triton, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{triton, sglang, torchserve} {
			if res := runGPUServingModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{triton, sglang, torchserve} {
			if res := runGPUServingModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
