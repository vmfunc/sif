package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runInferenceExposureModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func inferenceExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLLMInferenceExposureModules(t *testing.T) {
	const ollama = "../../modules/recon/ollama-api-exposure.yaml"
	const koboldcpp = "../../modules/recon/koboldcpp-api-exposure.yaml"
	const tabby = "../../modules/recon/tabby-api-exposure.yaml"
	const oobabooga = "../../modules/recon/oobabooga-api-exposure.yaml"

	ollamaTags := `{"models":[{"name":"deepseek-r1:latest","model":"deepseek-r1:latest",` +
		`"modified_at":"2025-05-10T08:06:48.639712648-07:00","size":4683075271,` +
		`"digest":"0a8c266910232fd3291e71e5ba1e058cc5af9d411192cf88b6d30e92b6e73163",` +
		`"details":{"parent_model":"","format":"gguf","family":"qwen2","families":["qwen2"],` +
		`"parameter_size":"7.6B","quantization_level":"Q4_K_M"}}]}`

	koboldVersion := `{"result":"KoboldCpp","version":"1.71.1","protected":false,"llm":true,` +
		`"txt2img":true,"vision":false,"audio":false,"transcribe":false,"multiplayer":false,` +
		`"websearch":false,"tts":false,"embeddings":false,"music":false,"savedata":false,` +
		`"admin":0,"router":false,"guidance":false,"jinja":true,"mcp":false}`

	tabbyHealth := `{"model":"TabbyML/StarCoder-1B","chat_model":"Qwen2.5-Coder-7B-Instruct",` +
		`"device":"cuda","cuda_devices":["NVIDIA GeForce RTX 4090"],"models":{"completion":{"vram":1234}},` +
		`"arch":"x86_64","cpu_info":"AMD Ryzen 9 5950X","cpu_count":32,` +
		`"version":{"build_date":"2024-06-01","build_timestamp":"2024-06-01T00:00:00Z",` +
		`"git_sha":"deadbeef","git_describe":"v0.13.0"},"webserver":true}`

	oobaModelInfo := `{"model_name":"TheBloke_Llama-2-13B-chat-GPTQ","lora_names":["alpaca-lora"],` +
		`"loader":"ExLlamav2_HF"}`

	t.Run("an ollama tags api is flagged with its model name", func(t *testing.T) {
		res := runInferenceExposureModule(t, ollama, 200, ollamaTags)
		if len(res.Findings) == 0 {
			t.Fatal("expected an ollama finding")
		}
		if v := inferenceExtract(res, "ollama_model"); v != "deepseek-r1:latest" {
			t.Errorf("ollama_model=%q, want deepseek-r1:latest", v)
		}
	})

	t.Run("an ollama tags list without model details is not flagged", func(t *testing.T) {
		body := `{"models":[{"name":"llama3:latest","digest":"abc"}]}`
		if res := runInferenceExposureModule(t, ollama, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare model list should not match ollama, got %d findings", len(res.Findings))
		}
	})

	t.Run("an ollama version response is not flagged", func(t *testing.T) {
		if res := runInferenceExposureModule(t, ollama, 200, `{"version":"0.5.1"}`); len(res.Findings) > 0 {
			t.Errorf("a version response should not match ollama, got %d findings", len(res.Findings))
		}
	})

	t.Run("a koboldcpp version probe is flagged with its version", func(t *testing.T) {
		res := runInferenceExposureModule(t, koboldcpp, 200, koboldVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a koboldcpp finding")
		}
		if v := inferenceExtract(res, "koboldcpp_version"); v != "1.71.1" {
			t.Errorf("koboldcpp_version=%q, want 1.71.1", v)
		}
		if v := inferenceExtract(res, "koboldcpp_protected"); v != "false" {
			t.Errorf("koboldcpp_protected=%q, want false", v)
		}
	})

	t.Run("a koboldcpp result without txt2img is not flagged", func(t *testing.T) {
		body := `{"result":"KoboldCpp","protected":false}`
		if res := runInferenceExposureModule(t, koboldcpp, 200, body); len(res.Findings) > 0 {
			t.Errorf("a probe without txt2img should not match koboldcpp, got %d findings", len(res.Findings))
		}
	})

	t.Run("a koboldcpp result without protected is not flagged", func(t *testing.T) {
		body := `{"result":"KoboldCpp","txt2img":true}`
		if res := runInferenceExposureModule(t, koboldcpp, 200, body); len(res.Findings) > 0 {
			t.Errorf("a probe without protected should not match koboldcpp, got %d findings", len(res.Findings))
		}
	})

	t.Run("another server reporting capabilities is not flagged as koboldcpp", func(t *testing.T) {
		body := `{"result":"SomeOtherServer","protected":false,"txt2img":true}`
		if res := runInferenceExposureModule(t, koboldcpp, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-kobold result should not match koboldcpp, got %d findings", len(res.Findings))
		}
	})

	t.Run("a tabby health is flagged with its model", func(t *testing.T) {
		res := runInferenceExposureModule(t, tabby, 200, tabbyHealth)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tabby finding")
		}
		if v := inferenceExtract(res, "tabby_model"); v != "TabbyML/StarCoder-1B" {
			t.Errorf("tabby_model=%q, want TabbyML/StarCoder-1B", v)
		}
	})

	t.Run("a tabby health without git_describe is not flagged", func(t *testing.T) {
		body := `{"cpu_info":"AMD Ryzen","cuda_devices":["RTX 4090"],"device":"cuda"}`
		if res := runInferenceExposureModule(t, tabby, 200, body); len(res.Findings) > 0 {
			t.Errorf("a health body without git_describe should not match tabby, got %d findings", len(res.Findings))
		}
	})

	t.Run("a tabby health without cuda_devices is not flagged", func(t *testing.T) {
		body := `{"cpu_info":"AMD Ryzen","version":{"git_describe":"v0.13.0"}}`
		if res := runInferenceExposureModule(t, tabby, 200, body); len(res.Findings) > 0 {
			t.Errorf("a health body without cuda_devices should not match tabby, got %d findings", len(res.Findings))
		}
	})

	t.Run("a build info without cpu_info is not flagged as tabby", func(t *testing.T) {
		body := `{"cuda_devices":["RTX 4090"],"version":{"git_describe":"v0.13.0"}}`
		if res := runInferenceExposureModule(t, tabby, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without cpu_info should not match tabby, got %d findings", len(res.Findings))
		}
	})

	t.Run("an oobabooga model info is flagged with its model name", func(t *testing.T) {
		res := runInferenceExposureModule(t, oobabooga, 200, oobaModelInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected an oobabooga finding")
		}
		if v := inferenceExtract(res, "oobabooga_model"); v != "TheBloke_Llama-2-13B-chat-GPTQ" {
			t.Errorf("oobabooga_model=%q, want TheBloke_Llama-2-13B-chat-GPTQ", v)
		}
	})

	t.Run("a body without lora_names is not flagged as oobabooga", func(t *testing.T) {
		body := `{"model_name":"some-model","loader":"Transformers"}`
		if res := runInferenceExposureModule(t, oobabooga, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without lora_names should not match oobabooga, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without model_name is not flagged as oobabooga", func(t *testing.T) {
		body := `{"lora_names":["x"],"loader":"Transformers"}`
		if res := runInferenceExposureModule(t, oobabooga, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without model_name should not match oobabooga, got %d findings", len(res.Findings))
		}
	})

	t.Run("a model_names plural list is not flagged as oobabooga", func(t *testing.T) {
		body := `{"model_names":["TheBloke_Llama-2-13B-chat-GPTQ","mistral-7b-instruct"]}`
		if res := runInferenceExposureModule(t, oobabooga, 200, body); len(res.Findings) > 0 {
			t.Errorf("a model_names plural list should not match oobabooga, got %d findings", len(res.Findings))
		}
	})

	t.Run("an idle oobabooga with no model loaded is still flagged", func(t *testing.T) {
		body := `{"model_name":"None","lora_names":[],"loader":"Transformers"}`
		if res := runInferenceExposureModule(t, oobabooga, 200, body); len(res.Findings) == 0 {
			t.Error("expected an idle oobabooga (model_name None) to still be flagged")
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{ollama, koboldcpp, oobabooga, tabby} {
			if res := runInferenceExposureModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{ollama, koboldcpp, oobabooga, tabby} {
			if res := runInferenceExposureModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
