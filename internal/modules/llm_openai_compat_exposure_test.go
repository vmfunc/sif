package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runOpenAICompatModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func openAICompatExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLLMOpenAICompatExposureModules(t *testing.T) {
	const vllm = "../../modules/recon/vllm-api-exposure.yaml"
	const llamacpp = "../../modules/recon/llamacpp-api-exposure.yaml"
	const infinity = "../../modules/recon/infinity-embedding-api-exposure.yaml"
	const lmstudio = "../../modules/recon/lmstudio-api-exposure.yaml"

	vllmModels := `{"object":"list","data":[{"id":"meta-llama/Llama-3.1-8B-Instruct","object":"model",` +
		`"created":1718900000,"owned_by":"vllm","root":"meta-llama/Llama-3.1-8B-Instruct",` +
		`"parent":null,"max_model_len":131072}]}`

	llamacppModels := `{"object":"list","data":[{"id":"/models/llama-2-7b.Q4_K_M.gguf","object":"model",` +
		`"created":1718900000,"owned_by":"llamacpp"}]}`

	infinityModels := `{"data":[{"id":"BAAI/bge-small-en-v1.5","stats":{"queue_fraction":0.0,` +
		`"queue_absolute":0,"results_pending":0,"results_queue":0},"object":"model","owned_by":"infinity",` +
		`"created":1718900000,"backend":"torch","capabilities":["embed"]}],"object":"list"}`

	lmstudioModels := `{"object":"list","data":[{"id":"qwen2-vl-7b-instruct","object":"model",` +
		`"type":"vlm","publisher":"mlx-community","arch":"qwen2_vl","compatibility_type":"mlx",` +
		`"quantization":"4bit","state":"not-loaded","max_context_length":32768},` +
		`{"id":"text-embedding-nomic-embed-text-v1.5","object":"model","type":"embeddings",` +
		`"publisher":"nomic-ai","arch":"nomic-bert","compatibility_type":"gguf","quantization":"Q4_0",` +
		`"state":"not-loaded","max_context_length":2048}]}`

	t.Run("a vllm models api is flagged with its model id", func(t *testing.T) {
		res := runOpenAICompatModule(t, vllm, 200, vllmModels)
		if len(res.Findings) == 0 {
			t.Fatal("expected a vllm finding")
		}
		if v := openAICompatExtract(res, "vllm_model"); v != "meta-llama/Llama-3.1-8B-Instruct" {
			t.Errorf("vllm_model=%q, want meta-llama/Llama-3.1-8B-Instruct", v)
		}
	})

	t.Run("a vllm-prefixed but distinct owned_by is not flagged as vllm", func(t *testing.T) {
		body := `{"object":"list","data":[{"id":"meta-llama/Llama-3.1-8B-Instruct","object":"model",` +
			`"created":1718900000,"owned_by":"vllm-frontend-rs","root":"meta-llama/Llama-3.1-8B-Instruct"}]}`
		if res := runOpenAICompatModule(t, vllm, 200, body); len(res.Findings) > 0 {
			t.Errorf("owned_by vllm-frontend-rs should not match the anchored vllm regex, got %d findings", len(res.Findings))
		}
	})

	t.Run("a llamacpp models api is flagged with its model id", func(t *testing.T) {
		res := runOpenAICompatModule(t, llamacpp, 200, llamacppModels)
		if len(res.Findings) == 0 {
			t.Fatal("expected a llamacpp finding")
		}
		if v := openAICompatExtract(res, "llamacpp_model"); v != "/models/llama-2-7b.Q4_K_M.gguf" {
			t.Errorf("llamacpp_model=%q, want /models/llama-2-7b.Q4_K_M.gguf", v)
		}
	})

	t.Run("a llamacpp models api is not flagged as vllm", func(t *testing.T) {
		if res := runOpenAICompatModule(t, vllm, 200, llamacppModels); len(res.Findings) > 0 {
			t.Errorf("a llamacpp list should not match the vllm module, got %d findings", len(res.Findings))
		}
	})

	t.Run("a vllm models api is not flagged as llamacpp", func(t *testing.T) {
		if res := runOpenAICompatModule(t, llamacpp, 200, vllmModels); len(res.Findings) > 0 {
			t.Errorf("a vllm list should not match the llamacpp module, got %d findings", len(res.Findings))
		}
	})

	t.Run("an openai compatible list owned by openai is not flagged as vllm", func(t *testing.T) {
		body := `{"object":"list","data":[{"id":"gpt-4o","object":"model","owned_by":"openai"}]}`
		if res := runOpenAICompatModule(t, vllm, 200, body); len(res.Findings) > 0 {
			t.Errorf("an openai-owned list should not match vllm, got %d findings", len(res.Findings))
		}
	})

	t.Run("an infinity models list is flagged with its model id", func(t *testing.T) {
		res := runOpenAICompatModule(t, infinity, 200, infinityModels)
		if len(res.Findings) == 0 {
			t.Fatal("expected an infinity finding")
		}
		if v := openAICompatExtract(res, "infinity_model"); v != "BAAI/bge-small-en-v1.5" {
			t.Errorf("infinity_model=%q, want BAAI/bge-small-en-v1.5", v)
		}
	})

	t.Run("an infinity list without owned_by is not flagged", func(t *testing.T) {
		body := `{"data":[{"id":"x","backend":"torch","capabilities":["embed"]}],"object":"list"}`
		if res := runOpenAICompatModule(t, infinity, 200, body); len(res.Findings) > 0 {
			t.Errorf("a list without owned_by should not match infinity, got %d findings", len(res.Findings))
		}
	})

	t.Run("an infinity list without a backend is not flagged", func(t *testing.T) {
		body := `{"data":[{"id":"x","owned_by":"infinity","capabilities":["embed"]}],"object":"list"}`
		if res := runOpenAICompatModule(t, infinity, 200, body); len(res.Findings) > 0 {
			t.Errorf("a list without backend should not match infinity, got %d findings", len(res.Findings))
		}
	})

	t.Run("an infinity list without capabilities is not flagged", func(t *testing.T) {
		body := `{"data":[{"id":"x","owned_by":"infinity","backend":"torch"}],"object":"list"}`
		if res := runOpenAICompatModule(t, infinity, 200, body); len(res.Findings) > 0 {
			t.Errorf("a list without capabilities should not match infinity, got %d findings", len(res.Findings))
		}
	})

	t.Run("a non-infinity server with backend and capabilities is not flagged", func(t *testing.T) {
		body := `{"object":"list","data":[{"id":"m","object":"model","owned_by":"acme-org",` +
			`"backend":"vllm","capabilities":["chat"]}]}`
		if res := runOpenAICompatModule(t, infinity, 200, body); len(res.Findings) > 0 {
			t.Errorf("backend+capabilities with a non-infinity owned_by should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a vllm models list is not flagged as infinity", func(t *testing.T) {
		if res := runOpenAICompatModule(t, infinity, 200, vllmModels); len(res.Findings) > 0 {
			t.Errorf("a vllm list should not match infinity, got %d findings", len(res.Findings))
		}
	})

	t.Run("an infinity list is not flagged as vllm", func(t *testing.T) {
		if res := runOpenAICompatModule(t, vllm, 200, infinityModels); len(res.Findings) > 0 {
			t.Errorf("an infinity list should not match the vllm module, got %d findings", len(res.Findings))
		}
	})

	t.Run("an lmstudio models api is flagged with its model id", func(t *testing.T) {
		res := runOpenAICompatModule(t, lmstudio, 200, lmstudioModels)
		if len(res.Findings) == 0 {
			t.Fatal("expected an lmstudio finding")
		}
		if v := openAICompatExtract(res, "lmstudio_model"); v != "qwen2-vl-7b-instruct" {
			t.Errorf("lmstudio_model=%q, want qwen2-vl-7b-instruct", v)
		}
	})

	t.Run("a body without compatibility_type is not flagged as lmstudio", func(t *testing.T) {
		body := `{"object":"list","data":[{"id":"x","quantization":"4bit","max_context_length":4096}]}`
		if res := runOpenAICompatModule(t, lmstudio, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without compatibility_type should not match lmstudio, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without quantization is not flagged as lmstudio", func(t *testing.T) {
		body := `{"object":"list","data":[{"id":"x","compatibility_type":"gguf","max_context_length":4096}]}`
		if res := runOpenAICompatModule(t, lmstudio, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without quantization should not match lmstudio, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without max_context_length is not flagged as lmstudio", func(t *testing.T) {
		body := `{"object":"list","data":[{"id":"x","compatibility_type":"gguf","quantization":"4bit"}]}`
		if res := runOpenAICompatModule(t, lmstudio, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without max_context_length should not match lmstudio, got %d findings", len(res.Findings))
		}
	})

	t.Run("an openai compatible v1 models list is not flagged as lmstudio", func(t *testing.T) {
		if res := runOpenAICompatModule(t, lmstudio, 200, vllmModels); len(res.Findings) > 0 {
			t.Errorf("a plain v1 models list should not match lmstudio, got %d findings", len(res.Findings))
		}
	})

	t.Run("an lmstudio models list is not flagged as vllm", func(t *testing.T) {
		if res := runOpenAICompatModule(t, vllm, 200, lmstudioModels); len(res.Findings) > 0 {
			t.Errorf("an lmstudio list should not match the vllm module, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{vllm, llamacpp, lmstudio, infinity} {
			if res := runOpenAICompatModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{vllm, llamacpp, lmstudio, infinity} {
			if res := runOpenAICompatModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
