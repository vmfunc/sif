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
	const tgi = "../../modules/recon/tgi-api-exposure.yaml"
	const tei = "../../modules/recon/tei-api-exposure.yaml"

	tgiInfo := `{"model_id":"meta-llama/Llama-2-7b-chat-hf","model_sha":"abc","model_pipeline_tag":"text-generation",` +
		`"max_concurrent_requests":128,"max_best_of":2,"max_input_tokens":4095,"max_total_tokens":4096,` +
		`"max_batch_total_tokens":16384,"router":"text-generation-router","version":"2.0.4","sha":"deadbeef"}`

	teiInfo := `{"model_id":"BAAI/bge-large-en-v1.5","model_sha":"abc","model_dtype":"float16",` +
		`"model_type":{"embedding":{"pooling":"cls"}},"max_concurrent_requests":512,"max_input_length":512,` +
		`"max_batch_tokens":16384,"max_client_batch_size":32,"tokenization_workers":8,"version":"1.5.0"}`

	t.Run("a tgi info is flagged with its model id", func(t *testing.T) {
		res := runInferenceExposureModule(t, tgi, 200, tgiInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tgi finding")
		}
		if v := inferenceExtract(res, "tgi_model"); v != "meta-llama/Llama-2-7b-chat-hf" {
			t.Errorf("tgi_model=%q, want meta-llama/Llama-2-7b-chat-hf", v)
		}
	})

	t.Run("a tei info is flagged with its model id", func(t *testing.T) {
		res := runInferenceExposureModule(t, tei, 200, teiInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tei finding")
		}
		if v := inferenceExtract(res, "tei_model"); v != "BAAI/bge-large-en-v1.5" {
			t.Errorf("tei_model=%q, want BAAI/bge-large-en-v1.5", v)
		}
	})

	t.Run("a tgi info is not flagged as tei", func(t *testing.T) {
		if res := runInferenceExposureModule(t, tei, 200, tgiInfo); len(res.Findings) > 0 {
			t.Errorf("a tgi info should not match the tei module, got %d findings", len(res.Findings))
		}
	})

	t.Run("a tei info is not flagged as tgi", func(t *testing.T) {
		if res := runInferenceExposureModule(t, tgi, 200, teiInfo); len(res.Findings) > 0 {
			t.Errorf("a tei info should not match the tgi module, got %d findings", len(res.Findings))
		}
	})

	t.Run("a hugging face model config is not flagged as tei", func(t *testing.T) {
		body := `{"model_type":"bert","hidden_size":768,"num_attention_heads":12,"vocab_size":30522}`
		if res := runInferenceExposureModule(t, tei, 200, body); len(res.Findings) > 0 {
			t.Errorf("a model config.json should not match tei, got %d findings", len(res.Findings))
		}
	})

	t.Run("a batch-tokens body without model_type is not flagged as tei", func(t *testing.T) {
		body := `{"max_batch_tokens":16384,"max_concurrent_requests":512}`
		if res := runInferenceExposureModule(t, tei, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without model_type should not match tei, got %d findings", len(res.Findings))
		}
	})

	t.Run("a different router is not flagged as tgi", func(t *testing.T) {
		body := `{"router":"some-other-router","max_concurrent_requests":10}`
		if res := runInferenceExposureModule(t, tgi, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-tgi router should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{tgi, tei} {
			if res := runInferenceExposureModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{tgi, tei} {
			if res := runInferenceExposureModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
