package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runSpeechModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func speechExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestSpeechAudioExposureModules(t *testing.T) {
	const speaches = "../../modules/recon/speaches-api-exposure.yaml"
	const xtts = "../../modules/recon/xtts-api-server-exposure.yaml"

	speachesSTT := `{"data":[{"id":"Systran/faster-whisper-small","created":0,"object":"model",` +
		`"owned_by":"Systran","language":["en"],"task":"automatic-speech-recognition"}],"object":"list"}`

	speachesTTS := `{"data":[{"id":"speaches-ai/Kokoro-82M-v1.0-ONNX","created":0,"object":"model",` +
		`"owned_by":"speaches-ai","language":["en"],"task":"text-to-speech"}],"object":"list"}`

	xttsFolders := `{"speaker_folder":"/app/speakers","output_folder":"/app/output",` +
		`"model_folder":"/app/xtts_models"}`

	t.Run("a speaches stt model list is flagged with its model id", func(t *testing.T) {
		res := runSpeechModule(t, speaches, 200, speachesSTT)
		if len(res.Findings) == 0 {
			t.Fatal("expected a speaches finding")
		}
		if v := speechExtract(res, "speaches_model"); v != "Systran/faster-whisper-small" {
			t.Errorf("speaches_model=%q, want Systran/faster-whisper-small", v)
		}
	})

	t.Run("a speaches tts-only model list is flagged", func(t *testing.T) {
		if res := runSpeechModule(t, speaches, 200, speachesTTS); len(res.Findings) == 0 {
			t.Error("expected a speaches finding for a text-to-speech model list")
		}
	})

	t.Run("a generic openai-compatible model list is not flagged as speaches", func(t *testing.T) {
		body := `{"data":[{"id":"meta-llama/Llama-3","created":1234,"object":"model","owned_by":"vllm"}],"object":"list"}`
		if res := runSpeechModule(t, speaches, 200, body); len(res.Findings) > 0 {
			t.Errorf("a taskless model list should not match speaches, got %d findings", len(res.Findings))
		}
	})

	t.Run("a model list with a non-speech task is not flagged as speaches", func(t *testing.T) {
		body := `{"data":[{"id":"bert-base","object":"model","owned_by":"hf","task":"fill-mask"}],"object":"list"}`
		if res := runSpeechModule(t, speaches, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-speech task should not match speaches, got %d findings", len(res.Findings))
		}
	})

	t.Run("an empty speaches model list is not flagged", func(t *testing.T) {
		// A fresh speaches server with no models downloaded returns an empty data
		// array with nothing speaches-specific to anchor on; this known miss is
		// preferable to firing on every empty OpenAI-shaped list.
		body := `{"data":[],"object":"list"}`
		if res := runSpeechModule(t, speaches, 200, body); len(res.Findings) > 0 {
			t.Errorf("an empty model list should not match speaches, got %d findings", len(res.Findings))
		}
	})

	t.Run("an xtts get-folders is flagged with its model folder", func(t *testing.T) {
		res := runSpeechModule(t, xtts, 200, xttsFolders)
		if len(res.Findings) == 0 {
			t.Fatal("expected an xtts finding")
		}
		if v := speechExtract(res, "xtts_model_folder"); v != "/app/xtts_models" {
			t.Errorf("xtts_model_folder=%q, want /app/xtts_models", v)
		}
	})

	t.Run("a body without speaker_folder is not flagged as xtts", func(t *testing.T) {
		body := `{"output_folder":"/app/output","model_folder":"/app/xtts_models"}`
		if res := runSpeechModule(t, xtts, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without speaker_folder should not match xtts, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without model_folder is not flagged as xtts", func(t *testing.T) {
		body := `{"speaker_folder":"/app/speakers","output_folder":"/app/output"}`
		if res := runSpeechModule(t, xtts, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without model_folder should not match xtts, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without output_folder is not flagged as xtts", func(t *testing.T) {
		body := `{"speaker_folder":"/app/speakers","model_folder":"/app/xtts_models"}`
		if res := runSpeechModule(t, xtts, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without output_folder should not match xtts, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{speaches, xtts} {
			if res := runSpeechModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{speaches, xtts} {
			if res := runSpeechModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
