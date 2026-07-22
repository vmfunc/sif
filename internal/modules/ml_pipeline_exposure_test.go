package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runMLPipelineModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func mlPipelineExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestMLPipelineExposureModules(t *testing.T) {
	const kubeflow = "../../modules/recon/kubeflow-pipelines-exposure.yaml"
	const metaflow = "../../modules/recon/metaflow-metadata-exposure.yaml"

	t.Run("a kubeflow pipelines list is flagged with its pipeline count", func(t *testing.T) {
		body := `{"pipelines":[{"id":"a1b2c3","created_at":"2026-01-01T00:00:00Z","name":"training-pipeline",` +
			`"parameters":[],"resource_references":[]}],"total_size":1,"next_page_token":""}`
		res := runMLPipelineModule(t, kubeflow, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kubeflow finding")
		}
		if v := mlPipelineExtract(res, "kubeflow_pipeline_count"); v != "1" {
			t.Errorf("kubeflow_pipeline_count=%q, want 1", v)
		}
	})

	t.Run("a generic pipelines-word page is not flagged as kubeflow", func(t *testing.T) {
		// shares the bare word "pipelines" (a CI product's dashboard prose) but not the
		// kubeflow pagination shape.
		body := `{"message":"see your pipelines dashboard","pipelines_url":"https://ci.example.com/pipelines"}`
		if res := runMLPipelineModule(t, kubeflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("a page merely mentioning pipelines should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a metaflow flows list is flagged with a flow id", func(t *testing.T) {
		body := `[{"flow_id":"TrainingFlow","user_name":"data-eng","ts_epoch":1735689600000,` +
			`"tags":null,"system_tags":["production"]}]`
		res := runMLPipelineModule(t, metaflow, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a metaflow finding")
		}
		if v := mlPipelineExtract(res, "metaflow_flow_id"); v != "TrainingFlow" {
			t.Errorf("metaflow_flow_id=%q, want TrainingFlow", v)
		}
	})

	t.Run("a generic user/timestamp array is not flagged as metaflow", func(t *testing.T) {
		body := `[{"user_name":"alice","ts_epoch":1735689600000,"role":"admin"}]`
		if res := runMLPipelineModule(t, metaflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body missing flow_id should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{kubeflow, metaflow} {
			if res := runMLPipelineModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 401 is not a leak", func(t *testing.T) {
		for _, file := range []string{kubeflow, metaflow} {
			if res := runMLPipelineModule(t, file, 401, `{"error":"unauthorized"}`); len(res.Findings) > 0 {
				t.Errorf("%s: a 401 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{kubeflow, metaflow} {
			if res := runMLPipelineModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a different product's version api is not flagged", func(t *testing.T) {
		// argocd's /api/version shape: shares no kubeflow/metaflow anchors.
		body := `{"Version":"v2.9.3","KustomizeVersion":"v5.3.0","HelmVersion":"v3.14.0"}`
		for _, file := range []string{kubeflow, metaflow} {
			if res := runMLPipelineModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a different product's version body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
