package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runTrackingModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func trackingExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestMLTrackingExposureModules(t *testing.T) {
	const mlflow = "../../modules/recon/mlflow-api-exposure.yaml"
	const tensorboard = "../../modules/recon/tensorboard-exposure.yaml"
	const aim = "../../modules/recon/aim-exposure.yaml"
	const determined = "../../modules/recon/determined-master-exposure.yaml"

	mlflowExperiment := `{"experiment":{"experiment_id":"0","name":"Default",` +
		`"artifact_location":"file:///mlflow/mlruns/0","lifecycle_stage":"active",` +
		`"creation_time":1700000000000,"last_update_time":1700000000000,"tags":[]}}`

	tensorboardEnv := `{"data_location":"/home/ml/runs/exp-2024","window_title":"",` +
		`"experiment_name":"","experiment_description":"","creation_time":0,"version":"2.16.2"}`

	aimProject := `{"name":"my-aim-repo","path":"/home/ml/.aim","description":"",` +
		`"telemetry_enabled":0,"warn_index":false,"warn_runs":false}`

	determinedMaster := `{"version":"0.27.1","master_id":"6f1f2a9c","cluster_id":"a1b2c3d4-e5f6-7890",` +
		`"cluster_name":"prod-cluster","telemetry_enabled":true,"rbac_enabled":false,` +
		`"strict_job_queue_control":false,"has_custom_logo":false,"branding":"determined"}`

	t.Run("an mlflow experiment is flagged with its artifact store", func(t *testing.T) {
		res := runTrackingModule(t, mlflow, 200, mlflowExperiment)
		if len(res.Findings) == 0 {
			t.Fatal("expected an mlflow finding")
		}
		if v := trackingExtract(res, "mlflow_artifact_location"); v != "file:///mlflow/mlruns/0" {
			t.Errorf("mlflow_artifact_location=%q, want file:///mlflow/mlruns/0", v)
		}
	})

	t.Run("an experiment_id without lifecycle_stage is not flagged as mlflow", func(t *testing.T) {
		body := `{"experiment_id":"5","artifact_location":"s3://bucket/x"}`
		if res := runTrackingModule(t, mlflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial body should not match mlflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("an experiment without an artifact_location is not flagged as mlflow", func(t *testing.T) {
		body := `{"experiment":{"experiment_id":"0","name":"Default","lifecycle_stage":"active"}}`
		if res := runTrackingModule(t, mlflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("an artifactless experiment should not match mlflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("an experiment without an experiment_id is not flagged as mlflow", func(t *testing.T) {
		body := `{"experiment":{"name":"Default","artifact_location":"file:///x","lifecycle_stage":"active"}}`
		if res := runTrackingModule(t, mlflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("an idless experiment should not match mlflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic lifecycle body is not flagged as mlflow", func(t *testing.T) {
		body := `{"lifecycle_stage":"production","name":"some-service"}`
		if res := runTrackingModule(t, mlflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic lifecycle body should not match mlflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a model checkpoint list is not flagged as mlflow", func(t *testing.T) {
		body := `[{"title":"x","model_name":"y","filename":"z"}]`
		if res := runTrackingModule(t, mlflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("a model list should not match mlflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a tensorboard environment is flagged with its version and run path", func(t *testing.T) {
		res := runTrackingModule(t, tensorboard, 200, tensorboardEnv)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tensorboard finding")
		}
		if v := trackingExtract(res, "tensorboard_version"); v != "2.16.2" {
			t.Errorf("tensorboard_version=%q, want 2.16.2", v)
		}
		if v := trackingExtract(res, "tensorboard_data_location"); v != "/home/ml/runs/exp-2024" {
			t.Errorf("tensorboard_data_location=%q, want /home/ml/runs/exp-2024", v)
		}
	})

	t.Run("a body without data_location is not flagged as tensorboard", func(t *testing.T) {
		body := `{"window_title":"","version":"2.16.2"}`
		if res := runTrackingModule(t, tensorboard, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without data_location should not match tensorboard, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without window_title is not flagged as tensorboard", func(t *testing.T) {
		body := `{"data_location":"/runs","version":"2.16.2"}`
		if res := runTrackingModule(t, tensorboard, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without window_title should not match tensorboard, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without a version is not flagged as tensorboard", func(t *testing.T) {
		body := `{"data_location":"/runs","window_title":"my board"}`
		if res := runTrackingModule(t, tensorboard, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without version should not match tensorboard, got %d findings", len(res.Findings))
		}
	})

	t.Run("an aim project is flagged with its repo path", func(t *testing.T) {
		res := runTrackingModule(t, aim, 200, aimProject)
		if len(res.Findings) == 0 {
			t.Fatal("expected an aim finding")
		}
		if v := trackingExtract(res, "aim_project_path"); v != "/home/ml/.aim" {
			t.Errorf("aim_project_path=%q, want /home/ml/.aim", v)
		}
	})

	t.Run("a body without telemetry_enabled is not flagged as aim", func(t *testing.T) {
		body := `{"name":"x","path":"/y","warn_index":false,"warn_runs":false}`
		if res := runTrackingModule(t, aim, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without telemetry_enabled should not match aim, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without warn_index is not flagged as aim", func(t *testing.T) {
		body := `{"telemetry_enabled":0,"warn_runs":false,"name":"x"}`
		if res := runTrackingModule(t, aim, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without warn_index should not match aim, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without warn_runs is not flagged as aim", func(t *testing.T) {
		body := `{"telemetry_enabled":0,"warn_index":false,"name":"x"}`
		if res := runTrackingModule(t, aim, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without warn_runs should not match aim, got %d findings", len(res.Findings))
		}
	})

	t.Run("a determined master is flagged with its version and cluster id", func(t *testing.T) {
		res := runTrackingModule(t, determined, 200, determinedMaster)
		if len(res.Findings) == 0 {
			t.Fatal("expected a determined finding")
		}
		if v := trackingExtract(res, "determined_version"); v != "0.27.1" {
			t.Errorf("determined_version=%q, want 0.27.1", v)
		}
		if v := trackingExtract(res, "determined_cluster_id"); v != "a1b2c3d4-e5f6-7890" {
			t.Errorf("determined_cluster_id=%q, want a1b2c3d4-e5f6-7890", v)
		}
	})

	t.Run("a cluster info without a master_id is not flagged as determined", func(t *testing.T) {
		body := `{"cluster_id":"x","cluster_name":"y","version":"1.0"}`
		if res := runTrackingModule(t, determined, 200, body); len(res.Findings) > 0 {
			t.Errorf("a masterless cluster info should not match determined, got %d findings", len(res.Findings))
		}
	})

	t.Run("a master without a cluster_id is not flagged as determined", func(t *testing.T) {
		body := `{"master_id":"x","cluster_name":"y","version":"1.0"}`
		if res := runTrackingModule(t, determined, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without cluster_id should not match determined, got %d findings", len(res.Findings))
		}
	})

	t.Run("a master without a cluster_name is not flagged as determined", func(t *testing.T) {
		body := `{"master_id":"x","cluster_id":"y","version":"1.0"}`
		if res := runTrackingModule(t, determined, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without cluster_name should not match determined, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{mlflow, tensorboard, aim, determined} {
			if res := runTrackingModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{mlflow, tensorboard, aim, determined} {
			if res := runTrackingModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
