package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runPipelineModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func pipelineExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDataPipelineAPIExposureModules(t *testing.T) {
	const airflow = "../../modules/recon/airflow-api-exposure.yaml"
	const flink = "../../modules/recon/flink-api-exposure.yaml"
	const kafka = "../../modules/recon/kafka-connect-api-exposure.yaml"

	airflowHealth := `{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy",` +
		`"latest_scheduler_heartbeat":"2023-09-13T09:35:49.123456+00:00"}}`

	flinkOverview := `{"taskmanagers":1,"slots-total":4,"slots-available":4,"jobs-running":0,` +
		`"jobs-finished":2,"jobs-cancelled":0,"jobs-failed":0,"flink-version":"1.17.1","flink-commit":"2750d5c"}`

	kafkaConnect := `{"version":"3.5.0","commit":"c97b88d5db4de28d","kafka_cluster_id":"M_oad8FjQ1eMShri6_jjQg"}`

	t.Run("an exposed airflow health endpoint is flagged", func(t *testing.T) {
		res := runPipelineModule(t, airflow, 200, airflowHealth)
		if len(res.Findings) == 0 {
			t.Fatal("expected an airflow finding")
		}
		if v := pipelineExtract(res, "airflow_scheduler_heartbeat"); v != "2023-09-13T09:35:49.123456+00:00" {
			t.Errorf("airflow_scheduler_heartbeat=%q, want the heartbeat timestamp", v)
		}
	})

	t.Run("an exposed flink dashboard is flagged and versioned", func(t *testing.T) {
		res := runPipelineModule(t, flink, 200, flinkOverview)
		if len(res.Findings) == 0 {
			t.Fatal("expected a flink finding")
		}
		if v := pipelineExtract(res, "flink_version"); v != "1.17.1" {
			t.Errorf("flink_version=%q, want 1.17.1", v)
		}
	})

	t.Run("an exposed kafka connect api is flagged and versioned", func(t *testing.T) {
		res := runPipelineModule(t, kafka, 200, kafkaConnect)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kafka connect finding")
		}
		if v := pipelineExtract(res, "kafka_version"); v != "3.5.0" {
			t.Errorf("kafka_version=%q, want 3.5.0", v)
		}
	})

	t.Run("an airflow metadatabase without a scheduler is not flagged", func(t *testing.T) {
		body := `{"metadatabase":{"status":"healthy"}}`
		if res := runPipelineModule(t, airflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("metadatabase alone should not match airflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("an airflow scheduler without a metadatabase is not flagged", func(t *testing.T) {
		body := `{"scheduler":{"status":"healthy","latest_scheduler_heartbeat":"2023-09-13T09:35:49.123456+00:00"}}`
		if res := runPipelineModule(t, airflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("scheduler alone should not match airflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a flink version without a slot total is not flagged", func(t *testing.T) {
		body := `{"flink-version":"1.17.1","taskmanagers":1}`
		if res := runPipelineModule(t, flink, 200, body); len(res.Findings) > 0 {
			t.Errorf("flink version alone should not match flink, got %d findings", len(res.Findings))
		}
	})

	t.Run("a slot total without a flink version is not flagged", func(t *testing.T) {
		body := `{"slots-total":4,"jobs-running":0}`
		if res := runPipelineModule(t, flink, 200, body); len(res.Findings) > 0 {
			t.Errorf("a slot total alone should not match flink, got %d findings", len(res.Findings))
		}
	})

	t.Run("a kafka cluster id without a version is not flagged", func(t *testing.T) {
		body := `{"kafka_cluster_id":"M_oad8FjQ1eMShri6_jjQg","commit":"abc"}`
		if res := runPipelineModule(t, kafka, 200, body); len(res.Findings) > 0 {
			t.Errorf("a cluster id alone should not match kafka connect, got %d findings", len(res.Findings))
		}
	})

	t.Run("a version without a kafka cluster id is not flagged", func(t *testing.T) {
		body := `{"version":"3.5.0","name":"someservice"}`
		if res := runPipelineModule(t, kafka, 200, body); len(res.Findings) > 0 {
			t.Errorf("a version alone should not match kafka connect, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic health json is not airflow", func(t *testing.T) {
		body := `{"status":"UP","components":{"db":{"status":"UP"}}}`
		if res := runPipelineModule(t, airflow, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic health should not match airflow, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{airflow, flink, kafka} {
			if res := runPipelineModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{airflow, flink, kafka} {
			if res := runPipelineModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
