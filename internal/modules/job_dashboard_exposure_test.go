package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runJobDashModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func jobDashExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestJobDashboardExposureModules(t *testing.T) {
	const sidekiq = "../../modules/recon/sidekiq-web-exposure.yaml"
	const flower = "../../modules/recon/celery-flower-exposure.yaml"
	const rq = "../../modules/recon/rq-dashboard-exposure.yaml"

	t.Run("a sidekiq stats dump is flagged with its redis version", func(t *testing.T) {
		body := `{"sidekiq":{"processed":12345,"failed":67,"busy":3,"processes":2,"enqueued":10,` +
			`"scheduled":5,"retries":1,"dead":0,"default_latency":0},"redis":{"redis_version":"7.2.4",` +
			`"uptime_in_days":"12","connected_clients":"8","used_memory_human":"2.50M",` +
			`"used_memory_peak_human":"3.10M"},"server_utc_time":"18:00:00 UTC"}`
		res := runJobDashModule(t, sidekiq, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a sidekiq finding")
		}
		if v := jobDashExtract(res, "redis_version"); v != "7.2.4" {
			t.Errorf("redis_version=%q, want 7.2.4", v)
		}
	})

	t.Run("a bare redis-info body without default_latency is not flagged as sidekiq", func(t *testing.T) {
		if res := runJobDashModule(t, sidekiq, 200, `{"redis_version":"7.2.4","server_utc_time":"x"}`); len(res.Findings) > 0 {
			t.Errorf("a redis info blob should not match sidekiq, got %d findings", len(res.Findings))
		}
	})

	t.Run("a flower workers api is flagged with the celery version", func(t *testing.T) {
		body := `{"celery@worker1":{"active_queues":[{"name":"celery","exchange":{"name":"celery",` +
			`"type":"direct"},"routing_key":"celery"}],"conf":{"broker_url":"redis://localhost:6379/0",` +
			`"result_backend":"redis://localhost:6379/0"},"registered":["tasks.add","tasks.send_email"],` +
			`"stats":{"sw_ident":"py-celery","sw_ver":"5.3.6","sw_sys":"Linux","pool":{"max-concurrency":4},` +
			`"broker":{"hostname":"localhost","transport":"redis"}},"timestamp":1719345600.0}}`
		res := runJobDashModule(t, flower, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a flower finding")
		}
		if v := jobDashExtract(res, "celery_version"); v != "5.3.6" {
			t.Errorf("celery_version=%q, want 5.3.6", v)
		}
	})

	t.Run("a worker blob without conf is not flagged as flower", func(t *testing.T) {
		if res := runJobDashModule(t, flower, 200, `{"celery@w":{"active_queues":[],"registered":["tasks.add"]}}`); len(res.Findings) > 0 {
			t.Errorf("a confless worker blob should not match flower, got %d findings", len(res.Findings))
		}
	})

	t.Run("an rq queues dump is flagged with the first queue name", func(t *testing.T) {
		body := `{"queues":[{"name":"default","count":42,"queued_url":"/0/view/jobs/default/queued/...",` +
			`"failed_job_registry_count":3,"failed_url":"...","started_job_registry_count":1,"started_url":"...",` +
			`"deferred_job_registry_count":0,"deferred_url":"...","finished_job_registry_count":100,` +
			`"finished_url":"...","canceled_job_registry_count":0,"canceled_url":"...",` +
			`"scheduled_job_registry_count":5,"scheduled_url":"..."}]}`
		res := runJobDashModule(t, rq, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an rq finding")
		}
		if v := jobDashExtract(res, "rq_queue_name"); v != "default" {
			t.Errorf("rq_queue_name=%q, want default", v)
		}
	})

	t.Run("a queues blob without the registry counts is not flagged as rq", func(t *testing.T) {
		if res := runJobDashModule(t, rq, 200, `{"queues":[{"name":"q","failed_job_registry_count":0}]}`); len(res.Findings) > 0 {
			t.Errorf("a partial queues blob should not match rq, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{sidekiq, flower, rq} {
			if res := runJobDashModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{sidekiq, flower, rq} {
			if res := runJobDashModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
