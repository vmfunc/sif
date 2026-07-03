package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runPulsarModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func TestPulsarMetricsExposureModule(t *testing.T) {
	const pulsar = "../../modules/recon/pulsar-metrics-exposure.yaml"

	t.Run("a pulsar broker metrics page is flagged", func(t *testing.T) {
		body := "# HELP pulsar_topics_count number of topics owned by this broker\n" +
			"# TYPE pulsar_topics_count gauge\n" +
			"pulsar_topics_count{cluster=\"standalone\"} 12\n" +
			"# HELP pulsar_subscriptions_count number of pulsar subscriptions\n" +
			"# TYPE pulsar_subscriptions_count gauge\n" +
			"pulsar_subscriptions_count{cluster=\"standalone\"} 4\n"
		res := runPulsarModule(t, pulsar, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a pulsar finding")
		}
	})

	t.Run("topics count without a TYPE line is not flagged", func(t *testing.T) {
		body := "pulsar_topics_count{cluster=\"standalone\"} 12\n" +
			"pulsar_subscriptions_count{cluster=\"standalone\"} 4\n"
		if res := runPulsarModule(t, pulsar, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without a prometheus TYPE line should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unrelated prometheus exporter is not flagged", func(t *testing.T) {
		body := "# HELP node_cpu_seconds_total seconds the cpus spent in each mode\n" +
			"# TYPE node_cpu_seconds_total counter\n" +
			"node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 12345\n"
		if res := runPulsarModule(t, pulsar, 200, body); len(res.Findings) > 0 {
			t.Errorf("node_exporter output should not match pulsar, got %d findings", len(res.Findings))
		}
	})

	t.Run("only subscriptions count without topics count is not flagged", func(t *testing.T) {
		body := "# TYPE pulsar_subscriptions_count gauge\n" +
			"pulsar_subscriptions_count{cluster=\"standalone\"} 4\n"
		if res := runPulsarModule(t, pulsar, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial metric set should not match pulsar, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 401 is not a leak", func(t *testing.T) {
		if res := runPulsarModule(t, pulsar, 401, "Unauthorized"); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runPulsarModule(t, pulsar, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
