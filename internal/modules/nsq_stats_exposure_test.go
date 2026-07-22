package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runNSQModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func nsqExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestNSQStatsExposureModule(t *testing.T) {
	const nsq = "../../modules/recon/nsq-stats-exposure.yaml"

	t.Run("an nsqd stats response is flagged with its version", func(t *testing.T) {
		body := `{"version":"1.3.0","health":"OK","start_time":1717000000,"topics":[` +
			`{"topic_name":"orders","channels":[{"channel_name":"billing","depth":0,` +
			`"backend_depth":0,"in_flight_count":0,"message_count":1204,"clients":[` +
			`{"client_id":"worker-1","remote_address":"10.0.4.12:51322"}]}],` +
			`"depth":0,"message_count":1204}],"producers":[],` +
			`"memory":{"heap_objects":1024}}`
		res := runNSQModule(t, nsq, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an nsq finding")
		}
		if v := nsqExtract(res, "nsq_version"); v != "1.3.0" {
			t.Errorf("nsq_version=%q, want 1.3.0", v)
		}
	})

	t.Run("a version and topics without health and start_time is not flagged", func(t *testing.T) {
		body := `{"version":"1.3.0","topics":[{"topic_name":"orders"}]}`
		if res := runNSQModule(t, nsq, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial body should not match nsq, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unhealthy status value is not flagged", func(t *testing.T) {
		body := `{"version":"1.3.0","health":"NOK: no topics","start_time":1717000000,"topics":[]}`
		if res := runNSQModule(t, nsq, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-OK health value should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic monitoring body is not a leak", func(t *testing.T) {
		body := `{"status":"healthy","version":"3.1.0","uptime_seconds":1234}`
		if res := runNSQModule(t, nsq, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic health body should not match nsq, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 401 login page is not a leak", func(t *testing.T) {
		if res := runNSQModule(t, nsq, 401, "Unauthorized"); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runNSQModule(t, nsq, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
