package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runTempoSearchModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/tempo-search-exposure.yaml")
	if err != nil {
		t.Fatalf("parse tempo search module: %v", err)
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
		t.Fatalf("execute tempo search module: %v", err)
	}
	return res
}

func tempoSearchExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestTempoSearchExposureModule(t *testing.T) {
	tempoSearchBody := `{"traces":[{"traceID":"a1b2c3d4e5f60123","rootServiceName":"checkout-service",` +
		`"rootTraceName":"POST /api/checkout","startTimeUnixNano":"1700000000000000000","durationMs":842,` +
		`"spanSets":[{"spans":[{"spanID":"1122334455667788","startTimeUnixNano":"1700000000000000000",` +
		`"durationNanos":"842000000"}],"matched":1}]}],` +
		`"metrics":{"inspectedTraces":128,"inspectedBytes":"4096","totalBlocks":3}}`

	t.Run("an exposed tempo search endpoint is flagged and the root service is extracted", func(t *testing.T) {
		res := runTempoSearchModule(t, 200, tempoSearchBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tempo search finding")
		}
		if v := tempoSearchExtract(res, "tempo_root_service"); v != "checkout-service" {
			t.Errorf("tempo_root_service=%q, want checkout-service", v)
		}
	})

	t.Run("a traceID without rootServiceName or rootTraceName is not flagged", func(t *testing.T) {
		body := `{"traces":[{"traceID":"a1b2c3d4e5f60123","startTimeUnixNano":"1700000000000000000"}]}`
		if res := runTempoSearchModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare traceID should not match tempo, got %d findings", len(res.Findings))
		}
	})

	t.Run("a rootServiceName without a traceID is not flagged", func(t *testing.T) {
		body := `{"rootServiceName":"checkout-service","rootTraceName":"POST /api/checkout"}`
		if res := runTempoSearchModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a rootServiceName without a traceID should not match tempo, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unauthorized response is not a leak", func(t *testing.T) {
		body := `{"status":"error","message":"unauthorized"}`
		if res := runTempoSearchModule(t, 401, body); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runTempoSearchModule(t, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runTempoSearchModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
