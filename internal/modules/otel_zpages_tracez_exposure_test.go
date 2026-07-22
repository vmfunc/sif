package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runOtelZpagesTracezModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/otel-zpages-tracez-exposure.yaml")
	if err != nil {
		t.Fatalf("parse otel zpages tracez module: %v", err)
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
		t.Fatalf("execute otel zpages tracez module: %v", err)
	}
	return res
}

func otelZpagesExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestOtelZpagesTracezExposureModule(t *testing.T) {
	tracezBody := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Trace Spans</title></head>` +
		`<body><h1>Trace Spans</h1><table style="border-spacing: 0"><tr>` +
		`<td colspan=1 align=left><b>Span Name</b></td>` +
		`<td colspan=1 align="center"><b>Running</b></td>` +
		`<td colspan=9 align="center"><b>Latency Samples</b></td>` +
		`<td colspan=1 align="center"><b>Error Samples</b></td></tr>` +
		`<tr><td>grpc.Server.Handle</td><td>` +
		`<a href="tracez?zspanname=grpc.Server.Handle&ztype=0">3</a></td>` +
		`<td><a href="tracez?zspanname=grpc.Server.Handle&ztype=1&zlatencybucket=0">12</a></td>` +
		`<td><a href="tracez?zspanname=grpc.Server.Handle&ztype=2&zlatencybucket=0">1</a></td></tr>` +
		`</table></body></html>`

	t.Run("an exposed tracez page is flagged and the span name is extracted", func(t *testing.T) {
		res := runOtelZpagesTracezModule(t, 200, tracezBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tracez finding")
		}
		if v := otelZpagesExtract(res, "otel_span_name"); v != "grpc.Server.Handle" {
			t.Errorf("otel_span_name=%q, want grpc.Server.Handle", v)
		}
	})

	t.Run("a page with only the span name header is not flagged", func(t *testing.T) {
		body := `<html><title>Debug</title><body><b>Span Name</b> some other debug tool</body></html>`
		if res := runOtelZpagesTracezModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a lone Span Name header should not match zpages, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page with the title but no summary table is not flagged", func(t *testing.T) {
		body := `<html><head><title>Trace Spans</title></head><body>no data available</body></html>`
		if res := runOtelZpagesTracezModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare title without the summary table should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unauthorized response is not a leak", func(t *testing.T) {
		if res := runOtelZpagesTracezModule(t, 401, "unauthorized"); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runOtelZpagesTracezModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
