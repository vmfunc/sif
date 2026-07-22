package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runHAProxyStatsModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/haproxy-stats-exposure.yaml")
	if err != nil {
		t.Fatalf("parse haproxy stats module: %v", err)
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
		t.Fatalf("execute haproxy stats module: %v", err)
	}
	return res
}

func haproxyExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestHAProxyStatsExposureModule(t *testing.T) {
	// title and process-info banner text taken verbatim from a live haproxy stats page
	statsBody := `<html><head><title>Statistics Report for HAProxy on formilux</title></head>` +
		`<body><h1>Statistics Report for HAProxy on formilux</h1>` +
		`<h2>&gt; General process information</h2>` +
		`<p><b>HAProxy version 3.5-dev1</b>, released 2026/06/25</p>` +
		`<p>pid = 1314390 (process #1, nbproc = 1, nbthread = 4)</p></body></html>`

	t.Run("an exposed haproxy stats page is flagged and versioned", func(t *testing.T) {
		res := runHAProxyStatsModule(t, 200, statsBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a haproxy stats finding")
		}
		if v := haproxyExtract(res, "haproxy_version"); v != "3.5" {
			t.Errorf("haproxy_version=%q, want 3.5", v)
		}
	})

	t.Run("a basic-auth challenge is not a leak", func(t *testing.T) {
		body := `<html><head><title>401 Unauthorized</title></head>` +
			`<body><h1>401 Unauthorized</h1>You need a valid user and password to access this content.</body></html>`
		if res := runHAProxyStatsModule(t, 401, body); len(res.Findings) > 0 {
			t.Errorf("a 401 stats auth challenge should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page merely mentioning haproxy is not a leak", func(t *testing.T) {
		// prose that names haproxy but is not the stats page itself
		body := `<html><body><h1>Our load balancer</h1>` +
			`<p>We run HAProxy version 2.8 behind nginx for high availability.</p></body></html>`
		if res := runHAProxyStatsModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose mentioning haproxy version should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a stats title without the version banner is not enough", func(t *testing.T) {
		// shares the title anchor but not the version banner, proving both are load-bearing
		body := `<html><head><title>Statistics Report for something else</title></head>` +
			`<body>Statistics Report for pid 1 on host</body></html>`
		if res := runHAProxyStatsModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a title-only page should not match without the version banner, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runHAProxyStatsModule(t, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})
}
