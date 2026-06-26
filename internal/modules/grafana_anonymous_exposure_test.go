package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runGrafanaModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func grafanaExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestGrafanaAnonymousExposureModule(t *testing.T) {
	const grafana = "../../modules/recon/grafana-anonymous-exposure.yaml"

	t.Run("an anonymous search result is flagged with a dashboard title", func(t *testing.T) {
		body := `[{"id":1,"uid":"abc123","title":"Production Overview","uri":"db/production-overview",` +
			`"url":"/d/abc123/production-overview","slug":"","type":"dash-db","tags":["prod"],` +
			`"isStarred":false,"sortMeta":0}]`
		res := runGrafanaModule(t, grafana, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a grafana finding")
		}
		if v := grafanaExtract(res, "grafana_dashboard"); v != "Production Overview" {
			t.Errorf("grafana_dashboard=%q, want Production Overview", v)
		}
	})

	t.Run("a folder-only result is not flagged", func(t *testing.T) {
		body := `[{"id":1,"uid":"f","title":"General","uri":"db/general","url":"/dashboards/f/general",` +
			`"type":"dash-folder","isStarred":false}]`
		if res := runGrafanaModule(t, grafana, 200, body); len(res.Findings) > 0 {
			t.Errorf("a folder-only search should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a dash-db result without isStarred is not flagged", func(t *testing.T) {
		body := `[{"uid":"abc","title":"x","uri":"db/x","type":"dash-db"}]`
		if res := runGrafanaModule(t, grafana, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial search blob should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a login-required grafana is not flagged", func(t *testing.T) {
		body := `{"message":"Unauthorized"}`
		if res := runGrafanaModule(t, grafana, 401, body); len(res.Findings) > 0 {
			t.Errorf("a 401 grafana should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runGrafanaModule(t, grafana, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runGrafanaModule(t, grafana, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
