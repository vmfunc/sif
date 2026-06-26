package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDBHTTPModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func dbHTTPExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDatabaseHTTPExposureModules(t *testing.T) {
	const clickhouse = "../../modules/recon/clickhouse-http-exposure.yaml"
	const dgraph = "../../modules/recon/dgraph-api-exposure.yaml"

	t.Run("a clickhouse FORMAT JSON result is flagged with the version", func(t *testing.T) {
		body := `{"meta":[{"name":"version()","type":"String"}],"data":[{"version()":"24.3.1.2672"}],` +
			`"rows":1,"statistics":{"elapsed":0.000123,"rows_read":1,"bytes_read":1}}`
		res := runDBHTTPModule(t, clickhouse, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a clickhouse finding")
		}
		if v := dbHTTPExtract(res, "clickhouse_version"); v != "24.3.1.2672" {
			t.Errorf("clickhouse_version=%q, want 24.3.1.2672", v)
		}
	})

	t.Run("a json result without the statistics envelope is not flagged as clickhouse", func(t *testing.T) {
		body := `{"meta":[{"name":"x"}],"data":[{"x":1}],"rows":1}`
		if res := runDBHTTPModule(t, clickhouse, 200, body); len(res.Findings) > 0 {
			t.Errorf("a statless json result should not match clickhouse, got %d findings", len(res.Findings))
		}
	})

	t.Run("a dgraph alpha health is flagged with its version", func(t *testing.T) {
		body := `[{"instance":"alpha","address":"localhost:7080","status":"healthy","group":"0",` +
			`"version":"v23.1.0","uptime":3600,"lastEcho":1700000000,"ongoing":["opRollup"],"max_assigned":30002}]`
		res := runDBHTTPModule(t, dgraph, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a dgraph finding")
		}
		if v := dbHTTPExtract(res, "dgraph_version"); v != "v23.1.0" {
			t.Errorf("dgraph_version=%q, want v23.1.0", v)
		}
	})

	t.Run("a dgraph alpha health without max_assigned is not flagged", func(t *testing.T) {
		body := `[{"instance":"alpha","status":"healthy","lastEcho":1700000000}]`
		if res := runDBHTTPModule(t, dgraph, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial alpha health should not match dgraph, got %d findings", len(res.Findings))
		}
	})

	t.Run("a non-alpha instance health is not flagged as dgraph", func(t *testing.T) {
		body := `[{"instance":"zero","max_assigned":30002,"lastEcho":1700000000}]`
		if res := runDBHTTPModule(t, dgraph, 200, body); len(res.Findings) > 0 {
			t.Errorf("a zero-node health should not match dgraph alpha, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{clickhouse, dgraph} {
			if res := runDBHTTPModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 403 or 404 is not a leak", func(t *testing.T) {
		if res := runDBHTTPModule(t, clickhouse, 403, "Authentication failed"); len(res.Findings) > 0 {
			t.Errorf("a 403 clickhouse should not match, got %d findings", len(res.Findings))
		}
		for _, file := range []string{clickhouse, dgraph} {
			if res := runDBHTTPModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
