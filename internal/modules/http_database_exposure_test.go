package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runHTTPDBModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func httpdbExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestHTTPDatabaseExposureModules(t *testing.T) {
	const influxdb = "../../modules/recon/influxdb-api-exposure.yaml"
	const arangodb = "../../modules/recon/arangodb-api-exposure.yaml"
	const neo4j = "../../modules/recon/neo4j-api-exposure.yaml"

	influxHealth := `{"name":"influxdb","message":"ready for queries and writes","status":"pass",` +
		`"checks":[],"version":"2.9.1","commit":"a1b2c3d4"}`

	arangoVersion := `{"server":"arango","version":"3.11.5","license":"community"}`

	neo4jDiscovery := `{"bolt_routing":"neo4j://localhost:7687","transaction":"http://localhost:7474/db/{databaseName}/tx",` +
		`"bolt_direct":"bolt://localhost:7687","neo4j_version":"5.13.0","neo4j_edition":"community"}`

	t.Run("an exposed influxdb health endpoint is flagged and versioned", func(t *testing.T) {
		res := runHTTPDBModule(t, influxdb, 200, influxHealth)
		if len(res.Findings) == 0 {
			t.Fatal("expected an influxdb finding")
		}
		if v := httpdbExtract(res, "influxdb_version"); v != "2.9.1" {
			t.Errorf("influxdb_version=%q, want 2.9.1", v)
		}
	})

	t.Run("an anonymous arangodb version endpoint is flagged and versioned", func(t *testing.T) {
		res := runHTTPDBModule(t, arangodb, 200, arangoVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected an arangodb finding")
		}
		if v := httpdbExtract(res, "arangodb_version"); v != "3.11.5" {
			t.Errorf("arangodb_version=%q, want 3.11.5", v)
		}
	})

	t.Run("an exposed neo4j discovery endpoint is flagged and versioned", func(t *testing.T) {
		res := runHTTPDBModule(t, neo4j, 200, neo4jDiscovery)
		if len(res.Findings) == 0 {
			t.Fatal("expected a neo4j finding")
		}
		if v := httpdbExtract(res, "neo4j_version"); v != "5.13.0" {
			t.Errorf("neo4j_version=%q, want 5.13.0", v)
		}
	})

	t.Run("an influxdb name without the health message is not flagged", func(t *testing.T) {
		body := `{"name":"influxdb","status":"pass"}`
		if res := runHTTPDBModule(t, influxdb, 200, body); len(res.Findings) > 0 {
			t.Errorf("an influxdb name alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a health message without the influxdb name is not flagged", func(t *testing.T) {
		body := `{"name":"telegraf","message":"ready for queries and writes"}`
		if res := runHTTPDBModule(t, influxdb, 200, body); len(res.Findings) > 0 {
			t.Errorf("the message alone should not match influxdb, got %d findings", len(res.Findings))
		}
	})

	t.Run("an arango without a license field is still flagged", func(t *testing.T) {
		body := `{"server":"arango","version":"3.11.5"}`
		res := runHTTPDBModule(t, arangodb, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an arangodb finding without a license field (pre-3.12)")
		}
		if v := httpdbExtract(res, "arangodb_version"); v != "3.11.5" {
			t.Errorf("arangodb_version=%q, want 3.11.5", v)
		}
	})

	t.Run("a non-arango version response is not flagged", func(t *testing.T) {
		body := `{"server":"foundationdb","version":"1.0.0"}`
		if res := runHTTPDBModule(t, arangodb, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-arango server should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an arango response without a version is not flagged", func(t *testing.T) {
		body := `{"server":"arango"}`
		if res := runHTTPDBModule(t, arangodb, 200, body); len(res.Findings) > 0 {
			t.Errorf("an arango without a version should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an arango that requires auth is not flagged", func(t *testing.T) {
		if res := runHTTPDBModule(t, arangodb, 401, arangoVersion); len(res.Findings) > 0 {
			t.Errorf("a 401 arango should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a neo4j version without an edition is not flagged", func(t *testing.T) {
		body := `{"neo4j_version":"5.13.0","transaction":"http://localhost:7474/db/neo4j/tx"}`
		if res := runHTTPDBModule(t, neo4j, 200, body); len(res.Findings) > 0 {
			t.Errorf("a neo4j version alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a neo4j edition without a version is not flagged", func(t *testing.T) {
		body := `{"neo4j_edition":"community","bolt_routing":"neo4j://localhost:7687"}`
		if res := runHTTPDBModule(t, neo4j, 200, body); len(res.Findings) > 0 {
			t.Errorf("a neo4j edition alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic health json is not influxdb", func(t *testing.T) {
		body := `{"status":"UP","components":{"db":{"status":"UP"}}}`
		if res := runHTTPDBModule(t, influxdb, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic health should not match influxdb, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{influxdb, arangodb, neo4j} {
			if res := runHTTPDBModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{influxdb, arangodb, neo4j} {
			if res := runHTTPDBModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
