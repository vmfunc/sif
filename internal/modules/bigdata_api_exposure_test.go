package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runBigDataModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func bigDataExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestBigDataAPIExposureModules(t *testing.T) {
	const solr = "../../modules/recon/solr-api-exposure.yaml"
	const spark = "../../modules/recon/spark-api-exposure.yaml"
	const hadoop = "../../modules/recon/hadoop-yarn-api-exposure.yaml"

	solrSystem := `{"responseHeader":{"status":0,"QTime":15},"mode":"std",` +
		`"solr_home":"/var/solr/data","lucene":{"solr-spec-version":"9.4.0",` +
		`"solr-impl-version":"9.4.0","lucene-spec-version":"9.8.0","lucene-impl-version":"9.8.0"},` +
		`"jvm":{"version":"17.0.9"}}`

	sparkState := `{"url":"spark://master:7077","workers":[{"id":"worker-1","host":"10.0.0.5"}],` +
		`"aliveworkers":2,"cores":8,"coresused":0,"memory":15360,"activeapps":[],` +
		`"completedapps":[],"status":"ALIVE"}`

	hadoopInfo := `{"clusterInfo":{"id":1700000000000,"startedOn":1700000000000,"state":"STARTED",` +
		`"haState":"ACTIVE","resourceManagerVersion":"3.3.6","resourceManagerBuildVersion":"3.3.6 from abc",` +
		`"hadoopVersion":"3.3.6","hadoopBuildVersion":"3.3.6 from abc","hadoopVersionBuiltOn":"2023-06-18"}}`

	t.Run("an exposed solr admin api is flagged and versioned", func(t *testing.T) {
		res := runBigDataModule(t, solr, 200, solrSystem)
		if len(res.Findings) == 0 {
			t.Fatal("expected a solr finding")
		}
		if v := bigDataExtract(res, "solr_version"); v != "9.4.0" {
			t.Errorf("solr_version=%q, want 9.4.0", v)
		}
	})

	t.Run("an exposed spark master leaks its url", func(t *testing.T) {
		res := runBigDataModule(t, spark, 200, sparkState)
		if len(res.Findings) == 0 {
			t.Fatal("expected a spark finding")
		}
		if v := bigDataExtract(res, "spark_master_url"); v != "spark://master:7077" {
			t.Errorf("spark_master_url=%q, want spark://master:7077", v)
		}
	})

	t.Run("an exposed hadoop yarn api is flagged and versioned", func(t *testing.T) {
		res := runBigDataModule(t, hadoop, 200, hadoopInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a hadoop finding")
		}
		if v := bigDataExtract(res, "hadoop_version"); v != "3.3.6" {
			t.Errorf("hadoop_version=%q, want 3.3.6", v)
		}
	})

	t.Run("a solr spec version without a solr home is not solr", func(t *testing.T) {
		body := `{"lucene":{"solr-spec-version":"9.4.0"},"name":"otherservice"}`
		if res := runBigDataModule(t, solr, 200, body); len(res.Findings) > 0 {
			t.Errorf("spec version alone should not match solr, got %d findings", len(res.Findings))
		}
	})

	t.Run("a solr home without a spec version is not solr", func(t *testing.T) {
		body := `{"solr_home":"/var/solr/data","mode":"std"}`
		if res := runBigDataModule(t, solr, 200, body); len(res.Findings) > 0 {
			t.Errorf("solr home alone should not match solr, got %d findings", len(res.Findings))
		}
	})

	t.Run("a spark url without alive workers is not flagged", func(t *testing.T) {
		body := `{"url":"spark://master:7077","workers":[],"status":"ALIVE"}`
		if res := runBigDataModule(t, spark, 200, body); len(res.Findings) > 0 {
			t.Errorf("a spark url alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("alive workers behind a non spark url is not flagged", func(t *testing.T) {
		body := `{"url":"http://internal:8080","aliveworkers":2}`
		if res := runBigDataModule(t, spark, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non spark url should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a cluster info without a resource manager version is not hadoop", func(t *testing.T) {
		body := `{"clusterInfo":{"id":1,"state":"STARTED","hadoopVersion":"3.3.6"}}`
		if res := runBigDataModule(t, hadoop, 200, body); len(res.Findings) > 0 {
			t.Errorf("cluster info alone should not match hadoop, got %d findings", len(res.Findings))
		}
	})

	t.Run("a resource manager version without a cluster info is not hadoop", func(t *testing.T) {
		body := `{"resourceManagerVersion":"3.3.6","app":"custom"}`
		if res := runBigDataModule(t, hadoop, 200, body); len(res.Findings) > 0 {
			t.Errorf("rm version alone should not match hadoop, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic json endpoint is not a spark master", func(t *testing.T) {
		body := `{"url":"http://app","workers":5,"name":"myservice"}`
		if res := runBigDataModule(t, spark, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic json should not match spark, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{solr, spark, hadoop} {
			if res := runBigDataModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{solr, spark, hadoop} {
			if res := runBigDataModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
