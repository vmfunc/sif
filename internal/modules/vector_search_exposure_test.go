package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runVectorSearchModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func vectorSearchExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestVectorSearchExposureModules(t *testing.T) {
	const marqo = "../../modules/recon/marqo-exposure.yaml"
	const vespa = "../../modules/recon/vespa-status-exposure.yaml"
	const meilisearch = "../../modules/recon/meilisearch-exposure.yaml"

	marqoRoot := `{"message":"Welcome to Marqo","version":"2.11.0"}`

	vespaStatus := `{"application":{"vespa":{"version":"8.43.64"},"meta":{"name":"default","generation":11}},` +
		`"abstractComponents":[],"handlers":[],"clients":[],"servers":[],"httpRequestFilters":[],` +
		`"httpResponseFilters":[],"processingChains":[]}`

	meiliVersion := `{"commitSha":"b46889b5","commitDate":"2026-01-15T00:00:00Z","pkgVersion":"1.12.0"}`

	t.Run("a marqo root is flagged with its version", func(t *testing.T) {
		res := runVectorSearchModule(t, marqo, 200, marqoRoot)
		if len(res.Findings) == 0 {
			t.Fatal("expected a marqo finding")
		}
		if v := vectorSearchExtract(res, "marqo_version"); v != "2.11.0" {
			t.Errorf("marqo_version=%q, want 2.11.0", v)
		}
	})

	t.Run("a generic root with a version is not flagged as marqo", func(t *testing.T) {
		body := `{"message":"Welcome","version":"2.11.0","service":"something-else"}`
		if res := runVectorSearchModule(t, marqo, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic welcome should not match marqo, got %d findings", len(res.Findings))
		}
	})

	t.Run("a marqo welcome without a version is not flagged", func(t *testing.T) {
		if res := runVectorSearchModule(t, marqo, 200, `{"message":"Welcome to Marqo"}`); len(res.Findings) > 0 {
			t.Errorf("a versionless welcome should not match marqo, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page mentioning marqo is not flagged", func(t *testing.T) {
		body := `<html><body><h1>Welcome to Marqo</h1><p>version 2.11.0 docs</p></body></html>`
		if res := runVectorSearchModule(t, marqo, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose mentioning marqo should not match the structured response, got %d findings", len(res.Findings))
		}
	})

	t.Run("a vespa status is flagged with its version", func(t *testing.T) {
		res := runVectorSearchModule(t, vespa, 200, vespaStatus)
		if len(res.Findings) == 0 {
			t.Fatal("expected a vespa finding")
		}
		if v := vectorSearchExtract(res, "vespa_version"); v != "8.43.64" {
			t.Errorf("vespa_version=%q, want 8.43.64", v)
		}
	})

	t.Run("a body without abstractComponents is not flagged as vespa", func(t *testing.T) {
		body := `{"handlers":[],"processingChains":[],"httpRequestFilters":[]}`
		if res := runVectorSearchModule(t, vespa, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without abstractComponents should not match vespa, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without processingChains is not flagged as vespa", func(t *testing.T) {
		body := `{"abstractComponents":[],"httpRequestFilters":[]}`
		if res := runVectorSearchModule(t, vespa, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without processingChains should not match vespa, got %d findings", len(res.Findings))
		}
	})

	t.Run("a meilisearch version is flagged", func(t *testing.T) {
		res := runVectorSearchModule(t, meilisearch, 200, meiliVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a meilisearch finding")
		}
		if v := vectorSearchExtract(res, "meilisearch_version"); v != "1.12.0" {
			t.Errorf("meilisearch_version=%q, want 1.12.0", v)
		}
	})

	t.Run("a body without commitSha is not flagged as meilisearch", func(t *testing.T) {
		body := `{"commitDate":"2026","pkgVersion":"1.12.0"}`
		if res := runVectorSearchModule(t, meilisearch, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without commitSha should not match meilisearch, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without pkgVersion is not flagged as meilisearch", func(t *testing.T) {
		body := `{"commitSha":"abc","commitDate":"2026"}`
		if res := runVectorSearchModule(t, meilisearch, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without pkgVersion should not match meilisearch, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{marqo, vespa, meilisearch} {
			if res := runVectorSearchModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{marqo, vespa, meilisearch} {
			if res := runVectorSearchModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
