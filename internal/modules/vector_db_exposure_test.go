package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runVectorDBModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func vectorDBExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestVectorDBExposureModules(t *testing.T) {
	const qdrant = "../../modules/recon/qdrant-api-exposure.yaml"
	const weaviate = "../../modules/recon/weaviate-api-exposure.yaml"
	const chroma = "../../modules/recon/chroma-api-exposure.yaml"

	qdrantCollections := `{"result":{"collections":[{"name":"documents"},{"name":"embeddings"}]},` +
		`"status":"ok","time":0.000018}`

	weaviateMeta := `{"hostname":"http://[::]:8080","modules":{"text2vec-openai":{"version":"v1.0.0"}},` +
		`"version":"1.23.7"}`

	chromaHeartbeat := `{"nanosecond heartbeat":1718900000000000000}`

	t.Run("a qdrant collections api is flagged and named", func(t *testing.T) {
		res := runVectorDBModule(t, qdrant, 200, qdrantCollections)
		if len(res.Findings) == 0 {
			t.Fatal("expected a qdrant finding")
		}
		if v := vectorDBExtract(res, "qdrant_collection"); v != "documents" {
			t.Errorf("qdrant_collection=%q, want documents", v)
		}
	})

	t.Run("a weaviate meta api is flagged with its hostname", func(t *testing.T) {
		res := runVectorDBModule(t, weaviate, 200, weaviateMeta)
		if len(res.Findings) == 0 {
			t.Fatal("expected a weaviate finding")
		}
		if v := vectorDBExtract(res, "weaviate_hostname"); v != "http://[::]:8080" {
			t.Errorf("weaviate_hostname=%q, want http://[::]:8080", v)
		}
	})

	t.Run("a chroma heartbeat api is flagged", func(t *testing.T) {
		res := runVectorDBModule(t, chroma, 200, chromaHeartbeat)
		if len(res.Findings) == 0 {
			t.Fatal("expected a chroma finding")
		}
	})

	t.Run("a qdrant status without a collections result is not flagged", func(t *testing.T) {
		body := `{"result":{"points":[{"id":1}]},"status":"ok","time":0.001}`
		if res := runVectorDBModule(t, qdrant, 200, body); len(res.Findings) > 0 {
			t.Errorf("a points result should not match qdrant, got %d findings", len(res.Findings))
		}
	})

	t.Run("a qdrant collections result without an ok status is not flagged", func(t *testing.T) {
		body := `{"result":{"collections":[{"name":"x"}]}}`
		if res := runVectorDBModule(t, qdrant, 200, body); len(res.Findings) > 0 {
			t.Errorf("a collections result without ok status should not match qdrant, got %d findings", len(res.Findings))
		}
	})

	t.Run("a weaviate meta without a version is not flagged", func(t *testing.T) {
		body := `{"hostname":"http://x:8080","modules":{"a":{}}}`
		if res := runVectorDBModule(t, weaviate, 200, body); len(res.Findings) > 0 {
			t.Errorf("a meta without a version should not match weaviate, got %d findings", len(res.Findings))
		}
	})

	t.Run("a weaviate hostname that is not a url is not flagged", func(t *testing.T) {
		body := `{"hostname":"db-internal","version":"1.23.7"}`
		if res := runVectorDBModule(t, weaviate, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare hostname should not match weaviate, got %d findings", len(res.Findings))
		}
	})

	t.Run("a chroma 200 without the heartbeat key is not flagged", func(t *testing.T) {
		body := `{"heartbeat":1718900000}`
		if res := runVectorDBModule(t, chroma, 200, body); len(res.Findings) > 0 {
			t.Errorf("a plain heartbeat key should not match chroma, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic version json is not a vector db", func(t *testing.T) {
		body := `{"version":"1.0.0","name":"app"}`
		for _, file := range []string{qdrant, weaviate, chroma} {
			if res := runVectorDBModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a generic version should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{qdrant, weaviate, chroma} {
			if res := runVectorDBModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{qdrant, weaviate, chroma} {
			if res := runVectorDBModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
