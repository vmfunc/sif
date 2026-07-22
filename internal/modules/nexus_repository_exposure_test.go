package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runNexusRepositoryModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/nexus-repository-exposure.yaml")
	if err != nil {
		t.Fatalf("parse nexus repository module: %v", err)
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
		t.Fatalf("execute nexus repository module: %v", err)
	}
	return res
}

func nexusExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestNexusRepositoryExposureModule(t *testing.T) {
	// real nexus rest catalog shape: name, format, type, url with the /repository/ content path
	catalogBody := `[{"name":"maven-central","format":"maven2","type":"proxy",` +
		`"url":"https://nexus.example.com/repository/maven-central"},` +
		`{"name":"npm-hosted","format":"npm","type":"hosted",` +
		`"url":"https://nexus.example.com/repository/npm-hosted"}]`

	t.Run("an exposed nexus repository catalog is flagged and names extracted", func(t *testing.T) {
		res := runNexusRepositoryModule(t, 200, catalogBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nexus repository finding")
		}
		if v := nexusExtract(res, "nexus_repository_names"); v != "maven-central" {
			t.Errorf("nexus_repository_names=%q, want maven-central", v)
		}
	})

	t.Run("an anonymous-disabled nexus returning 401 is not a leak", func(t *testing.T) {
		body := `{"format":"basic","type":"realm","errors":[{"id":"*","message":"authentication required"}]}`
		if res := runNexusRepositoryModule(t, 401, body); len(res.Findings) > 0 {
			t.Errorf("a 401 auth-required response should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a catalog without repository content urls is not flagged", func(t *testing.T) {
		// shares format and type but the url is not a /repository/ content path
		body := `[{"name":"thing","format":"maven2","type":"proxy",` +
			`"url":"https://example.com/service/rest/v1/status"}]`
		if res := runNexusRepositoryModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a catalog without a /repository/ url should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unrelated json api with format and type is not nexus", func(t *testing.T) {
		body := `{"format":"json","type":"object","data":[]}`
		if res := runNexusRepositoryModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic json with format and type should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runNexusRepositoryModule(t, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})
}
