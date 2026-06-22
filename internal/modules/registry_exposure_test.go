package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runRegistryModule(t *testing.T, file string, status int, headers map[string]string, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
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

func registryExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestRegistryExposureModules(t *testing.T) {
	const dockerRegistry = "../../modules/recon/docker-registry-api-exposure.yaml"
	const harbor = "../../modules/recon/harbor-api-exposure.yaml"

	registryHeader := map[string]string{"Docker-Distribution-Api-Version": "registry/2.0"}

	harborInfo := `{"auth_mode":"db_auth","registry_url":"harbor.example.com",` +
		`"external_url":"https://harbor.example.com","harbor_version":"v2.9.1-1f4a3c9d",` +
		`"self_registration":true,"has_ca_root":false,"read_only":false}`

	t.Run("an anonymous docker registry is flagged with its api version", func(t *testing.T) {
		res := runRegistryModule(t, dockerRegistry, 200, registryHeader, "{}")
		if len(res.Findings) == 0 {
			t.Fatal("expected a docker registry finding")
		}
		if v := registryExtract(res, "docker_registry_api_version"); v != "registry/2.0" {
			t.Errorf("docker_registry_api_version=%q, want registry/2.0", v)
		}
	})

	t.Run("a plain 200 without the registry header is not flagged", func(t *testing.T) {
		if res := runRegistryModule(t, dockerRegistry, 200, nil, "{}"); len(res.Findings) > 0 {
			t.Errorf("a 200 without the api-version header should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a registry that requires auth is not flagged", func(t *testing.T) {
		if res := runRegistryModule(t, dockerRegistry, 401, registryHeader, ""); len(res.Findings) > 0 {
			t.Errorf("a 401 registry should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an exposed harbor systeminfo is flagged and versioned", func(t *testing.T) {
		res := runRegistryModule(t, harbor, 200, nil, harborInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a harbor finding")
		}
		if v := registryExtract(res, "harbor_version"); v != "v2.9.1-1f4a3c9d" {
			t.Errorf("harbor_version=%q, want v2.9.1-1f4a3c9d", v)
		}
	})

	t.Run("a harbor version without an auth mode is not flagged", func(t *testing.T) {
		body := `{"harbor_version":"v2.9.1","registry_url":"harbor.example.com"}`
		if res := runRegistryModule(t, harbor, 200, nil, body); len(res.Findings) > 0 {
			t.Errorf("a harbor version alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an auth mode without a harbor version is not flagged", func(t *testing.T) {
		body := `{"auth_mode":"db_auth","self_registration":true}`
		if res := runRegistryModule(t, harbor, 200, nil, body); len(res.Findings) > 0 {
			t.Errorf("an auth mode alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{dockerRegistry, harbor} {
			if res := runRegistryModule(t, file, 200, nil, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{dockerRegistry, harbor} {
			if res := runRegistryModule(t, file, 404, nil, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
