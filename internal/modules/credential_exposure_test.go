package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runCredModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func credExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestCredentialExposureModules(t *testing.T) {
	const aws = "../../modules/recon/aws-credentials-exposure.yaml"
	const npmrc = "../../modules/recon/npmrc-exposure.yaml"
	const docker = "../../modules/recon/docker-config-exposure.yaml"

	t.Run("aws credentials leak the access key id", func(t *testing.T) {
		body := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
		res := runCredModule(t, aws, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an aws credentials finding")
		}
		if v := credExtract(res, "aws_access_key_id"); v != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("aws_access_key_id=%q, want AKIAIOSFODNN7EXAMPLE", v)
		}
	})

	t.Run("npmrc leaks the registry of an auth token", func(t *testing.T) {
		body := "//registry.npmjs.org/:_authToken=npm_AbCdEf0123456789AbCdEf0123456789\n"
		res := runCredModule(t, npmrc, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an npmrc finding")
		}
		if v := credExtract(res, "npm_registry"); v != "registry.npmjs.org" {
			t.Errorf("npm_registry=%q, want registry.npmjs.org", v)
		}
	})

	t.Run("docker config leaks the registry host", func(t *testing.T) {
		body := `{"auths":{"registry.example.com":{"auth":"dXNlcm5hbWU6c3VwZXJzZWNyZXRwYXNz"}}}`
		res := runCredModule(t, docker, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a docker config finding")
		}
		if v := credExtract(res, "docker_registry"); v != "registry.example.com" {
			t.Errorf("docker_registry=%q, want registry.example.com", v)
		}
	})

	t.Run("html page mentioning the key name is not a leak", func(t *testing.T) {
		body := `<html><head><title>Docs</title></head><body>` +
			`set your aws_secret_access_key in ~/.aws/credentials</body></html>`
		if res := runCredModule(t, aws, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html doc mentioning the key should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{aws, npmrc, docker} {
			if res := runCredModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{aws, npmrc, docker} {
			if res := runCredModule(t, file, 200, "nothing to see here"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a docker auth field holding a jwt is not a leak", func(t *testing.T) {
		body := `{"token":"x","auth":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`
		if res := runCredModule(t, docker, 200, body); len(res.Findings) > 0 {
			t.Errorf("a jwt in an auth field should not match, got %d findings", len(res.Findings))
		}
	})
}
