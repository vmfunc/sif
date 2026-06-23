/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runInfraModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func infraExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestInfraConfigExposureModules(t *testing.T) {
	const terraform = "../../modules/recon/terraform-state-exposure.yaml"
	const kubeconfig = "../../modules/recon/kubeconfig-exposure.yaml"
	const compose = "../../modules/recon/docker-compose-exposure.yaml"

	t.Run("terraform state leaks the terraform version", func(t *testing.T) {
		body := `{"version":4,"terraform_version":"1.5.7","serial":12,"lineage":"a1b2",` +
			`"outputs":{},"resources":[{"type":"aws_db_instance","name":"main"}]}`
		res := runInfraModule(t, terraform, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a terraform state finding")
		}
		if v := infraExtract(res, "terraform_version"); v != "1.5.7" {
			t.Errorf("terraform_version=%q, want 1.5.7", v)
		}
	})

	t.Run("terraform state with a pre-release version still extracts the number", func(t *testing.T) {
		body := `{"version":4,"terraform_version":"0.12.0-beta1","serial":1,"lineage":"x","resources":[]}`
		res := runInfraModule(t, terraform, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a terraform state finding")
		}
		if v := infraExtract(res, "terraform_version"); v != "0.12.0" {
			t.Errorf("terraform_version=%q, want 0.12.0", v)
		}
	})

	t.Run("kubeconfig leaks the cluster server", func(t *testing.T) {
		body := "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n" +
			"    server: https://10.0.0.1:6443\n  name: prod\ncurrent-context: prod\n"
		res := runInfraModule(t, kubeconfig, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kubeconfig finding")
		}
		if v := infraExtract(res, "cluster_server"); v != "https://10.0.0.1:6443" {
			t.Errorf("cluster_server=%q, want https://10.0.0.1:6443", v)
		}
	})

	t.Run("docker compose leaks the image version", func(t *testing.T) {
		body := "version: \"3.8\"\nservices:\n  web:\n    image: nginx:1.25\n    ports:\n" +
			"      - \"80:80\"\n  db:\n    image: postgres:15\n"
		res := runInfraModule(t, compose, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a docker compose finding")
		}
		if v := infraExtract(res, "compose_image"); v != "nginx:1.25" {
			t.Errorf("compose_image=%q, want nginx:1.25", v)
		}
	})

	t.Run("a terraform_version mention without the state structure is not a leak", func(t *testing.T) {
		body := `{"terraform_version":"1.5.7"}`
		if res := runInfraModule(t, terraform, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare version mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a kind Config mention without the kubeconfig structure is not a leak", func(t *testing.T) {
		body := "kind: Config\ndescription: an unrelated document\n"
		if res := runInfraModule(t, kubeconfig, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare kind mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a services key without a service definition is not a leak", func(t *testing.T) {
		body := "services: enabled\nnote: not a compose file\n"
		if res := runInfraModule(t, compose, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare services key should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page carrying the markers is not a leak", func(t *testing.T) {
		body := `<html><head><title>x</title></head><body>"terraform_version":"1.5.7" "lineage":"a1b2"</body></html>`
		if res := runInfraModule(t, terraform, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{terraform, kubeconfig, compose} {
			if res := runInfraModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{terraform, kubeconfig, compose} {
			if res := runInfraModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
