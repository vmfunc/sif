package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runOrchModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func orchExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestOrchestrationAPIExposureModules(t *testing.T) {
	const vault = "../../modules/recon/vault-api-exposure.yaml"
	const consul = "../../modules/recon/consul-api-exposure.yaml"
	const etcd = "../../modules/recon/etcd-api-exposure.yaml"

	vaultSeal := `{"type":"shamir","initialized":true,"sealed":false,"t":3,"n":5,` +
		`"progress":0,"nonce":"","version":"1.15.2","build_date":"2023-11-06T11:33:49Z",` +
		`"migration":false,"cluster_name":"vault-cluster-9d52b1f1","recovery_seal":false,` +
		`"storage_type":"raft"}`

	consulSelf := `{"Config":{"Datacenter":"dc1","NodeName":"consul-server-1","Server":true,` +
		`"Version":"1.17.0"},"Member":{"Name":"consul-server-1","Addr":"10.0.0.5","Port":8301}}`

	etcdVersion := `{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}`

	t.Run("an exposed vault seal-status is flagged and versioned", func(t *testing.T) {
		res := runOrchModule(t, vault, 200, vaultSeal)
		if len(res.Findings) == 0 {
			t.Fatal("expected a vault finding")
		}
		if v := orchExtract(res, "vault_version"); v != "1.15.2" {
			t.Errorf("vault_version=%q, want 1.15.2", v)
		}
	})

	t.Run("an exposed consul agent self leaks the datacenter", func(t *testing.T) {
		res := runOrchModule(t, consul, 200, consulSelf)
		if len(res.Findings) == 0 {
			t.Fatal("expected a consul finding")
		}
		if v := orchExtract(res, "consul_datacenter"); v != "dc1" {
			t.Errorf("consul_datacenter=%q, want dc1", v)
		}
	})

	t.Run("an exposed etcd version endpoint is flagged and versioned", func(t *testing.T) {
		res := runOrchModule(t, etcd, 200, etcdVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected an etcd finding")
		}
		if v := orchExtract(res, "etcd_version"); v != "3.5.9" {
			t.Errorf("etcd_version=%q, want 3.5.9", v)
		}
	})

	t.Run("a sealed flag without the other vault keys is not vault", func(t *testing.T) {
		body := `{"sealed":"yes","status":"ok"}`
		if res := runOrchModule(t, vault, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare sealed flag should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a datacenter field alone is not consul", func(t *testing.T) {
		body := `{"Datacenter":"dc1"}`
		if res := runOrchModule(t, consul, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare datacenter field should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a version response from another service is not etcd", func(t *testing.T) {
		body := `{"version":"1.2.3","service":"myapp"}`
		if res := runOrchModule(t, etcd, 200, body); len(res.Findings) > 0 {
			t.Errorf("another service version should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an etcdserver without an etcdcluster is not flagged", func(t *testing.T) {
		body := `{"etcdserver":"3.5.9"}`
		if res := runOrchModule(t, etcd, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial etcd response should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{vault, consul, etcd} {
			if res := runOrchModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{vault, consul, etcd} {
			if res := runOrchModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
