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

func runRuntimeModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func runtimeExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestRuntimeAPIExposureModules(t *testing.T) {
	const docker = "../../modules/recon/docker-api-exposure.yaml"
	const k8s = "../../modules/recon/kubernetes-api-exposure.yaml"
	const kubelet = "../../modules/recon/kubelet-api-exposure.yaml"

	dockerVersion := `{"Platform":{"Name":"Docker Engine - Community"},"Components":[` +
		`{"Name":"Engine","Version":"24.0.7","Details":{"ApiVersion":"1.43"}},` +
		`{"Name":"containerd","Version":"1.6.24"},{"Name":"runc","Version":"1.1.9"}],` +
		`"Version":"24.0.7","ApiVersion":"1.43","MinAPIVersion":"1.12","GitCommit":"311b9ff",` +
		`"GoVersion":"go1.20.10","Os":"linux","Arch":"amd64"}`

	k8sVersion := `{"major":"1","minor":"28","gitVersion":"v1.28.2","gitCommit":"abc123",` +
		`"gitTreeState":"clean","buildDate":"2023-09-13T09:35:49Z","goVersion":"go1.20.8",` +
		`"compiler":"gc","platform":"linux/amd64"}`

	kubeletPods := `{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":` +
		`{"name":"etcd-master","namespace":"kube-system"},"spec":{"containers":[{"name":"etcd"}]}}]}`

	t.Run("an exposed docker api is flagged and versioned", func(t *testing.T) {
		res := runRuntimeModule(t, docker, 200, dockerVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a docker finding")
		}
		if v := runtimeExtract(res, "docker_version"); v != "24.0.7" {
			t.Errorf("docker_version=%q, want 24.0.7", v)
		}
	})

	t.Run("an exposed kubernetes api is flagged and versioned", func(t *testing.T) {
		res := runRuntimeModule(t, k8s, 200, k8sVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kubernetes finding")
		}
		if v := runtimeExtract(res, "k8s_version"); v != "v1.28.2" {
			t.Errorf("k8s_version=%q, want v1.28.2", v)
		}
	})

	t.Run("an exposed kubelet leaks a pod namespace", func(t *testing.T) {
		res := runRuntimeModule(t, kubelet, 200, kubeletPods)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kubelet finding")
		}
		if v := runtimeExtract(res, "kubelet_namespace"); v != "kube-system" {
			t.Errorf("kubelet_namespace=%q, want kube-system", v)
		}
	})

	t.Run("a generic version json without the docker fields is not docker", func(t *testing.T) {
		body := `{"version":"1.0.0","name":"myapp"}`
		if res := runRuntimeModule(t, docker, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic version should not match docker, got %d findings", len(res.Findings))
		}
	})

	t.Run("an apiversion without a min api version is not docker", func(t *testing.T) {
		body := `{"ApiVersion":"2.0","name":"otherservice"}`
		if res := runRuntimeModule(t, docker, 200, body); len(res.Findings) > 0 {
			t.Errorf("apiversion alone should not match docker, got %d findings", len(res.Findings))
		}
	})

	t.Run("a min api version without an api version is not docker", func(t *testing.T) {
		body := `{"MinAPIVersion":"1.12","Os":"linux"}`
		if res := runRuntimeModule(t, docker, 200, body); len(res.Findings) > 0 {
			t.Errorf("min api version alone should not match docker, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic version json without the git fields is not kubernetes", func(t *testing.T) {
		body := `{"version":"1.2.3","build":"xyz"}`
		if res := runRuntimeModule(t, k8s, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic version should not match kubernetes, got %d findings", len(res.Findings))
		}
	})

	t.Run("a gitversion without a git tree state is not kubernetes", func(t *testing.T) {
		body := `{"gitVersion":"v1.0.0","app":"custom"}`
		if res := runRuntimeModule(t, k8s, 200, body); len(res.Findings) > 0 {
			t.Errorf("gitversion alone should not match kubernetes, got %d findings", len(res.Findings))
		}
	})

	t.Run("a build date without a gitversion is not kubernetes", func(t *testing.T) {
		body := `{"buildDate":"2023-01-01T00:00:00Z","app":"custom"}`
		if res := runRuntimeModule(t, k8s, 200, body); len(res.Findings) > 0 {
			t.Errorf("build date alone should not match kubernetes, got %d findings", len(res.Findings))
		}
	})

	t.Run("a service list is not a kubelet pod list", func(t *testing.T) {
		body := `{"kind":"ServiceList","apiVersion":"v1","items":[]}`
		if res := runRuntimeModule(t, kubelet, 200, body); len(res.Findings) > 0 {
			t.Errorf("a service list should not match kubelet, got %d findings", len(res.Findings))
		}
	})

	t.Run("a pod list without an api version is not flagged", func(t *testing.T) {
		body := `{"kind":"PodList","items":[]}`
		if res := runRuntimeModule(t, kubelet, 200, body); len(res.Findings) > 0 {
			t.Errorf("a pod list without apiversion should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{docker, k8s, kubelet} {
			if res := runRuntimeModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{docker, k8s, kubelet} {
			if res := runRuntimeModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
