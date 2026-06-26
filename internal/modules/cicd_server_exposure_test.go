package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runCICDModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func cicdExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestCICDServerExposureModules(t *testing.T) {
	const concourse = "../../modules/recon/concourse-info-exposure.yaml"
	const woodpecker = "../../modules/recon/woodpecker-version-exposure.yaml"
	const gocd = "../../modules/recon/gocd-version-exposure.yaml"

	t.Run("a concourse info is flagged with its version", func(t *testing.T) {
		body := `{"version":"7.11.2","worker_version":"2.4","external_url":"https://ci.example.com","cluster_name":"prod"}`
		res := runCICDModule(t, concourse, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a concourse finding")
		}
		if v := cicdExtract(res, "concourse_version"); v != "7.11.2" {
			t.Errorf("concourse_version=%q, want 7.11.2", v)
		}
	})

	t.Run("an info without worker_version is not flagged as concourse", func(t *testing.T) {
		body := `{"version":"1.0","external_url":"https://x"}`
		if res := runCICDModule(t, concourse, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without worker_version should not match concourse, got %d findings", len(res.Findings))
		}
	})

	t.Run("a woodpecker version is flagged with its version", func(t *testing.T) {
		body := `{"source":"https://github.com/woodpecker-ci/woodpecker","version":"2.1.0"}`
		res := runCICDModule(t, woodpecker, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a woodpecker finding")
		}
		if v := cicdExtract(res, "woodpecker_version"); v != "2.1.0" {
			t.Errorf("woodpecker_version=%q, want 2.1.0", v)
		}
	})

	t.Run("a drone version with the same shape is not flagged as woodpecker", func(t *testing.T) {
		body := `{"source":"https://github.com/harness/drone","version":"2.20.0"}`
		if res := runCICDModule(t, woodpecker, 200, body); len(res.Findings) > 0 {
			t.Errorf("a drone source should not match woodpecker, got %d findings", len(res.Findings))
		}
	})

	t.Run("a gocd version is flagged with its version", func(t *testing.T) {
		body := `{"_links":{"self":{"href":"https://ci/go/api/version"}},"version":"21.4.0",` +
			`"build_number":"13183","git_sha":"abc123","full_version":"21.4.0 (13183-abc123)",` +
			`"commit_url":"https://github.com/gocd/gocd/commit/abc123"}`
		res := runCICDModule(t, gocd, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a gocd finding")
		}
		if v := cicdExtract(res, "gocd_version"); v != "21.4.0" {
			t.Errorf("gocd_version=%q, want 21.4.0", v)
		}
	})

	t.Run("a version with a non-gocd commit url is not flagged as gocd", func(t *testing.T) {
		body := `{"version":"1.0","full_version":"1.0 (1-x)","commit_url":"https://github.com/other/repo/commit/x"}`
		if res := runCICDModule(t, gocd, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-gocd commit url should not match gocd, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{concourse, woodpecker, gocd} {
			if res := runCICDModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{concourse, woodpecker, gocd} {
			if res := runCICDModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
