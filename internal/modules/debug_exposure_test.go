package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runDebugModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func debugExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDebugExposureModules(t *testing.T) {
	const ignition = "../../modules/recon/laravel-ignition-exposure.yaml"
	const profiler = "../../modules/recon/symfony-profiler-exposure.yaml"
	const heapdump = "../../modules/recon/spring-heapdump-exposure.yaml"

	t.Run("ignition health check exposes command execution", func(t *testing.T) {
		res := runDebugModule(t, ignition, 200, `{"can_execute_commands":true,"config":{}}`)
		if len(res.Findings) == 0 {
			t.Fatal("expected an ignition finding")
		}
		if v := debugExtract(res, "can_execute_commands"); v != "true" {
			t.Errorf("can_execute_commands=%q, want true", v)
		}
	})

	t.Run("ignition exposed with debug off still flags and extracts false", func(t *testing.T) {
		res := runDebugModule(t, ignition, 200, `{"can_execute_commands":false}`)
		if len(res.Findings) == 0 {
			t.Fatal("expected an ignition finding even when command execution is off")
		}
		if v := debugExtract(res, "can_execute_commands"); v != "false" {
			t.Errorf("can_execute_commands=%q, want false", v)
		}
	})

	t.Run("symfony profiler exposes a request token", func(t *testing.T) {
		body := `<html><head><title>Symfony Profiler</title></head><body>` +
			`<a href="/_profiler/5f3a2b">GET /</a></body></html>`
		res := runDebugModule(t, profiler, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a symfony profiler finding")
		}
		if v := debugExtract(res, "profiler_token"); v != "5f3a2b" {
			t.Errorf("profiler_token=%q, want 5f3a2b", v)
		}
	})

	t.Run("spring heap dump exposes the hprof magic", func(t *testing.T) {
		body := "JAVA PROFILE 1.0.2\x00\x00\x00\x08heap bytes follow"
		res := runDebugModule(t, heapdump, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a heap dump finding")
		}
		if v := debugExtract(res, "hprof_version"); v != "1.0.2" {
			t.Errorf("hprof_version=%q, want 1.0.2", v)
		}
	})

	t.Run("the hprof magic must be at the start not merely present", func(t *testing.T) {
		body := "<html><body>docs about the JAVA PROFILE 1.0.2 hprof header</body></html>"
		if res := runDebugModule(t, heapdump, 200, body); len(res.Findings) > 0 {
			t.Errorf("the magic away from the start should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page that only names ignition is not the endpoint", func(t *testing.T) {
		body := `<html><body>we use ignition to render errors in development</body></html>`
		if res := runDebugModule(t, ignition, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{ignition, profiler, heapdump} {
			if res := runDebugModule(t, file, 200, "<html><body>plain</body></html>"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{ignition, profiler, heapdump} {
			if res := runDebugModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
