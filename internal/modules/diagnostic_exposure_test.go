package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

// runDiagModule runs a shipped module end to end against a server that returns
// the same status and body for every path it requests.
func runDiagModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func diagExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDiagnosticExposureModules(t *testing.T) {
	const actuator = "../../modules/recon/actuator-exposure.yaml"
	const phpinfo = "../../modules/recon/phpinfo-exposure.yaml"
	const apache = "../../modules/recon/apache-status-exposure.yaml"

	t.Run("actuator env endpoint leaks profiles", func(t *testing.T) {
		body := `{"activeProfiles":["production","cloud"],"propertySources":[{"name":"systemEnvironment"}]}`
		res := runDiagModule(t, actuator, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an actuator finding")
		}
		if v := diagExtract(res, "active_profiles"); !strings.Contains(v, "production") {
			t.Errorf("active_profiles=%q, want it to contain production", v)
		}
	})

	t.Run("actuator HAL index", func(t *testing.T) {
		body := `{"_links":{"self":{"href":"http://x/actuator"},"health":{"href":"http://x/actuator/health"}}}`
		if res := runDiagModule(t, actuator, 200, body); len(res.Findings) == 0 {
			t.Fatal("expected an actuator index finding")
		}
	})

	t.Run("phpinfo page leaks version", func(t *testing.T) {
		body := `<html><head><title>phpinfo()</title></head><body><h1 class="p">PHP Version 8.2.13</h1></body></html>`
		res := runDiagModule(t, phpinfo, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a phpinfo finding")
		}
		if v := diagExtract(res, "php_version"); v != "8.2.13" {
			t.Errorf("php_version=%q, want 8.2.13", v)
		}
	})

	t.Run("apache server-status leaks version", func(t *testing.T) {
		body := `<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for example.com</h1>` +
			`<dt>Server Version: Apache/2.4.52 (Ubuntu)</dt></body></html>`
		res := runDiagModule(t, apache, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an apache status finding")
		}
		if v := diagExtract(res, "apache_version"); v != "2.4.52" {
			t.Errorf("apache_version=%q, want 2.4.52", v)
		}
	})

	t.Run("page that only mentions PHP Version is not phpinfo", func(t *testing.T) {
		body := `<html><body><p>PHP Version 8.2 is recommended for this app.</p></body></html>`
		if res := runDiagModule(t, phpinfo, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose PHP Version mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("unrelated page is not an exposure", func(t *testing.T) {
		for _, file := range []string{actuator, phpinfo, apache} {
			if res := runDiagModule(t, file, 200, "<html><body>plain</body></html>"); len(res.Findings) > 0 {
				t.Errorf("%s: unrelated page should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
