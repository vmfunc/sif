package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

// zabbix-api-exposure fires only when the target answers apiinfo.version with a
// json-rpc content-type AND a dotted-version result. A foreign service that
// speaks json-rpc but returns a non-version result, or serves the version under
// the wrong content-type, must stay silent.
func TestZabbixAPIExposureModule(t *testing.T) {
	const mod = "../../modules/recon/zabbix-api-exposure.yaml"
	def, err := modules.ParseYAMLModule(mod)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	run := func(contentType, body string) *modules.Result {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def,
			modules.Options{Timeout: 5 * time.Second, Threads: 2})
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		return res
	}

	fire := run("application/json-rpc", `{"jsonrpc":"2.0","result":"7.0.5","id":1}`)
	if len(fire.Findings) == 0 {
		t.Error("fire-on-real failed: exposed apiinfo.version not detected")
	}
	var version string
	for _, f := range fire.Findings {
		if v := f.Extracted["zabbix_api_version"]; v != "" {
			version = v
		}
	}
	if version != "7.0.5" {
		t.Errorf("version extraction: got %q, want 7.0.5", version)
	}

	if res := run("application/json-rpc", `{"jsonrpc":"2.0","result":"pong","id":1}`); len(res.Findings) != 0 {
		t.Errorf("silent-on-foreign-jsonrpc failed: %d findings for a non-version result", len(res.Findings))
	}

	if res := run("application/json", `{"jsonrpc":"2.0","result":"7.0.5","id":1}`); len(res.Findings) != 0 {
		t.Errorf("silent-on-wrong-content-type failed: %d findings", len(res.Findings))
	}
}
