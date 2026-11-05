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

// zabbix-api-exposure fires on a target that answers apiinfo.version with a
// dotted-version json-rpc result. the discriminator is the result shape, not the
// content-type; the module explains why. a service that speaks json-rpc but
// returns something other than a version must stay silent.
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

	// what a live zabbix actually puts on the wire.
	fire := run("application/json", `{"jsonrpc":"2.0","result":"7.0.5","id":1}`)
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

	// key order is not guaranteed; a reordered body must still match.
	if res := run("application/json", `{"id":1,"jsonrpc":"2.0","result":"7.0.5"}`); len(res.Findings) == 0 {
		t.Error("fire-on-reordered-keys failed: exposed apiinfo.version not detected")
	}

	// older deployments and proxies that echo the request type back still fire.
	if res := run("application/json-rpc", `{"jsonrpc":"2.0","result":"7.0.5","id":1}`); len(res.Findings) == 0 {
		t.Error("fire-on-json-rpc-content-type failed: exposed apiinfo.version not detected")
	}

	if res := run("application/json", `{"jsonrpc":"2.0","result":"pong","id":1}`); len(res.Findings) != 0 {
		t.Errorf("silent-on-foreign-jsonrpc failed: %d findings for a non-version result", len(res.Findings))
	}

	// a json-rpc error (auth required, method not found) is not a version leak.
	if res := run("application/json", `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params."},"id":1}`); len(res.Findings) != 0 {
		t.Errorf("silent-on-jsonrpc-error failed: %d findings", len(res.Findings))
	}
}
