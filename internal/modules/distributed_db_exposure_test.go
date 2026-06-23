package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDistDBModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func distDBExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDistributedDBExposureModules(t *testing.T) {
	const riak = "../../modules/recon/riak-api-exposure.yaml"
	const couchbase = "../../modules/recon/couchbase-api-exposure.yaml"
	const druid = "../../modules/recon/druid-api-exposure.yaml"

	riakStats := `{"riak_kv_version":"3.0.16","riak_core_version":"3.0.99","riak_pipe_version":"3.0.16",` +
		`"sys_otp_release":"22","ring_members":["riak@10.0.0.1"],"ring_num_partitions":64,` +
		`"storage_backend":"riak_kv_bitcask_backend"}`

	couchbasePools := `{"pools":[{"name":"default","uri":"/pools/default?uuid=abc",` +
		`"streamingUri":"/poolsStreaming/default?uuid=abc"}],"isAdminCreds":false,"isEnterprise":true,` +
		`"implementationVersion":"7.2.0-6053-enterprise","uuid":"abc",` +
		`"componentsVersion":{"ns_server":"7.2.0-6053","couchdb":"3.1.1"}}`

	druidStatus := `{"version":"0.22.1","modules":[{"name":"org.apache.druid.server.initialization.jetty.JettyServerModule",` +
		`"artifact":"druid-server","version":"0.22.1"},{"name":"org.apache.druid.guice.AnnouncerModule",` +
		`"artifact":"druid-server","version":"0.22.1"}],"memory":{"maxMemory":1037959168,` +
		`"totalMemory":1037959168,"freeMemory":900000000,"directMemory":134217728}}`

	t.Run("an exposed riak http api is flagged and versioned", func(t *testing.T) {
		res := runDistDBModule(t, riak, 200, riakStats)
		if len(res.Findings) == 0 {
			t.Fatal("expected a riak finding")
		}
		if v := distDBExtract(res, "riak_version"); v != "3.0.16" {
			t.Errorf("riak_version=%q, want 3.0.16", v)
		}
	})

	t.Run("an exposed couchbase cluster api is flagged and versioned", func(t *testing.T) {
		res := runDistDBModule(t, couchbase, 200, couchbasePools)
		if len(res.Findings) == 0 {
			t.Fatal("expected a couchbase finding")
		}
		if v := distDBExtract(res, "couchbase_version"); v != "7.2.0-6053-enterprise" {
			t.Errorf("couchbase_version=%q, want 7.2.0-6053-enterprise", v)
		}
	})

	t.Run("an exposed druid process is flagged and versioned", func(t *testing.T) {
		res := runDistDBModule(t, druid, 200, druidStatus)
		if len(res.Findings) == 0 {
			t.Fatal("expected a druid finding")
		}
		if v := distDBExtract(res, "druid_version"); v != "0.22.1" {
			t.Errorf("druid_version=%q, want 0.22.1", v)
		}
	})

	t.Run("a riak kv version without a core version is not flagged", func(t *testing.T) {
		body := `{"riak_kv_version":"3.0.16","name":"app"}`
		if res := runDistDBModule(t, riak, 200, body); len(res.Findings) > 0 {
			t.Errorf("a kv version alone should not match riak, got %d findings", len(res.Findings))
		}
	})

	t.Run("a riak core version without a kv version is not flagged", func(t *testing.T) {
		body := `{"riak_core_version":"3.0.16","name":"app"}`
		if res := runDistDBModule(t, riak, 200, body); len(res.Findings) > 0 {
			t.Errorf("a core version alone should not match riak, got %d findings", len(res.Findings))
		}
	})

	t.Run("a couchbase impl version without a components version is not flagged", func(t *testing.T) {
		body := `{"implementationVersion":"7.2.0","name":"app"}`
		if res := runDistDBModule(t, couchbase, 200, body); len(res.Findings) > 0 {
			t.Errorf("an impl version alone should not match couchbase, got %d findings", len(res.Findings))
		}
	})

	t.Run("a couchbase components version without an impl version is not flagged", func(t *testing.T) {
		body := `{"componentsVersion":{"ns_server":"7.2.0"},"name":"app"}`
		if res := runDistDBModule(t, couchbase, 200, body); len(res.Findings) > 0 {
			t.Errorf("a components version alone should not match couchbase, got %d findings", len(res.Findings))
		}
	})

	t.Run("a druid package without a memory block is not flagged", func(t *testing.T) {
		body := `{"modules":[{"name":"org.apache.druid.cli.Main"}],"app":"x"}`
		if res := runDistDBModule(t, druid, 200, body); len(res.Findings) > 0 {
			t.Errorf("a druid package alone should not match druid, got %d findings", len(res.Findings))
		}
	})

	t.Run("a memory block without a druid package is not flagged", func(t *testing.T) {
		body := `{"memory":{"maxMemory":123},"app":"x"}`
		if res := runDistDBModule(t, druid, 200, body); len(res.Findings) > 0 {
			t.Errorf("a memory block alone should not match druid, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic version json is not a distributed db", func(t *testing.T) {
		body := `{"version":"1.0.0","name":"app"}`
		for _, file := range []string{riak, couchbase, druid} {
			if res := runDistDBModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a generic version should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{riak, couchbase, druid} {
			if res := runDistDBModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{riak, couchbase, druid} {
			if res := runDistDBModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
