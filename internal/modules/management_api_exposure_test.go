package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runMgmtModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func mgmtExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestManagementAPIExposureModules(t *testing.T) {
	const kong = "../../modules/recon/kong-api-exposure.yaml"
	const jolokia = "../../modules/recon/jolokia-api-exposure.yaml"
	const nats = "../../modules/recon/nats-api-exposure.yaml"

	kongRoot := `{"version":"3.4.0","tagline":"Welcome to kong","hostname":"kong-node","node_id":"abc",` +
		`"lua_version":"LuaJIT 2.1.0","plugins":{"available_on_server":{}},` +
		`"configuration":{"database":"postgres","admin_listen":["0.0.0.0:8001"]}}`

	jolokiaVersion := `{"request":{"type":"version"},"value":{"agent":"1.7.2","protocol":"7.2",` +
		`"config":{"agentType":"servlet"},"info":{"product":"tomcat"}},"status":200,"timestamp":1694598949}`

	natsVarz := `{"server_id":"NDABC","server_name":"NDABC","version":"2.10.1","proto":1,"go":"go1.21.1",` +
		`"host":"0.0.0.0","port":4222,"max_connections":65536,"max_payload":1048576,"connections":3,"total_connections":10}`

	t.Run("an exposed kong admin api is flagged and versioned", func(t *testing.T) {
		res := runMgmtModule(t, kong, 200, kongRoot)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kong finding")
		}
		if v := mgmtExtract(res, "kong_version"); v != "3.4.0" {
			t.Errorf("kong_version=%q, want 3.4.0", v)
		}
	})

	t.Run("an exposed jolokia agent is flagged and versioned", func(t *testing.T) {
		res := runMgmtModule(t, jolokia, 200, jolokiaVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jolokia finding")
		}
		if v := mgmtExtract(res, "jolokia_agent_version"); v != "1.7.2" {
			t.Errorf("jolokia_agent_version=%q, want 1.7.2", v)
		}
	})

	t.Run("an exposed nats monitor is flagged and versioned", func(t *testing.T) {
		res := runMgmtModule(t, nats, 200, natsVarz)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nats finding")
		}
		if v := mgmtExtract(res, "nats_version"); v != "2.10.1" {
			t.Errorf("nats_version=%q, want 2.10.1", v)
		}
	})

	t.Run("an available plugins map without an admin listen is not flagged", func(t *testing.T) {
		body := `{"plugins":{"available_on_server":{}},"version":"3.4.0"}`
		if res := runMgmtModule(t, kong, 200, body); len(res.Findings) > 0 {
			t.Errorf("an available plugins map alone should not match kong, got %d findings", len(res.Findings))
		}
	})

	t.Run("an admin listen without an available plugins map is not flagged", func(t *testing.T) {
		body := `{"configuration":{"admin_listen":["0.0.0.0:8001"]},"version":"1.0"}`
		if res := runMgmtModule(t, kong, 200, body); len(res.Findings) > 0 {
			t.Errorf("an admin listen alone should not match kong, got %d findings", len(res.Findings))
		}
	})

	t.Run("a jolokia agent without a protocol is not flagged", func(t *testing.T) {
		body := `{"value":{"agent":"1.7.2"}}`
		if res := runMgmtModule(t, jolokia, 200, body); len(res.Findings) > 0 {
			t.Errorf("an agent alone should not match jolokia, got %d findings", len(res.Findings))
		}
	})

	t.Run("a jolokia protocol without an agent is not flagged", func(t *testing.T) {
		body := `{"value":{"protocol":"7.2"},"info":{}}`
		if res := runMgmtModule(t, jolokia, 200, body); len(res.Findings) > 0 {
			t.Errorf("a protocol alone should not match jolokia, got %d findings", len(res.Findings))
		}
	})

	t.Run("a nats server id without a max payload is not flagged", func(t *testing.T) {
		body := `{"server_id":"NDABC","version":"2.10.1"}`
		if res := runMgmtModule(t, nats, 200, body); len(res.Findings) > 0 {
			t.Errorf("a server id alone should not match nats, got %d findings", len(res.Findings))
		}
	})

	t.Run("a max payload without a nats server id is not flagged", func(t *testing.T) {
		body := `{"max_payload":1048576,"port":4222}`
		if res := runMgmtModule(t, nats, 200, body); len(res.Findings) > 0 {
			t.Errorf("a max payload alone should not match nats, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic version json is not a management api", func(t *testing.T) {
		body := `{"version":"1.0.0","name":"app"}`
		for _, file := range []string{kong, jolokia, nats} {
			if res := runMgmtModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a generic version should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{kong, jolokia, nats} {
			if res := runMgmtModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{kong, jolokia, nats} {
			if res := runMgmtModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
