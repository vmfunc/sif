package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runRedfishModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func redfishExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestRedfishServiceRootModule(t *testing.T) {
	const rf = "../../modules/info/redfish-service-root.yaml"

	t.Run("a real redfish service root is flagged with its version", func(t *testing.T) {
		body := `{"@odata.context":"/redfish/v1/$metadata#ServiceRoot.ServiceRoot","@odata.id":"/redfish/v1/",` +
			`"@odata.type":"#ServiceRoot.v1_9_0.ServiceRoot","Id":"RootService","Name":"Root Service",` +
			`"RedfishVersion":"1.9.0","UUID":"92384634-2938-2342-8820-489239905423",` +
			`"Systems":{"@odata.id":"/redfish/v1/Systems"},"Chassis":{"@odata.id":"/redfish/v1/Chassis"},` +
			`"Managers":{"@odata.id":"/redfish/v1/Managers"},"SessionService":{"@odata.id":"/redfish/v1/SessionService"}}`
		res := runRedfishModule(t, rf, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a redfish service root finding")
		}
		if v := redfishExtract(res, "redfish_version"); v != "1.9.0" {
			t.Errorf("redfish_version=%q, want 1.9.0", v)
		}
	})

	t.Run("a body with RedfishVersion and Managers but a non-ServiceRoot odata.type is not flagged", func(t *testing.T) {
		body := `{"@odata.type":"#ManagerCollection.ManagerCollection","RedfishVersion":"1.9.0",` +
			`"Managers":[{"@odata.id":"/redfish/v1/Managers/1"}]}`
		if res := runRedfishModule(t, rf, 200, body); len(res.Findings) > 0 {
			t.Errorf("a manager collection page should not match the service root, got %d findings", len(res.Findings))
		}
	})

	t.Run("a docs page mentioning RedfishVersion in prose is not flagged", func(t *testing.T) {
		body := `<html><body>The Redfish service root exposes a RedfishVersion and a Managers collection for BMC discovery.</body></html>`
		if res := runRedfishModule(t, rf, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runRedfishModule(t, rf, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
