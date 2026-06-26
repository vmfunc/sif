package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runNodeRedModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func noderedExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestNodeREDFlowExposureModule(t *testing.T) {
	const nodered = "../../modules/recon/nodered-flow-exposure.yaml"

	t.Run("an open node-red flows export is flagged with its tab label", func(t *testing.T) {
		body := `[{"id":"396c2376.c693dc","type":"tab","label":"Sheet 1"},` +
			`{"id":"a1","type":"inject","z":"396c2376.c693dc","wires":[["b2"]]},` +
			`{"id":"b2","type":"function","z":"396c2376.c693dc","func":"return msg;","wires":[[]]}]`
		res := runNodeRedModule(t, nodered, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a node-red finding")
		}
		if v := noderedExtract(res, "nodered_flow_label"); v != "Sheet 1" {
			t.Errorf("nodered_flow_label=%q, want Sheet 1", v)
		}
	})

	t.Run("an adminAuth node-red returns 401 and is not flagged", func(t *testing.T) {
		if res := runNodeRedModule(t, nodered, 401, `{"message":"Unauthorized"}`); len(res.Findings) > 0 {
			t.Errorf("a 401 from a secured node-red should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a tabs-only flow without wires is not flagged", func(t *testing.T) {
		if res := runNodeRedModule(t, nodered, 200, `[{"id":"x","type":"tab","label":"Home"}]`); len(res.Findings) > 0 {
			t.Errorf("a tabs-only flow should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a wired graph without a tab is not flagged as node-red", func(t *testing.T) {
		if res := runNodeRedModule(t, nodered, 200, `[{"id":"x","type":"section","wires":[["y"]]}]`); len(res.Findings) > 0 {
			t.Errorf("a wired graph without a tab should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runNodeRedModule(t, nodered, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runNodeRedModule(t, nodered, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
