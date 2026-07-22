package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runIdracModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func idracExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDellIdracBMCInfoExposureModule(t *testing.T) {
	const idrac = "../../modules/recon/dell-idrac-bmc-info-exposure.yaml"

	t.Run("a real idrac9 bmc info response is flagged with firmware and model", func(t *testing.T) {
		body := `{"Attributes":{"BuildVersion":"21.07.00.00","FwVer":"5.10.10.00","SystemRev":"A00",` +
			`"SystemID":"03BB","SystemModelName":"PowerEdge R740","ChassisModel":"PowerEdge R740"}}`
		res := runIdracModule(t, idrac, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an idrac bmc info finding")
		}
		if v := idracExtract(res, "idrac_firmware"); v != "5.10.10.00" {
			t.Errorf("idrac_firmware=%q, want 5.10.10.00", v)
		}
		if v := idracExtract(res, "idrac_server_model"); v != "PowerEdge R740" {
			t.Errorf("idrac_server_model=%q, want PowerEdge R740", v)
		}
	})

	t.Run("a body with only SystemModelName and no BuildVersion is not flagged", func(t *testing.T) {
		body := `{"SystemModelName":"PowerEdge R740","Notes":"decommissioned"}`
		if res := runIdracModule(t, idrac, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic build info page mentioning BuildVersion alone is not flagged", func(t *testing.T) {
		body := `{"app":"internal-tool","BuildVersion":"1.2.3"}`
		if res := runIdracModule(t, idrac, 200, body); len(res.Findings) > 0 {
			t.Errorf("an unrelated BuildVersion-only body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIdracModule(t, idrac, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
