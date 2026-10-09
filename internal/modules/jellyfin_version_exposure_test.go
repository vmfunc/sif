package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runJellyfinModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/jellyfin-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse jellyfin module: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute jellyfin module: %v", err)
	}
	return res
}

func jellyfinExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestJellyfinVersionExposureModule(t *testing.T) {
	// real body from demo.jellyfin.org/stable/System/Info/Public
	jellyfinBody := `{"LocalAddress":"http://172.17.0.2:8096/stable","ServerName":"Stable Demo",` +
		`"Version":"10.11.11","ProductName":"Jellyfin Server","OperatingSystem":"",` +
		`"Id":"f0b3381645f04afb9a0e392e74b6a1b0","StartupWizardCompleted":true}`

	t.Run("an exposed jellyfin public info endpoint is flagged and versioned", func(t *testing.T) {
		res := runJellyfinModule(t, 200, jellyfinBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jellyfin finding")
		}
		if v := jellyfinExtract(res, "jellyfin_version"); v != "10.11.11" {
			t.Errorf("jellyfin_version=%q, want 10.11.11", v)
		}
	})

	t.Run("an emby public info endpoint is not flagged as jellyfin", func(t *testing.T) {
		// emby is the ancestor jellyfin forked from, sharing the same path and
		// json shape but reporting a different productname value
		body := `{"LocalAddress":"http://172.17.0.2:8096","ServerName":"demo",` +
			`"Version":"4.8.0.0","ProductName":"Emby Server","OperatingSystem":"linux",` +
			`"Id":"abc"}`
		if res := runJellyfinModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("an emby public info should not match jellyfin, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic info json is not jellyfin", func(t *testing.T) {
		body := `{"ServerName":"demo","Version":"1.0.0"}`
		if res := runJellyfinModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic info json should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runJellyfinModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
