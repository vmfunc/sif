package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runNextcloudModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/nextcloud-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse nextcloud module: %v", err)
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
		t.Fatalf("execute nextcloud module: %v", err)
	}
	return res
}

func nextcloudExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestNextcloudVersionExposureModule(t *testing.T) {
	// real body from cloud.nextcloud.com/status.php
	nextcloudBody := `{"installed":true,"maintenance":false,"needsDbUpgrade":false,` +
		`"version":"34.0.1.2","versionstring":"34.0.1","edition":"","productname":"Nextcloud",` +
		`"extendedSupport":false}`

	t.Run("an exposed nextcloud status endpoint is flagged and versioned", func(t *testing.T) {
		res := runNextcloudModule(t, 200, nextcloudBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nextcloud finding")
		}
		if v := nextcloudExtract(res, "nextcloud_version"); v != "34.0.1" {
			t.Errorf("nextcloud_version=%q, want 34.0.1", v)
		}
	})

	t.Run("an owncloud status endpoint is not flagged as nextcloud", func(t *testing.T) {
		// owncloud is the fork sharing the identical status.php schema but a
		// different productname value
		body := `{"installed":true,"maintenance":false,"needsDbUpgrade":false,` +
			`"version":"10.11.0.10","versionstring":"10.11.0","edition":"community",` +
			`"productname":"ownCloud"}`
		if res := runNextcloudModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("an owncloud status should not match nextcloud, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic status json is not nextcloud", func(t *testing.T) {
		body := `{"installed":true,"maintenance":false}`
		if res := runNextcloudModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic status json should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runNextcloudModule(t, 404, "File not found."); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
