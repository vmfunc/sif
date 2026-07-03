package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runImmichModule(t *testing.T, status int, header, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/immich-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse immich module: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if header != "" {
			w.Header().Set("Access-Control-Allow-Headers", header)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute immich module: %v", err)
	}
	return res
}

func immichExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestImmichVersionExposureModule(t *testing.T) {
	// real values from demo.immich.app/api/server/version
	immichHeader := "x-immich-session-token, x-api-key, Authorization, Content-Type"
	immichBody := `{"major":3,"minor":0,"patch":1,"prerelease":null}`

	t.Run("an exposed immich version endpoint is flagged and versioned", func(t *testing.T) {
		res := runImmichModule(t, 200, immichHeader, immichBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected an immich finding")
		}
		if v := immichExtract(res, "immich_major"); v != "3" {
			t.Errorf("immich_major=%q, want 3", v)
		}
		if v := immichExtract(res, "immich_patch"); v != "1" {
			t.Errorf("immich_patch=%q, want 1", v)
		}
	})

	t.Run("a generic version body without the immich cors header is not flagged", func(t *testing.T) {
		// the major/minor/patch body alone is generic, only the immich session
		// token in the cors allow-list makes it identifiable
		header := "Authorization, Content-Type"
		if res := runImmichModule(t, 200, header, immichBody); len(res.Findings) > 0 {
			t.Errorf("a generic version body should not match immich, got %d findings", len(res.Findings))
		}
	})

	t.Run("the immich header without a version body is not flagged", func(t *testing.T) {
		if res := runImmichModule(t, 200, immichHeader, `{"status":"ok"}`); len(res.Findings) > 0 {
			t.Errorf("the header alone should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runImmichModule(t, 404, immichHeader, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
