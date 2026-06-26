package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runMLPlatformModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func mlPlatformExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestMLPlatformExposureModules(t *testing.T) {
	const labelStudio = "../../modules/recon/label-studio-exposure.yaml"
	const cvat = "../../modules/recon/cvat-server-exposure.yaml"

	labelStudioVersion := `{"release":"1.13.1","label-studio-os-package":{"version":"1.13.1",` +
		`"short_version":"1.13","description":"Label Studio"},"label-studio-os-backend":{"message":"release",` +
		`"commit":"abc1234","date":"2024-06-01"}}`

	cvatAbout := `{"name":"Computer Vision Annotation Tool","description":"CVAT is a re-designed annotation tool",` +
		`"version":"2.20.0","logo_url":"http://host/static/logo.png","subtitle":""}`

	t.Run("a label studio version api is flagged with its release", func(t *testing.T) {
		res := runMLPlatformModule(t, labelStudio, 200, labelStudioVersion)
		if len(res.Findings) == 0 {
			t.Fatal("expected a label studio finding")
		}
		if v := mlPlatformExtract(res, "label_studio_release"); v != "1.13.1" {
			t.Errorf("label_studio_release=%q, want 1.13.1", v)
		}
	})

	t.Run("a generic release version is not flagged as label studio", func(t *testing.T) {
		body := `{"release":"1.0","name":"some-app"}`
		if res := runMLPlatformModule(t, labelStudio, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic release should not match label studio, got %d findings", len(res.Findings))
		}
	})

	t.Run("a label studio package without the backend key is not flagged", func(t *testing.T) {
		body := `{"release":"1.13.1","label-studio-os-package":{"version":"1.13.1"}}`
		if res := runMLPlatformModule(t, labelStudio, 200, body); len(res.Findings) > 0 {
			t.Errorf("a package-only body should not match label studio, got %d findings", len(res.Findings))
		}
	})

	t.Run("a label studio backend without the package key is not flagged", func(t *testing.T) {
		body := `{"release":"1.13.1","label-studio-os-backend":{"commit":"abc"}}`
		if res := runMLPlatformModule(t, labelStudio, 200, body); len(res.Findings) > 0 {
			t.Errorf("a backend-only body should not match label studio, got %d findings", len(res.Findings))
		}
	})

	t.Run("a cvat about is flagged with its version", func(t *testing.T) {
		res := runMLPlatformModule(t, cvat, 200, cvatAbout)
		if len(res.Findings) == 0 {
			t.Fatal("expected a cvat finding")
		}
		if v := mlPlatformExtract(res, "cvat_version"); v != "2.20.0" {
			t.Errorf("cvat_version=%q, want 2.20.0", v)
		}
	})

	t.Run("another annotation tool is not flagged as cvat", func(t *testing.T) {
		body := `{"name":"Some Other Tool","version":"1.0","logo_url":"http://x/l.png"}`
		if res := runMLPlatformModule(t, cvat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-cvat name should not match cvat, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page mentioning cvat is not flagged", func(t *testing.T) {
		body := `<html><body><h1>Computer Vision Annotation Tool</h1> version 2.20.0 logo_url</body></html>`
		if res := runMLPlatformModule(t, cvat, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose mentioning cvat should not match the structured response, got %d findings", len(res.Findings))
		}
	})

	t.Run("a cvat about without a logo_url is not flagged", func(t *testing.T) {
		body := `{"name":"Computer Vision Annotation Tool","version":"2.20.0"}`
		if res := runMLPlatformModule(t, cvat, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without logo_url should not match cvat, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{cvat, labelStudio} {
			if res := runMLPlatformModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{cvat, labelStudio} {
			if res := runMLPlatformModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

}
