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
	"os"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

// serveFavicon returns a server that hands the given bytes on assetPath (the
// real gitea favicon location) and 404s everything else, mirroring how a gitea
// instance answers the module's two probe paths.
func serveFavicon(assetPath string, icon []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == assetPath {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(icon)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func runGiteaFaviconModule(t *testing.T, srvURL string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/info/favicon-gitea.yaml")
	if err != nil {
		t.Fatalf("parse favicon-gitea.yaml: %v", err)
	}
	res, err := modules.ExecuteHTTPModule(context.Background(), srvURL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute favicon-gitea.yaml: %v", err)
	}
	return res
}

func TestFaviconGiteaModule(t *testing.T) {
	v124, err := os.ReadFile("testdata/gitea-favicon-v1.24.png")
	if err != nil {
		t.Fatalf("read v1.24 icon: %v", err)
	}
	v125, err := os.ReadFile("testdata/gitea-favicon-v1.25.png")
	if err != nil {
		t.Fatalf("read v1.25 icon: %v", err)
	}

	t.Run("the v1.24 icon at the modern asset path is flagged", func(t *testing.T) {
		srv := serveFavicon("/assets/img/favicon.png", v124)
		defer srv.Close()
		if res := runGiteaFaviconModule(t, srv.URL); len(res.Findings) == 0 {
			t.Fatal("expected a gitea favicon finding for the v1.24 icon")
		}
	})

	t.Run("the v1.25 icon is flagged", func(t *testing.T) {
		srv := serveFavicon("/assets/img/favicon.png", v125)
		defer srv.Close()
		if res := runGiteaFaviconModule(t, srv.URL); len(res.Findings) == 0 {
			t.Fatal("expected a gitea favicon finding for the v1.25 icon")
		}
	})

	t.Run("the pre-v1.21 icon path is still covered", func(t *testing.T) {
		srv := serveFavicon("/img/favicon.png", v124)
		defer srv.Close()
		if res := runGiteaFaviconModule(t, srv.URL); len(res.Findings) == 0 {
			t.Fatal("expected a finding when the icon is served from the legacy /img path")
		}
	})

	t.Run("a non-gitea icon is not flagged", func(t *testing.T) {
		srv := serveFavicon("/assets/img/favicon.png", []byte("not a gitea favicon"))
		defer srv.Close()
		if res := runGiteaFaviconModule(t, srv.URL); len(res.Findings) > 0 {
			t.Errorf("an unrelated favicon should not match gitea, got %d findings", len(res.Findings))
		}
	})
}
