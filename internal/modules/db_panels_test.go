package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDBModule(t *testing.T, file string, status int, headers map[string]string, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
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
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

func dbExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDBPanelModules(t *testing.T) {
	const adminer = "../../modules/info/adminer-panel.yaml"
	const phpmyadmin = "../../modules/info/phpmyadmin-panel.yaml"

	adminerLogin := `<form action=""><input type="hidden" name="auth[driver]" value="server">` +
		`<input name="auth[username]"></form>` +
		`<p class="links"><a href="https://www.adminer.org/">Adminer</a> <span class="version">4.8.1</span></p>`
	pmaLogin := `<link rel="stylesheet" href="themes/pmahomme/css/theme.css">` +
		`<input type="text" name="pma_username"><script>var data = {"PMA_VERSION":"5.2.1"};</script>`

	t.Run("adminer login", func(t *testing.T) {
		res := runDBModule(t, adminer, 200, nil, adminerLogin)
		if len(res.Findings) == 0 {
			t.Fatal("expected an adminer finding")
		}
		if v := dbExtract(res, "adminer_version"); v != "4.8.1" {
			t.Errorf("adminer_version=%q, want 4.8.1", v)
		}
	})

	t.Run("adminer unrelated page", func(t *testing.T) {
		if res := runDBModule(t, adminer, 200, nil, "<html><body>nothing</body></html>"); len(res.Findings) > 0 {
			t.Errorf("unrelated page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("phpmyadmin login", func(t *testing.T) {
		res := runDBModule(t, phpmyadmin, 200, map[string]string{"Set-Cookie": "phpMyAdmin=abc123; path=/"}, pmaLogin)
		if len(res.Findings) == 0 {
			t.Fatal("expected a phpmyadmin finding")
		}
		if v := dbExtract(res, "phpmyadmin_version"); v != "5.2.1" {
			t.Errorf("phpmyadmin_version=%q, want 5.2.1", v)
		}
	})

	t.Run("phpmyadmin unrelated page", func(t *testing.T) {
		if res := runDBModule(t, phpmyadmin, 200, nil, "<html><body>nothing</body></html>"); len(res.Findings) > 0 {
			t.Errorf("unrelated page should not match, got %d findings", len(res.Findings))
		}
	})
}
