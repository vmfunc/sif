package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runWebSrvModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func webSrvExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestWebserverConfigExposureModules(t *testing.T) {
	const htpasswd = "../../modules/recon/htpasswd-exposure.yaml"
	const webconfig = "../../modules/recon/webconfig-exposure.yaml"
	const htaccess = "../../modules/recon/htaccess-exposure.yaml"

	t.Run("htpasswd leaks the user and an apache md5 hash", func(t *testing.T) {
		body := "admin:$apr1$z9c.x1pq$Q8r6Jm0pYh0pX2yq4nN3l1\nbackup:$apr1$ab$cd\n"
		res := runWebSrvModule(t, htpasswd, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an htpasswd finding")
		}
		if v := webSrvExtract(res, "htpasswd_user"); v != "admin" {
			t.Errorf("htpasswd_user=%q, want admin", v)
		}
	})

	t.Run("htpasswd with a bcrypt hash also matches", func(t *testing.T) {
		body := "deploy:$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZ\n"
		if res := runWebSrvModule(t, htpasswd, 200, body); len(res.Findings) == 0 {
			t.Fatal("expected an htpasswd finding for a bcrypt hash")
		}
	})

	t.Run("web.config leaks a connection string", func(t *testing.T) {
		body := `<?xml version="1.0"?><configuration><connectionStrings>` +
			`<add name="Default" connectionString="Server=db;Database=app;User Id=sa;Password=p@ss;" ` +
			`providerName="System.Data.SqlClient" /></connectionStrings></configuration>`
		res := runWebSrvModule(t, webconfig, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a web.config finding")
		}
		want := "Server=db;Database=app;User Id=sa;Password=p@ss;"
		if v := webSrvExtract(res, "connection_string"); v != want {
			t.Errorf("connection_string=%q, want %q", v, want)
		}
	})

	t.Run("htaccess leaks the password file path", func(t *testing.T) {
		body := "RewriteEngine On\nAuthType Basic\nAuthName \"Restricted\"\n" +
			"AuthUserFile /var/www/.htpasswd\nRequire valid-user\n"
		res := runWebSrvModule(t, htaccess, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an htaccess finding")
		}
		if v := webSrvExtract(res, "auth_user_file"); v != "/var/www/.htpasswd" {
			t.Errorf("auth_user_file=%q, want /var/www/.htpasswd", v)
		}
	})

	t.Run("a minimal htaccess with only access control still flags", func(t *testing.T) {
		body := "Options -Indexes\nDeny from all\n"
		if res := runWebSrvModule(t, htaccess, 200, body); len(res.Findings) == 0 {
			t.Fatal("expected a finding for a deny-from-all htaccess")
		}
	})

	t.Run("a plaintext password line is not a hash", func(t *testing.T) {
		body := "admin:notahashedpassword\n"
		if res := runWebSrvModule(t, htpasswd, 200, body); len(res.Findings) > 0 {
			t.Errorf("a plaintext line should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a configuration element without a dotnet section is not a leak", func(t *testing.T) {
		body := `<?xml version="1.0"?><configuration><customRoot><foo/></customRoot></configuration>`
		if res := runWebSrvModule(t, webconfig, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non dotnet configuration should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page is not an htaccess", func(t *testing.T) {
		body := "<html><head><title>x</title></head><body>RewriteEngine On AuthType Basic</body></html>"
		if res := runWebSrvModule(t, htaccess, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{htpasswd, webconfig, htaccess} {
			if res := runWebSrvModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{htpasswd, webconfig, htaccess} {
			if res := runWebSrvModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
