package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runRailsModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func railsExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestRailsSecretExposureModules(t *testing.T) {
	const database = "../../modules/recon/rails-database-yml-exposure.yaml"
	const secrets = "../../modules/recon/rails-secrets-yml-exposure.yaml"
	const masterKey = "../../modules/recon/rails-master-key-exposure.yaml"

	const keyBase = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const masterKeyValue = "0123456789abcdef0123456789abcdef"

	t.Run("database config leaks the database name and credentials", func(t *testing.T) {
		body := "default: &default\n  adapter: postgresql\n  encoding: unicode\n  pool: 5\n" +
			"  username: app_user\n  password: s3cr3tdbpass\n  host: db.internal\n\n" +
			"production:\n  <<: *default\n  database: myapp_production\n"
		res := runRailsModule(t, database, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a database config finding")
		}
		if v := railsExtract(res, "database"); v != "myapp_production" {
			t.Errorf("database=%q, want myapp_production", v)
		}
	})

	t.Run("a credential free sqlite database config is not a leak", func(t *testing.T) {
		body := "production:\n  adapter: sqlite3\n  database: db/production.sqlite3\n  pool: 5\n"
		if res := runRailsModule(t, database, 200, body); len(res.Findings) > 0 {
			t.Errorf("a sqlite config without credentials should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("secrets config leaks the secret key base", func(t *testing.T) {
		body := "development:\n  secret_key_base: " + keyBase + "\n"
		res := runRailsModule(t, secrets, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a secrets config finding")
		}
		if v := railsExtract(res, "secret_key_base"); v != keyBase {
			t.Errorf("secret_key_base=%q, want %q", v, keyBase)
		}
	})

	t.Run("master key file leaks the key", func(t *testing.T) {
		res := runRailsModule(t, masterKey, 200, masterKeyValue)
		if len(res.Findings) == 0 {
			t.Fatal("expected a master key finding")
		}
		if v := railsExtract(res, "master_key"); v != masterKeyValue {
			t.Errorf("master_key=%q, want %q", v, masterKeyValue)
		}
	})

	t.Run("a longer hex digest is not the master key", func(t *testing.T) {
		body := masterKeyValue + masterKeyValue
		if res := runRailsModule(t, masterKey, 200, body); len(res.Findings) > 0 {
			t.Errorf("a 64 char digest should not match the 32 char key, got %d findings", len(res.Findings))
		}
	})

	t.Run("a hex value not at the body start is not the master key", func(t *testing.T) {
		body := "key=" + masterKeyValue
		if res := runRailsModule(t, masterKey, 200, body); len(res.Findings) > 0 {
			t.Errorf("a hex value away from the start should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page naming the rails markers is not a leak", func(t *testing.T) {
		body := "<html><head><title>Error</title></head><body>secret_key_base: " + keyBase + "</body></html>"
		if res := runRailsModule(t, secrets, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a config without the rails markers is not a leak", func(t *testing.T) {
		body := "password: hunter2\nusername: admin\nhost: db.internal\n"
		for _, file := range []string{database, secrets, masterKey} {
			if res := runRailsModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a config without the rails markers should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{database, secrets, masterKey} {
			if res := runRailsModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
