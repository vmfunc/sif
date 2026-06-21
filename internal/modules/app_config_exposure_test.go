package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runAppCfgModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func appCfgExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestAppConfigExposureModules(t *testing.T) {
	const spring = "../../modules/recon/spring-application-config-exposure.yaml"
	const appsettings = "../../modules/recon/appsettings-exposure.yaml"
	const wpconfig = "../../modules/recon/wp-config-backup-exposure.yaml"

	springProps := "spring.application.name=billing\n" +
		"spring.datasource.url=jdbc:mysql://db.internal:3306/billing\n" +
		"spring.datasource.username=app\nspring.datasource.password=s3cr3tP@ss\n" +
		"spring.jpa.hibernate.ddl-auto=update\nserver.port=8080\n"

	springYaml := "spring:\n  datasource:\n    url: jdbc:postgresql://pg.internal:5432/app\n" +
		"    username: app\n    password: hunter2\nserver:\n  port: 8443\n"

	appSettings := `{` + "\n" +
		`  "Logging": { "LogLevel": { "Default": "Information" } },` + "\n" +
		`  "ConnectionStrings": {` + "\n" +
		`    "DefaultConnection": "Server=db;Database=app;User Id=sa;Password=P@ssw0rd;"` + "\n" +
		`  },` + "\n" +
		`  "AllowedHosts": "*"` + "\n}"

	wpConfig := "<?php\ndefine( 'DB_NAME', 'wordpress' );\ndefine( 'DB_USER', 'wp' );\n" +
		"define( 'DB_PASSWORD', 'Tr0ub4dor&3' );\ndefine( 'DB_HOST', 'localhost' );\n" +
		"$table_prefix = 'wp_';\n"

	t.Run("a spring properties file leaks the jdbc url", func(t *testing.T) {
		res := runAppCfgModule(t, spring, 200, springProps)
		if len(res.Findings) == 0 {
			t.Fatal("expected a spring config finding")
		}
		if v := appCfgExtract(res, "jdbc_url"); v != "jdbc:mysql://db.internal:3306/billing" {
			t.Errorf("jdbc_url=%q, want the mysql url", v)
		}
	})

	t.Run("a spring yaml file also matches and names the jdbc url", func(t *testing.T) {
		res := runAppCfgModule(t, spring, 200, springYaml)
		if len(res.Findings) == 0 {
			t.Fatal("expected a spring config finding for yaml")
		}
		if v := appCfgExtract(res, "jdbc_url"); v != "jdbc:postgresql://pg.internal:5432/app" {
			t.Errorf("jdbc_url=%q, want the postgres url", v)
		}
	})

	t.Run("an appsettings json leaks the connection string", func(t *testing.T) {
		res := runAppCfgModule(t, appsettings, 200, appSettings)
		if len(res.Findings) == 0 {
			t.Fatal("expected an appsettings finding")
		}
		want := "Server=db;Database=app;User Id=sa;Password=P@ssw0rd;"
		if v := appCfgExtract(res, "connection_string"); v != want {
			t.Errorf("connection_string=%q, want %q", v, want)
		}
	})

	t.Run("a wp-config backup leaks the database password", func(t *testing.T) {
		res := runAppCfgModule(t, wpconfig, 200, wpConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a wp-config finding")
		}
		if v := appCfgExtract(res, "db_password"); v != "Tr0ub4dor&3" {
			t.Errorf("db_password=%q, want Tr0ub4dor&3", v)
		}
	})

	t.Run("a spring config with no credential is not flagged", func(t *testing.T) {
		body := "spring.application.name=app\nserver.port=8080\n"
		if res := runAppCfgModule(t, spring, 200, body); len(res.Findings) > 0 {
			t.Errorf("a credential-free config should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a spring config inside an html page is not flagged", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>spring.datasource.password=x</pre></body></html>"
		if res := runAppCfgModule(t, spring, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an appsettings without a connection string is not flagged", func(t *testing.T) {
		body := `{"Logging":{"LogLevel":{"Default":"Information"}},"AllowedHosts":"*"}`
		if res := runAppCfgModule(t, appsettings, 200, body); len(res.Findings) > 0 {
			t.Errorf("a config without a connection string should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an appsettings with no password is not a credential leak", func(t *testing.T) {
		body := `{"ConnectionStrings":{"Db":"Server=db;Database=app;Integrated Security=true;"}}`
		if res := runAppCfgModule(t, appsettings, 200, body); len(res.Findings) > 0 {
			t.Errorf("a passwordless connection string should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an appsettings password outside a connection strings section is not flagged", func(t *testing.T) {
		body := `{"Smtp":{"Host":"Server=mail;Password=relaypass;"}}`
		if res := runAppCfgModule(t, appsettings, 200, body); len(res.Findings) > 0 {
			t.Errorf("a password outside ConnectionStrings should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("prose that names the wp-config password is not a backup", func(t *testing.T) {
		body := "set the DB_PASSWORD env var before running the installer"
		if res := runAppCfgModule(t, wpconfig, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose naming DB_PASSWORD should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a wp-config shown in an html page is not flagged", func(t *testing.T) {
		body := "<html><head><title>setup</title></head><body>define( 'DB_PASSWORD', 'x' ); DB_NAME</body></html>"
		if res := runAppCfgModule(t, wpconfig, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{spring, appsettings, wpconfig} {
			if res := runAppCfgModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{spring, appsettings, wpconfig} {
			if res := runAppCfgModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
