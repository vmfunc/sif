package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/modules"
)

func runDotfileModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func dotfileExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDotfileCredentialExposureModules(t *testing.T) {
	const netrc = "../../modules/recon/netrc-exposure.yaml"
	const pgpass = "../../modules/recon/pgpass-exposure.yaml"
	const mycnf = "../../modules/recon/mysql-client-config-exposure.yaml"

	netrcBody := "machine api.example.com\n  login deploy\n  password s3cr3tP@ss\n" +
		"machine ftp.example.com\n  login anon\n  password anon@site\n"

	pgpassBody := "db.example.com:5432:appdb:appuser:Sup3rSecret\n*:*:*:replication:replpass\n"

	mycnfBody := "[client]\nuser=root\npassword=R00tPass!\nhost=127.0.0.1\nport=3306\n"

	t.Run("an exposed netrc leaks the machine host", func(t *testing.T) {
		res := runDotfileModule(t, netrc, 200, netrcBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a netrc finding")
		}
		if v := dotfileExtract(res, "netrc_machine"); v != "api.example.com" {
			t.Errorf("netrc_machine=%q, want api.example.com", v)
		}
	})

	t.Run("an exposed pgpass leaks the host", func(t *testing.T) {
		res := runDotfileModule(t, pgpass, 200, pgpassBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a pgpass finding")
		}
		if v := dotfileExtract(res, "pgpass_host"); v != "db.example.com" {
			t.Errorf("pgpass_host=%q, want db.example.com", v)
		}
	})

	t.Run("an exposed my.cnf leaks the client user", func(t *testing.T) {
		res := runDotfileModule(t, mycnf, 200, mycnfBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a my.cnf finding")
		}
		if v := dotfileExtract(res, "mysql_user"); v != "root" {
			t.Errorf("mysql_user=%q, want root", v)
		}
	})

	t.Run("prose that names machine login and password out of order is not a netrc", func(t *testing.T) {
		body := "this machine requires a login; store the password securely"
		if res := runDotfileModule(t, netrc, 200, body); len(res.Findings) > 0 {
			t.Errorf("out of order prose should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a netrc is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>machine api.example.com login deploy password s3cret</pre></body></html>"
		if res := runDotfileModule(t, netrc, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html netrc tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a yaml db config with colon keys is not a pgpass", func(t *testing.T) {
		body := "database:\n  host: db.example.com\n  port: 5432\n  user: appuser\n  password: secret\n"
		if res := runDotfileModule(t, pgpass, 200, body); len(res.Findings) > 0 {
			t.Errorf("a yaml db config should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a pgpass shaped line with a non numeric port is not flagged", func(t *testing.T) {
		body := "db.example.com:default:appdb:appuser:Sup3rSecret\n"
		if res := runDotfileModule(t, pgpass, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non numeric port should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a multi line config with a number field does not match across lines", func(t *testing.T) {
		body := "timeout:30:seconds configured\nsee http://docs.example.com:8080 for details\n"
		if res := runDotfileModule(t, pgpass, 200, body); len(res.Findings) > 0 {
			t.Errorf("fields must stay on one line, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a pgpass is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html>\n<html><body><pre>\ndb.example.com:5432:appdb:appuser:secret\n</pre></body></html>\n"
		if res := runDotfileModule(t, pgpass, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html pgpass tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a my.cnf client section without a password is not flagged", func(t *testing.T) {
		body := "[client]\nuser=root\nhost=localhost\nport=3306\n"
		if res := runDotfileModule(t, mycnf, 200, body); len(res.Findings) > 0 {
			t.Errorf("a section without a password should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a password line without a my.cnf section is not flagged", func(t *testing.T) {
		body := "password=hunter2\nfoo=bar\n"
		if res := runDotfileModule(t, mycnf, 200, body); len(res.Findings) > 0 {
			t.Errorf("a password without a section should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a my.cnf is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>[client]\npassword=secret</pre></body></html>"
		if res := runDotfileModule(t, mycnf, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html my.cnf tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{netrc, pgpass, mycnf} {
			if res := runDotfileModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{netrc, pgpass, mycnf} {
			if res := runDotfileModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
