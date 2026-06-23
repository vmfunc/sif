package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDeployModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func deployExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDeployConfigExposureModules(t *testing.T) {
	const vscode = "../../modules/recon/vscode-sftp-exposure.yaml"
	const sublime = "../../modules/recon/sublime-sftp-exposure.yaml"
	const ftpconfig = "../../modules/recon/ftpconfig-exposure.yaml"

	t.Run("vscode sftp config leaks the deploy host", func(t *testing.T) {
		body := `{"name":"prod","host":"deploy.example.com","protocol":"sftp",` +
			`"username":"root","password":"s3cr3t","remotePath":"/var/www","uploadOnSave":true}`
		res := runDeployModule(t, vscode, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a vscode sftp finding")
		}
		if v := deployExtract(res, "remote_host"); v != "deploy.example.com" {
			t.Errorf("remote_host=%q, want deploy.example.com", v)
		}
	})

	t.Run("vscode sftp config with key auth still flags and extracts the host", func(t *testing.T) {
		body := `{"host":"key.example.com","protocol":"sftp",` +
			`"username":"deploy","privateKeyPath":"~/.ssh/id_rsa","uploadOnSave":true}`
		res := runDeployModule(t, vscode, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a vscode sftp finding for a key-auth config")
		}
		if v := deployExtract(res, "remote_host"); v != "key.example.com" {
			t.Errorf("remote_host=%q, want key.example.com", v)
		}
	})

	t.Run("sublime sftp config leaks the deploy host", func(t *testing.T) {
		body := `{"type":"sftp","host":"sftp.example.org","user":"www","password":"hunter2",` +
			`"remote_path":"/srv","upload_on_save":true,"sync_down_on_open":false}`
		res := runDeployModule(t, sublime, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a sublime sftp finding")
		}
		if v := deployExtract(res, "remote_host"); v != "sftp.example.org" {
			t.Errorf("remote_host=%q, want sftp.example.org", v)
		}
	})

	t.Run("atom remote-ftp config leaks the deploy host", func(t *testing.T) {
		body := `{"protocol":"ftp","host":"ftp.example.net","port":21,"user":"upload",` +
			`"pass":"letmein","remote":"/","connTimeout":10000,"pasvTimeout":10000}`
		res := runDeployModule(t, ftpconfig, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an atom remote-ftp finding")
		}
		if v := deployExtract(res, "remote_host"); v != "ftp.example.net" {
			t.Errorf("remote_host=%q, want ftp.example.net", v)
		}
	})

	t.Run("an html login page carrying the same keys is not a leak", func(t *testing.T) {
		body := `<html><head><title>Sign in</title></head><body>` +
			`config keys "remotePath" "password" "host":"evil.example.com"</body></html>`
		if res := runDeployModule(t, vscode, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain json config without the tool keys is not a leak", func(t *testing.T) {
		body := `{"host":"db.internal","username":"admin","user":"admin","pass":"x","password":"hunter2"}`
		for _, file := range []string{vscode, sublime, ftpconfig} {
			if res := runDeployModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a config without the tool keys should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a tool config with a host but no credential field is not a leak", func(t *testing.T) {
		bodies := map[string]string{
			vscode:    `{"host":"h.example.com","remotePath":"/var/www","uploadOnSave":true}`,
			sublime:   `{"type":"sftp","host":"h.example.com","upload_on_save":true}`,
			ftpconfig: `{"protocol":"ftp","host":"h.example.com","connTimeout":10000,"pasvTimeout":10000}`,
		}
		for file, body := range bodies {
			if res := runDeployModule(t, file, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: a config with no credential field should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{vscode, sublime, ftpconfig} {
			if res := runDeployModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
