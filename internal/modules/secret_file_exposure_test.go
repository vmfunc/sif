package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runSecretModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func secretExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestSecretFileExposureModules(t *testing.T) {
	const privkey = "../../modules/recon/private-key-exposure.yaml"
	const gitcred = "../../modules/recon/git-credentials-exposure.yaml"
	const pypirc = "../../modules/recon/pypirc-exposure.yaml"

	opensshKey := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy\n" +
		"NTUxOQAAACD1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"-----END OPENSSH PRIVATE KEY-----\n"

	rsaKey := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEArandombase64payloadthatstandsinforakeybodyhere1234567890\n" +
		"-----END RSA PRIVATE KEY-----\n"

	gitCreds := "https://octocat:ghp_AbCdEf0123456789AbCdEf0123456789@github.com\n" +
		"https://deploy:s3cr3t@gitlab.example.com\n"

	pypiConfig := "[distutils]\nindex-servers =\n    pypi\n\n[pypi]\n" +
		"username = __token__\npassword = pypi-AgEIcHlwaS5vcmcCJDQ2Y2Q\n"

	t.Run("an openssh private key is flagged and typed", func(t *testing.T) {
		res := runSecretModule(t, privkey, 200, opensshKey)
		if len(res.Findings) == 0 {
			t.Fatal("expected a private key finding")
		}
		if v := secretExtract(res, "key_type"); v != "OPENSSH" {
			t.Errorf("key_type=%q, want OPENSSH", v)
		}
	})

	t.Run("an rsa private key is flagged and typed", func(t *testing.T) {
		res := runSecretModule(t, privkey, 200, rsaKey)
		if len(res.Findings) == 0 {
			t.Fatal("expected a private key finding")
		}
		if v := secretExtract(res, "key_type"); v != "RSA" {
			t.Errorf("key_type=%q, want RSA", v)
		}
	})

	t.Run("a git credential store leaks its host", func(t *testing.T) {
		res := runSecretModule(t, gitcred, 200, gitCreds)
		if len(res.Findings) == 0 {
			t.Fatal("expected a git credential finding")
		}
		if v := secretExtract(res, "git_host"); v != "github.com" {
			t.Errorf("git_host=%q, want github.com", v)
		}
	})

	t.Run("a pypirc leaks the upload token", func(t *testing.T) {
		res := runSecretModule(t, pypirc, 200, pypiConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a pypirc finding")
		}
		if v := secretExtract(res, "pypi_token"); v != "pypi-AgEIcHlwaS5vcmcCJDQ2Y2Q" {
			t.Errorf("pypi_token=%q, want the pypi- token", v)
		}
	})

	t.Run("a public key is not a private key", func(t *testing.T) {
		body := "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK\n" +
			"-----END PUBLIC KEY-----\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host\n"
		if res := runSecretModule(t, privkey, 200, body); len(res.Findings) > 0 {
			t.Errorf("a public key should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("prose that names a private key is not the key", func(t *testing.T) {
		body := "Generate your private key with ssh-keygen and keep id_rsa secret."
		if res := runSecretModule(t, privkey, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose about keys should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a git remote url without a password is not a credential store", func(t *testing.T) {
		body := "https://github.com/octocat/hello-world.git\n"
		if res := runSecretModule(t, gitcred, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare remote url should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a pypi section without a credential is not a leak", func(t *testing.T) {
		body := "[distutils]\nindex-servers =\n    pypi\n"
		if res := runSecretModule(t, pypirc, 200, body); len(res.Findings) > 0 {
			t.Errorf("a section with no credential should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("credentials shown in an html page are not a store", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body>clone with https://user:pass@host.example</body></html>"
		if res := runSecretModule(t, gitcred, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a pypi config inside an html page is not a leak", func(t *testing.T) {
		body := "<html><head><title>docs</title></head><body><pre>[pypi]\npassword = pypi-x</pre></body></html>"
		if res := runSecretModule(t, pypirc, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{privkey, gitcred, pypirc} {
			if res := runSecretModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{privkey, gitcred, pypirc} {
			if res := runSecretModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
