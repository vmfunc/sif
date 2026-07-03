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
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runIACModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func iacExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestTerraformTfvarsExposure(t *testing.T) {
	const file = "../../modules/recon/terraform-tfvars-exposure.yaml"

	t.Run("real tfvars with region and password leaks", func(t *testing.T) {
		body := "region        = \"us-east-1\"\n" +
			"instance_type = \"t3.medium\"\n" +
			"db_password   = \"hunter2wow\"\n"
		res := runIACModule(t, file, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a tfvars finding")
		}
		if v := iacExtract(res, "tfvars_first_key"); v != "region" {
			t.Errorf("tfvars_first_key=%q, want region", v)
		}
	})

	t.Run("a single assignment line is not enough structure", func(t *testing.T) {
		body := "region = \"us-east-1\"\n"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("a lone assignment line should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("two assignment lines without infra vocabulary is not a leak", func(t *testing.T) {
		body := "greeting = \"hello\"\nfarewell = \"bye\"\n"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("generic key/value pairs should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page quoting a tfvars sample is not a leak", func(t *testing.T) {
		body := "<html><head><title>docs</title></head><body>example:<pre>\n" +
			"region = \"us-east-1\"\ndb_password = \"hunter2wow\"\n</pre></body></html>"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html docs page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestAnsibleVaultExposure(t *testing.T) {
	const file = "../../modules/recon/ansible-vault-exposure.yaml"

	t.Run("a real vault header with hex ciphertext leaks", func(t *testing.T) {
		body := "$ANSIBLE_VAULT;1.1;AES256\n" +
			"66306233383530323332383937616434373966336134393634356164616662653933\n" +
			"3934363865616461393866346336336336616337663764303431653534380a3833\n"
		res := runIACModule(t, file, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an ansible vault finding")
		}
		if v := iacExtract(res, "vault_format_version"); v != "1" {
			t.Errorf("vault_format_version=%q, want 1", v)
		}
	})

	t.Run("a 1.2 vault header also leaks", func(t *testing.T) {
		body := "$ANSIBLE_VAULT;1.2;AES256\n" +
			"66306233383530323332383937616434373966336134393634356164616662653933\n"
		res := runIACModule(t, file, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an ansible vault finding")
		}
		if v := iacExtract(res, "vault_format_version"); v != "2" {
			t.Errorf("vault_format_version=%q, want 2", v)
		}
	})

	t.Run("a docs page mentioning the vault header mid-body is not a leak", func(t *testing.T) {
		body := "<html><head><title>ansible vault docs</title></head><body>" +
			"a vault file starts with $ANSIBLE_VAULT;1.1;AES256 followed by hex" +
			"</body></html>"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("a docs page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("the bare header without a ciphertext blob is not a leak", func(t *testing.T) {
		body := "$ANSIBLE_VAULT;1.1;AES256\n"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("a header with no ciphertext should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestGitlabCIConfigExposure(t *testing.T) {
	const file = "../../modules/recon/gitlab-ci-config-exposure.yaml"

	t.Run("a real gitlab-ci pipeline leaks the build image", func(t *testing.T) {
		body := "stages:\n  - build\n  - deploy\n\nbuild:\n  stage: build\n" +
			"  image: registry.internal.example.com/builder:1.4\n" +
			"  script:\n    - make build\n  artifacts:\n    paths:\n      - dist/\n"
		res := runIACModule(t, file, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a gitlab-ci finding")
		}
		if v := iacExtract(res, "ci_image"); v != "registry.internal.example.com/builder:1.4" {
			t.Errorf("ci_image=%q, want registry.internal.example.com/builder:1.4", v)
		}
	})

	t.Run("a script key alone without stage vocabulary is not a leak", func(t *testing.T) {
		body := "script: this word appears in prose too\n"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("a bare script mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a blog post discussing gitlab-ci as html is not a leak", func(t *testing.T) {
		body := "<html><head><title>gitlab ci guide</title></head><body>" +
			"a pipeline needs stages: and script: to run jobs" +
			"</body></html>"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html blog post should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestJenkinsfileExposure(t *testing.T) {
	const file = "../../modules/recon/jenkinsfile-exposure.yaml"

	t.Run("a real declarative Jenkinsfile leaks the agent", func(t *testing.T) {
		body := "pipeline {\n  agent docker\n  stages {\n    stage('Build') {\n" +
			"      steps {\n        sh 'make build'\n      }\n    }\n  }\n}\n"
		res := runIACModule(t, file, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jenkinsfile finding")
		}
		if v := iacExtract(res, "jenkinsfile_agent"); v != "docker" {
			t.Errorf("jenkinsfile_agent=%q, want docker", v)
		}
	})

	t.Run("a scripted Jenkinsfile with node and stage also leaks", func(t *testing.T) {
		body := "node {\n  stage('checkout') {\n    checkout scm\n  }\n}\n"
		res := runIACModule(t, file, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jenkinsfile finding")
		}
	})

	t.Run("prose mentioning a deployment pipeline without DSL syntax is not a leak", func(t *testing.T) {
		body := "our deployment pipeline runs several stages before release\n"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page quoting Jenkinsfile syntax is not a leak", func(t *testing.T) {
		body := "<html><head><title>jenkins docs</title></head><body><pre>" +
			"pipeline { agent any stages { stage('x') { steps { } } } }" +
			"</pre></body></html>"
		if res := runIACModule(t, file, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html docs page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIACModule(t, file, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
