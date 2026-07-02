package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runAutomationModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func automationExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestAutomationServerExposureModules(t *testing.T) {
	const jenkins = "../../modules/recon/jenkins-api-exposure.yaml"
	const nifi = "../../modules/recon/nifi-api-exposure.yaml"

	t.Run("a jenkins controller api is flagged with the first job", func(t *testing.T) {
		body := `{"_class":"hudson.model.Hudson","assignedLabels":[{}],"mode":"NORMAL","nodeDescription":` +
			`"the master Jenkins node","nodeName":"","numExecutors":2,"jobs":[{"_class":` +
			`"hudson.model.FreeStyleProject","name":"deploy-prod","url":"http://ci/job/deploy-prod/","color":"blue"}],` +
			`"useSecurity":true,"views":[{"_class":"hudson.model.AllView","name":"all","url":"http://ci/"}]}`
		res := runAutomationModule(t, jenkins, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jenkins finding")
		}
		if v := automationExtract(res, "jenkins_job"); v != "deploy-prod" {
			t.Errorf("jenkins_job=%q, want deploy-prod", v)
		}
	})

	t.Run("a non-root jenkins object is not flagged as the controller", func(t *testing.T) {
		body := `{"_class":"hudson.model.FreeStyleProject","name":"deploy-prod","jobs":[],"color":"blue"}`
		if res := runAutomationModule(t, jenkins, 200, body); len(res.Findings) > 0 {
			t.Errorf("a FreeStyleProject object should not match the controller, got %d findings", len(res.Findings))
		}
	})

	t.Run("a hudson root without a jobs key is not flagged", func(t *testing.T) {
		if res := runAutomationModule(t, jenkins, 200, `{"_class":"hudson.model.Hudson","mode":"NORMAL"}`); len(res.Findings) > 0 {
			t.Errorf("a jobless controller blob should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a nifi about is flagged with its version", func(t *testing.T) {
		body := `{"about":{"title":"NiFi","version":"1.28.1","uri":"https://nifi:8443/nifi-api/",` +
			`"contentViewerUrl":"../nifi-content-viewer/","timezone":"UTC","buildTag":"nifi-1.28.1-RC1",` +
			`"buildRevision":"abc123","buildBranch":"support/nifi-1.x","buildTimestamp":"06/01/2024 10:00:00 UTC"}}`
		res := runAutomationModule(t, nifi, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nifi finding")
		}
		if v := automationExtract(res, "nifi_version"); v != "1.28.1" {
			t.Errorf("nifi_version=%q, want 1.28.1", v)
		}
	})

	t.Run("an about block for another product is not flagged as nifi", func(t *testing.T) {
		if res := runAutomationModule(t, nifi, 200, `{"about":{"title":"SomeApp","version":"2.0.0"}}`); len(res.Findings) > 0 {
			t.Errorf("a non-nifi about block should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{jenkins, nifi} {
			if res := runAutomationModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 403 or 401 is not a leak", func(t *testing.T) {
		if res := runAutomationModule(t, jenkins, 403, `{"_class":"hudson.model.Hudson","jobs":[]}`); len(res.Findings) > 0 {
			t.Errorf("a 403 jenkins should not match, got %d findings", len(res.Findings))
		}
		if res := runAutomationModule(t, nifi, 401, `{"about":{"title":"NiFi","version":"1.28.1"}}`); len(res.Findings) > 0 {
			t.Errorf("a 401 nifi should not match, got %d findings", len(res.Findings))
		}
	})
}
