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

func runLoginModule(t *testing.T, file string, status int, headers map[string]string, body string) *modules.Result {
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

func loginExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestLoginPanelModules(t *testing.T) {
	const grafana = "../../modules/info/grafana-panel.yaml"
	const kibana = "../../modules/info/kibana-panel.yaml"
	const jenkins = "../../modules/info/jenkins-panel.yaml"

	grafanaBody := `<body class="app-grafana"><grafana-app></grafana-app>` +
		`<script>window.grafanaBootData = {"settings":{"buildInfo":{"version":"10.4.2","commit":"abc"}}};</script></body>`
	kibanaBody := `<div data-test-subj="kibanaChrome"><kbn-injected-metadata data="x"></kbn-injected-metadata></div>`

	t.Run("grafana login", func(t *testing.T) {
		res := runLoginModule(t, grafana, 200, nil, grafanaBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a grafana finding")
		}
		if v := loginExtract(res, "grafana_version"); v != "10.4.2" {
			t.Errorf("grafana_version=%q, want 10.4.2", v)
		}
	})

	t.Run("kibana via response headers", func(t *testing.T) {
		res := runLoginModule(t, kibana, 200, map[string]string{"kbn-version": "8.13.0", "kbn-name": "node-1"}, kibanaBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kibana finding")
		}
		if v := loginExtract(res, "kibana_version"); v != "8.13.0" {
			t.Errorf("kibana_version=%q, want 8.13.0", v)
		}
	})

	t.Run("jenkins via X-Jenkins header on a 403", func(t *testing.T) {
		res := runLoginModule(t, jenkins, 403, map[string]string{"X-Jenkins": "2.426.1"},
			`<html><head><title>Authentication required</title></head></html>`)
		if len(res.Findings) == 0 {
			t.Fatal("expected a jenkins finding")
		}
		if v := loginExtract(res, "jenkins_version"); v != "2.426.1" {
			t.Errorf("jenkins_version=%q, want 2.426.1", v)
		}
	})

	t.Run("unrelated page is not a panel", func(t *testing.T) {
		for _, file := range []string{grafana, kibana, jenkins} {
			if res := runLoginModule(t, file, 200, nil, "<html><body>plain</body></html>"); len(res.Findings) > 0 {
				t.Errorf("%s: unrelated page should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
