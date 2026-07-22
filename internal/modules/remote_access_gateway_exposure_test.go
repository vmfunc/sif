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

func runRemoteAccessModule(t *testing.T, file string, status int, headers map[string]string, body string) *modules.Result {
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

func remoteAccessExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestRemoteAccessGatewayExposureModules(t *testing.T) {
	const guacamole = "../../modules/recon/guacamole-login-exposure.yaml"
	const webmin = "../../modules/recon/webmin-login-exposure.yaml"

	// real markup served by guacamole-client's index.html (guacamole/src/main/frontend/src/index.html):
	// the guacamole-common-js bundle and the <guac-login> element are always present server-side,
	// before any angular bootstrapping happens client-side.
	guacamoleBody := `<html ng-app="index" ng-controller="indexController"><head><title></title></head>` +
		`<body><guac-login ng-switch-when="awaitingCredentials" help-text="loginHelpText"></guac-login>` +
		`<script type="text/javascript" src="guacamole-common-js/all.min.js?b=1.5.5"></script>` +
		`</body></html>`

	t.Run("a guacamole login page is flagged with its build id", func(t *testing.T) {
		res := runRemoteAccessModule(t, guacamole, 200, nil, guacamoleBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a guacamole finding")
		}
		if v := remoteAccessExtract(res, "guacamole_build_id"); v != "1.5.5" {
			t.Errorf("guacamole_build_id=%q, want 1.5.5", v)
		}
	})

	t.Run("a page that only mentions guacamole in prose is not flagged", func(t *testing.T) {
		body := `<html><body><h1>my favorite guacamole recipe</h1>` +
			`<p>read more about apache guacamole, a remote desktop gateway, on their site.</p></body></html>`
		if res := runRemoteAccessModule(t, guacamole, 200, nil, body); len(res.Findings) > 0 {
			t.Errorf("prose mentioning guacamole should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a guac-login element without the bundled client js is not flagged", func(t *testing.T) {
		body := `<html><body><guac-login></guac-login></body></html>`
		if res := runRemoteAccessModule(t, guacamole, 200, nil, body); len(res.Findings) > 0 {
			t.Errorf("a lone guac-login tag should not match, got %d findings", len(res.Findings))
		}
	})

	// real markup/headers served by webmin's miniserv.pl + session_login.cgi:
	// server_info() defaults the Server header to "MiniServ" (or "MiniServ/<version>" once
	// installed), and session_login.cgi titles the form with the session_header lang string
	// ("Login to Webmin"), which Usermin renders as "Login to Usermin" instead.
	webminHeaders := map[string]string{"Server": "MiniServ/1.999"}
	webminBody := `<html><head><title>Login to Webmin</title></head><body>` +
		`<form action="/session_login.cgi" method="post">` +
		`<input type="text" name="user"><input type="password" name="pass">` +
		`</form></body></html>`

	t.Run("a webmin login page is flagged with its miniserv version", func(t *testing.T) {
		res := runRemoteAccessModule(t, webmin, 200, webminHeaders, webminBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a webmin finding")
		}
		if v := remoteAccessExtract(res, "webmin_version"); v != "1.999" {
			t.Errorf("webmin_version=%q, want 1.999", v)
		}
	})

	t.Run("usermin, which shares the MiniServ header, is not flagged as webmin", func(t *testing.T) {
		body := `<html><head><title>Login to Usermin</title></head><body>` +
			`<form action="/session_login.cgi" method="post"></form></body></html>`
		if res := runRemoteAccessModule(t, webmin, 200, webminHeaders, body); len(res.Findings) > 0 {
			t.Errorf("usermin should not match the webmin module, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic login form without the MiniServ header is not flagged", func(t *testing.T) {
		if res := runRemoteAccessModule(t, webmin, 200, nil, webminBody); len(res.Findings) > 0 {
			t.Errorf("a generic login form should not match webmin, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain unrelated page is not a gateway", func(t *testing.T) {
		for _, file := range []string{guacamole, webmin} {
			if res := runRemoteAccessModule(t, file, 200, nil, "<html><body>plain</body></html>"); len(res.Findings) > 0 {
				t.Errorf("%s: unrelated page should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a gateway", func(t *testing.T) {
		for _, file := range []string{guacamole, webmin} {
			if res := runRemoteAccessModule(t, file, 404, webminHeaders, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
