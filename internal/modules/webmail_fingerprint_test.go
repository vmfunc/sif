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

func runWebmailModule(t *testing.T, file string, status int, headers map[string]string, body string) *modules.Result {
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

func webmailExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

// TestRoundcubeWebmailModule validates the roundcube-webmail fingerprint against a
// realistic rendering of the elastic skin login.html (skins/elastic/templates/login.html
// plus program/include/rcmail_output_html.php's `var rcmail = new rcube_webmail();` head_top
// bootstrap). display_product_info defaults to 1 (name only, no version), so the
// version-bearing sample models an admin who bumped it to 2.
func TestRoundcubeWebmailModule(t *testing.T) {
	const rc = "../../modules/info/roundcube-webmail.yaml"

	nameOnlyBody := `<!DOCTYPE html><html><head><title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>
<script>var rcmail = new rcube_webmail();</script></head>
<body>
<h1 class="voice">Roundcube Webmail Login</h1>
<div id="layout-content" class="selected no-navbar" role="main">
<form id="login-form" name="login-form" method="post" class="propform">
<div id="login-footer" role="contentinfo">Roundcube Webmail</div>
</form></div></body></html>`

	versionBody := `<!DOCTYPE html><html><head><title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>
<script>var rcmail = new rcube_webmail();</script></head>
<body>
<h1 class="voice">Roundcube Webmail Login</h1>
<div id="layout-content" class="selected no-navbar" role="main">
<form id="login-form" name="login-form" method="post" class="propform">
<div id="login-footer" role="contentinfo">Roundcube Webmail 1.6.9</div>
</form></div></body></html>`

	t.Run("default install with display_product_info=1 fingerprints without a version", func(t *testing.T) {
		res := runWebmailModule(t, rc, 200, nil, nameOnlyBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a roundcube finding")
		}
		if v := webmailExtract(res, "roundcube_version"); v != "" {
			t.Errorf("roundcube_version=%q, want empty (display_product_info=1 hides it)", v)
		}
	})

	t.Run("display_product_info=2 also yields the version", func(t *testing.T) {
		res := runWebmailModule(t, rc, 200, nil, versionBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a roundcube finding")
		}
		if v := webmailExtract(res, "roundcube_version"); v != "1.6.9" {
			t.Errorf("roundcube_version=%q, want 1.6.9", v)
		}
	})

	t.Run("a login page served through a cdn that strips Set-Cookie still fires", func(t *testing.T) {
		// the body pair is product-unique on its own; the fingerprint must not depend on a
		// session cookie a caching reverse-proxy commonly drops on cacheable responses.
		res := runWebmailModule(t, rc, 200, nil, nameOnlyBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a roundcube finding without any Set-Cookie header")
		}
	})

	t.Run("prose mentioning Roundcube Webmail without the app markers is not flagged", func(t *testing.T) {
		body := `<html><body><article><h1>Switching from Roundcube Webmail to something else</h1>
<p>We migrated off Roundcube Webmail last year after evaluating alternatives.</p></article></body></html>`
		if res := runWebmailModule(t, rc, 200, nil, body); len(res.Findings) > 0 {
			t.Errorf("a blog post mentioning roundcube should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 is not a leak", func(t *testing.T) {
		if res := runWebmailModule(t, rc, 200, nil, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})
}

// TestZimbraWebmailModule validates the zimbra-webmail fingerprint against the real,
// unauthenticated zm-web-client static asset WebRoot/js/zimbraMail/share/model/ZmSettings.js,
// whose license header literally reads "Zimbra Collaboration Suite Web Client" and whose
// CLIENT_VERSION registerSetting call carries the build's version string in production
// (the source repo ships the unbuilt "@buildVersion@" placeholder).
func TestZimbraWebmailModule(t *testing.T) {
	const zm = "../../modules/info/zimbra-webmail.yaml"

	builtBody := `/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Web Client
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Synacor, Inc.
 */
	this.registerSetting("BRANCH",							{type:ZmSetting.T_CONFIG, defaultValue:"JUDASPRIEST"});
	this.registerSetting("CLIENT_DATETIME",					{type:ZmSetting.T_CONFIG, defaultValue:"04/17/2024 12:00:00"});
	this.registerSetting("CLIENT_RELEASE",					{type:ZmSetting.T_CONFIG, defaultValue:"GA"});
	this.registerSetting("CLIENT_VERSION",					{type:ZmSetting.T_CONFIG, defaultValue:"8.8.12_GA_3844"});
	this.registerSetting("CONFIG_PATH",						{type:ZmSetting.T_CONFIG, defaultValue:appContextPath + "/js/zimbraMail/config"});
`

	unbuiltBody := `/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Web Client
 */
	this.registerSetting("CLIENT_VERSION",					{type:ZmSetting.T_CONFIG, defaultValue:"@buildVersion@"});
`

	t.Run("a built zm-web-client asset is flagged with its build version", func(t *testing.T) {
		res := runWebmailModule(t, zm, 200, map[string]string{"Content-Type": "application/x-javascript"}, builtBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a zimbra finding")
		}
		if v := webmailExtract(res, "zimbra_version"); v != "8.8.12_GA_3844" {
			t.Errorf("zimbra_version=%q, want 8.8.12_GA_3844", v)
		}
	})

	t.Run("an unbuilt source checkout fingerprints without a usable version", func(t *testing.T) {
		res := runWebmailModule(t, zm, 200, nil, unbuiltBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a zimbra finding even without a real build stamp")
		}
		if v := webmailExtract(res, "zimbra_version"); v != "" {
			t.Errorf("zimbra_version=%q, want empty (placeholder build value must not be captured)", v)
		}
	})

	t.Run("a sibling settings file mentioning CLIENT_VERSION alone is not flagged", func(t *testing.T) {
		// shares the CLIENT_VERSION token but not the Zimbra product string: proves the
		// product-string anchor, not the generic config key, is load-bearing.
		body := `this.registerSetting("CLIENT_VERSION", {type:Setting.T_CONFIG, defaultValue:"1.0.0"});`
		if res := runWebmailModule(t, zm, 200, nil, body); len(res.Findings) > 0 {
			t.Errorf("a generic settings file should not match zimbra, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runWebmailModule(t, zm, 404, nil, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
