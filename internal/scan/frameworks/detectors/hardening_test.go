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

/*

   BSD 3-Clause License
   (c) 2022-2026 vmfunc, xyzeva & contributors

*/

// this file pins the fp/fn corpus behind the framework-detector hardening
// pass: for each fixed defect it asserts BOTH the real-product positive
// still detects and the prose/other-product negative does not.
package detectors

import (
	"net/http"
	"testing"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func hdr(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}

func detect(t *testing.T, name, body string, headers http.Header) (float32, string) {
	t.Helper()
	d, ok := fw.GetDetector(name)
	if !ok {
		t.Fatalf("detector %q not registered", name)
	}
	if headers == nil {
		headers = http.Header{}
	}
	return d.Detect(body, headers)
}

// --- Django ---

func TestDjango_BodyFieldPlusCookieDetects(t *testing.T) {
	body := `<form><input type="hidden" name="csrfmiddlewaretoken" value="abc"></form>`
	conf, _ := detect(t, "Django", body, hdr("Set-Cookie", "csrftoken=xyz; Path=/"))
	if conf <= 0.5 {
		t.Errorf("real Django page (csrf body field + csrftoken cookie) confidence = %.3f, want > 0.5", conf)
	}
}

func TestDjango_RandomPageNoMatch(t *testing.T) {
	conf, _ := detect(t, "Django", "<html><body>hello</body></html>", http.Header{})
	if conf > 0.5 {
		t.Errorf("random page with no django markers confidence = %.3f, want <= 0.5", conf)
	}
}

// --- ASP.NET ---

func TestASPNET_CanonicalHeadersAloneDetects(t *testing.T) {
	headers := hdr(
		"X-AspNet-Version", "4.0.30319",
		"X-Powered-By", "ASP.NET",
		"Server", "Microsoft-IIS/10.0",
	)
	conf, _ := detect(t, "ASP.NET", `{"status":"ok"}`, headers)
	if conf <= 0.5 {
		t.Errorf("ASP.NET canonical headers (no body markers) confidence = %.3f, want > 0.5", conf)
	}
}

func TestASPNET_VersionExtractedFromHeader(t *testing.T) {
	headers := hdr("X-AspNet-Version", "4.0.30319", "X-Powered-By", "ASP.NET")
	_, version := detect(t, "ASP.NET", `{"status":"ok"}`, headers)
	if version != "4.0.30319" {
		t.Errorf("ASP.NET version = %q, want %q (extracted from X-AspNet-Version header)", version, "4.0.30319")
	}
}

func TestASPNET_NoVersionWithoutHeader(t *testing.T) {
	// body markers alone push confidence over threshold but there is no
	// version anywhere in the response; must not fabricate one.
	body := `<form><input type="hidden" name="__VIEWSTATE" value="x"><input type="hidden" name="__EVENTVALIDATION" value="y">` +
		`<input type="hidden" name="__VIEWSTATEGENERATOR" value="z"></form>`
	conf, version := detect(t, "ASP.NET", body, http.Header{})
	if conf <= 0.5 {
		t.Fatalf("setup: expected ASP.NET body markers to detect, confidence = %.3f", conf)
	}
	if version != "" && version != "unknown" {
		t.Errorf("ASP.NET version = %q, want empty/unknown with no version marker present", version)
	}
}

// --- Flask ---

func TestFlask_VersionExtractedFromServerHeader(t *testing.T) {
	_, version := detect(t, "Flask", "<html></html>", hdr("Server", "Werkzeug/2.3.0 Python/3.11"))
	if version != "2.3.0" {
		t.Errorf("Flask version = %q, want %q (extracted from Werkzeug Server header)", version, "2.3.0")
	}
}

// --- CakePHP ---

func TestCakePHP_CookieDetects(t *testing.T) {
	conf, _ := detect(t, "CakePHP", "<html><body>Home</body></html>", hdr("Set-Cookie", "CAKEPHP=abc123; path=/"))
	if conf <= 0.5 {
		t.Errorf("CakePHP CAKEPHP cookie confidence = %.3f, want > 0.5", conf)
	}
}

// --- Angular ---

func TestAngular_NgVersionAloneDetects(t *testing.T) {
	body := `<app-root ng-version="17.3.0"></app-root>`
	conf, _ := detect(t, "Angular", body, nil)
	if conf <= 0.5 {
		t.Errorf("Angular ng-version attribute alone confidence = %.3f, want > 0.5", conf)
	}
}

func TestAngular_ProseMentionDoesNotDetect(t *testing.T) {
	body := `<html><body><article>Angular automatically stamps an ng-version marker
	onto the root element for diagnostics purposes; see the ng-version docs for details.</article></body></html>`
	conf, _ := detect(t, "Angular", body, nil)
	if conf > 0.5 {
		t.Errorf("prose mention of ng-version confidence = %.3f, want <= 0.5", conf)
	}
}

// --- Astro ---

func TestAstro_GeneratorMetaAloneDetects(t *testing.T) {
	body := `<meta name="generator" content="Astro v4.5.0">`
	conf, _ := detect(t, "Astro", body, nil)
	if conf <= 0.5 {
		t.Errorf("Astro generator meta alone confidence = %.3f, want > 0.5", conf)
	}
}

func TestAstro_ProseMentionDoesNotDetect(t *testing.T) {
	body := `<html><body><article>Astro is a popular static site generator that
	many teams evaluate alongside Next.js and SvelteKit.</article></body></html>`
	conf, _ := detect(t, "Astro", body, nil)
	if conf > 0.5 {
		t.Errorf("prose mention of Astro confidence = %.3f, want <= 0.5", conf)
	}
}

// --- Next.js ---

func TestNextJS_StaticAssetAloneDetects(t *testing.T) {
	body := `<html><head><link rel="stylesheet" href="/_next/static/css/abc.css">` +
		`<script src="/_next/static/chunks/main.js"></script></head><body></body></html>`
	conf, _ := detect(t, "Next.js", body, hdr("Server", "nginx"))
	if conf <= 0.5 {
		t.Errorf("self-hosted app-router Next.js (only /_next/static) confidence = %.3f, want > 0.5", conf)
	}
}

func TestNextJS_ProseMentionDoesNotDetect(t *testing.T) {
	body := `<html><body><p>Static assets live under /_next/static/ by Next.js convention.</p></body></html>`
	conf, _ := detect(t, "Next.js", body, nil)
	if conf > 0.5 {
		t.Errorf("prose mention of /_next/static/ confidence = %.3f, want <= 0.5", conf)
	}
}

// --- Full-corpus sweep ---

func TestSweep_GenericPagesNoFire(t *testing.T) {
	cases := []struct {
		name string
		body string
		hdr  http.Header
	}{
		{
			name: "plain nginx welcome",
			body: `<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed.</p></body></html>`,
			hdr:  hdr("Server", "nginx/1.24.0", "Content-Type", "text/html"),
		},
		{
			name: "apache php site",
			body: `<html><body><h1>My PHP Site</h1><form method="post"><input name="q"></form></body></html>`,
			hdr:  hdr("Server", "Apache/2.4.57", "X-Powered-By", "PHP/8.2.0", "Set-Cookie", "PHPSESSID=abc; path=/"),
		},
		{
			name: "tech blog article listing frameworks",
			body: `<html><body><article>2026 framework roundup: we cover Joomla, Magento, Drupal, WordPress, Ghost, Symfony, Meteor, and Angular in depth.</article></body></html>`,
			hdr:  hdr("Server", "nginx"),
		},
		{
			name: "generic java tomcat app",
			body: `<html><body>Login</body></html>`,
			hdr:  hdr("Server", "Apache-Coyote/1.1", "Set-Cookie", "JSESSIONID=1A2B3C; Path=/; HttpOnly"),
		},
	}

	dets := fw.GetDetectors()
	for _, c := range cases {
		headers := c.hdr
		if headers == nil {
			headers = http.Header{}
		}
		for name, d := range dets {
			conf, ver := d.Detect(c.body, headers)
			if conf > 0.5 {
				t.Errorf("%s: detector %q false-fired confidence=%.4f version=%q", c.name, name, conf, ver)
			}
		}
	}
}
