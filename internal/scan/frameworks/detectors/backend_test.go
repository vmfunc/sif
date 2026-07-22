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

package detectors

import (
	"net/http"
	"testing"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func TestWebFrameworkDetectors_Positive(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		headers  http.Header
	}{
		{"Tornado", &tornadoDetector{}, "", hdr("Server", "TornadoServer/6.4.1")},
		{"CherryPy", &cherrypyDetector{}, "", hdr("Server", "CherryPy/18.8.0")},
		{"Play session", &playDetector{}, "", hdr("Set-Cookie", "PLAY_SESSION=eyJhbGci; Path=/; HTTPOnly")},
		{"Sails.js", &sailsDetector{}, "", hdr("Set-Cookie", "sails.sid=s%3Aabc.def; Path=/; HttpOnly")},
		{"Beego", &beegoDetector{}, "", hdr("Set-Cookie", "beegosessionID=8f2a1c; Path=/; HttpOnly")},
		{"JSF javax", &jsfDetector{}, `<input type="hidden" name="javax.faces.ViewState" id="j_id1:javax.faces.ViewState:0" value="x" autocomplete="off" />`, http.Header{}},
		{"JSF jakarta", &jsfDetector{}, `<input type="hidden" name="jakarta.faces.ViewState" value="x" />`, http.Header{}},
		{"GWT", &gwtDetector{}, `<script type="text/javascript" language="javascript" src="myapp/myapp.nocache.js"></script>`, http.Header{}},
		{"GWT meta combo", &gwtDetector{}, `<meta name="gwt:property" content="locale=en"><iframe id="__gwt_historyFrame"></iframe>`, http.Header{}},
		{"Vaadin security key", &vaadinDetector{}, `{"appConfig":{"uidl":{"Vaadin-Security-Key":"f0ef03d7-0cf4-4f32-834d-47b88a1034b7"}}}`, http.Header{}},
		{"Vaadin Flow deferred", &vaadinDetector{}, `<script>window.Vaadin = window.Vaadin || {};window.Vaadin.Flow = {};</script><script type="module" src="./VAADIN/build/vaadin-bundle-1a2b.js"></script>`, http.Header{}},
		{"ColdFusion pair", &coldfusionDetector{}, "", hdr("Set-Cookie", "CFID=2401; CFTOKEN=55be99e7c")},
		{"ColdFusion token only", &coldfusionDetector{}, "", hdr("Set-Cookie", "CFTOKEN=55be99e7c2f8b2a1")},
		{"Strapi powered-by", &strapiDetector{}, "", hdr("X-Powered-By", "Strapi <strapi.io>")},
		{"CakePHP cookie", &cakephpDetector{}, "", hdr("Set-Cookie", "CAKEPHP=8f2a1c4e; path=/; HttpOnly")},
		{"Express powered-by", &expressDetector{}, "", hdr("X-Powered-By", "Express")},
		{"Flask werkzeug server", &flaskDetector{}, "", hdr("Server", "Werkzeug/2.3.0 Python/3.11")},
		{"Symfony debug token", &symfonyDetector{}, "", hdr("X-Debug-Token", "a1b2c3")},
		{"Symfony sf2 session cookie", &symfonyDetector{}, "", hdr("Set-Cookie", "_sf2_ses=8f2a1c4e9d3b; path=/; HttpOnly")},
		{"Spring Boot whitelabel", &springBootDetector{}, `<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p><div>There was an unexpected error (type=Not Found, status=404).</div></body></html>`, http.Header{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect(tt.body, tt.headers)
			if conf <= 0.5 {
				t.Errorf("%s: confidence = %.3f, want > 0.5", tt.name, conf)
			}
		})
	}
}

func TestWebFrameworkDetectors_Negative(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		headers  http.Header
	}{
		{"JSF prose", &jsfDetector{}, "<p>In JSF, the javax.faces.ViewState field stores view state.</p>", http.Header{}},
		{"GWT prose", &gwtDetector{}, "<p>GWT writes a .nocache.js bootstrap that is never cached.</p>", http.Header{}},
		{"Vaadin prose", &vaadinDetector{}, "<p>Vaadin is a Java web framework with a Vaadin-Security-Key concept.</p>", http.Header{}},
		{"Vaadin path only", &vaadinDetector{}, `<link href="/VAADIN/themes/mytheme/styles.css">`, http.Header{}},
		{"Vaadin global only", &vaadinDetector{}, `<script>window.Vaadin = window.Vaadin || {};</script>`, http.Header{}},
		{"ColdFusion id only", &coldfusionDetector{}, "", hdr("Set-Cookie", "CFID=2401; Path=/")},
		{"CakePHP prose", &cakephpDetector{}, `<a href="/questions/tagged/cakephp">cakephp tag</a>`, http.Header{}},
		{"Strapi prose", &strapiDetector{}, "<p>Strapi is an open source headless CMS built on Node.</p>", http.Header{}},
		{"Strapi domain link header", &strapiDetector{}, "", hdr("Link", "<https://strapi.io/docs>; rel=help")},
		{"Express checkout cookie", &expressDetector{}, "", hdr("Set-Cookie", "express_checkout=1; path=/")},
		{"Flask werkzeug docs link", &flaskDetector{}, "", hdr("Link", "<https://werkzeug.palletsprojects.com>; rel=help")},
		{"CherryPy domain link", &cherrypyDetector{}, "", hdr("Link", "<https://cherrypy.dev>; rel=help")},
		{"Tornado via header", &tornadoDetector{}, "", hdr("Via", "1.1 proxy-fronting-tornadoserver")},
		{"Symfony domain link", &symfonyDetector{}, "", hdr("Link", "<https://symfony.com/x>; rel=help")},
		{"Symfony near-miss cookie", &symfonyDetector{}, "", hdr("Set-Cookie", "misfa_sf_token=abc123; path=/")},
		{"Spring Boot tutorial prose", &springBootDetector{}, `<article>To fix the Whitelabel Error Page in Spring Boot, add a controller.</article>`, http.Header{}},
		{"plain page Tornado", &tornadoDetector{}, "<html><body>hello</body></html>", hdr("Server", "nginx/1.25.3")},
		{"plain page Play", &playDetector{}, "<html></html>", hdr("Set-Cookie", "sessionid=abc; Path=/")},
		{"plain page ColdFusion", &coldfusionDetector{}, "<html></html>", hdr("Set-Cookie", "JSESSIONID=abc; Path=/")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect(tt.body, tt.headers)
			if conf > 0.5 {
				t.Errorf("%s: confidence = %.3f, want <= 0.5", tt.name, conf)
			}
		})
	}
}

func TestWebFrameworkDetectors_Version(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		headers  http.Header
		want     string
	}{
		{"Tornado", &tornadoDetector{}, hdr("Server", "TornadoServer/6.4.1"), "6.4.1"},
		{"CherryPy", &cherrypyDetector{}, hdr("Server", "CherryPy/18.8.0"), "18.8.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, version := tt.detector.Detect("", tt.headers)
			if version != tt.want {
				t.Errorf("%s: version = %q, want %q", tt.name, version, tt.want)
			}
		})
	}
}
