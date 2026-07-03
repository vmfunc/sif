/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

/*

   BSD 3-Clause License
   (c) 2022-2026 vmfunc, xyzeva & contributors

*/

package detectors

import (
	"net/http"
	"testing"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

// cdnHeaders builds a header set from name/value pairs for readability in
// the table below (unlike accHeader in accuracy_test.go, most CDN cases need
// more than one header set at once).
func cdnHeaders(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

func TestCDNDetectors_TruePositives(t *testing.T) {
	cases := []struct {
		name string
		det  fw.Detector
		h    http.Header
	}{
		{"Cloudflare ray + server", &cloudflareDetector{}, cdnHeaders("CF-RAY", "7d1f4a2b3c4d5e6f-LAX", "Server", "cloudflare")},
		{"Fastly request id", &fastlyDetector{}, cdnHeaders("X-Fastly-Request-ID", "3a2b1c", "Via", "1.1 varnish")},
		{"Akamai grn", &akamaiDetector{}, cdnHeaders("Akamai-GRN", "0.abcd1234.1234567.abcdef", "X-Cache", "TCP_MISS from a23-1-2-3.akamai.net")},
		{"CloudFront amz id + via", &cloudfrontDetector{}, cdnHeaders("X-Amz-Cf-Id", "abc123", "Via", "1.1 abcdef.cloudfront.net (CloudFront)")},
		{"Vercel id + server", &vercelDetector{}, cdnHeaders("X-Vercel-Id", "sfo1::abcde", "Server", "Vercel")},
		{"Netlify request id + server", &netlifyDetector{}, cdnHeaders("X-Nf-Request-Id", "01abc", "Server", "Netlify")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if conf, _ := c.det.Detect("", c.h); conf <= 0.5 {
				t.Errorf("missed: confidence = %.3f, want > 0.5", conf)
			}
		})
	}
}

func TestCDNDetectors_FalsePositives(t *testing.T) {
	cases := []struct {
		name string
		det  fw.Detector
		h    http.Header
	}{
		// generic reverse proxy: a Via header with no vendor token at all.
		{"Cloudflare vs generic via-only proxy", &cloudflareDetector{}, cdnHeaders("Via", "1.1 proxy.internal")},
		// self-hosted varnish, no fastly-only header present.
		{"Fastly vs bare varnish", &fastlyDetector{}, cdnHeaders("Via", "1.1 varnish (Varnish/6.0)", "X-Cache", "HIT")},
		// generic x-cache/x-served-by pair a lot of CDN-agnostic caches emit.
		{"Akamai vs generic cache headers", &akamaiDetector{}, cdnHeaders("X-Cache", "HIT", "X-Served-By", "cache-lax1")},
		{"CloudFront vs generic via proxy", &cloudfrontDetector{}, cdnHeaders("Via", "1.1 mycompany-proxy")},
		{"Vercel vs generic node server", &vercelDetector{}, cdnHeaders("Server", "nginx", "X-Powered-By", "Express")},
		{"Netlify vs generic static host", &netlifyDetector{}, cdnHeaders("Server", "nginx")},
		// prose/body mention: badge markup naming the provider must never
		// count, only headers the edge itself stamps.
		{"Cloudflare body-only badge", &cloudflareDetector{}, http.Header{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := ""
			if c.name == "Cloudflare body-only badge" {
				body = `<img src="/cloudflare-badge.png" alt="Protected by Cloudflare">`
			}
			if conf, _ := c.det.Detect(body, c.h); conf > 0.5 {
				t.Errorf("false positive: confidence = %.3f, want <= 0.5", conf)
			}
		})
	}
}

func TestCDNDetectors_Registered(t *testing.T) {
	for _, name := range []string{"Cloudflare", "Fastly", "Akamai", "Amazon CloudFront", "Vercel", "Netlify"} {
		if _, ok := fw.GetCDNDetectors()[name]; !ok {
			t.Errorf("%s should be registered via RegisterCDN", name)
		}
	}
}

func TestCDNDetectors_NotInFrameworkRegistry(t *testing.T) {
	// the whole point of RegisterCDN is that these never compete in
	// DetectFramework's single-winner argmax. prove none leaked into the
	// shared registry via a stray fw.Register call.
	for _, name := range []string{"Cloudflare", "Fastly", "Akamai", "Amazon CloudFront", "Vercel", "Netlify"} {
		if _, ok := fw.GetDetector(name); ok {
			t.Errorf("%s must not be in the shared framework registry (breaks argmax isolation)", name)
		}
	}
}
