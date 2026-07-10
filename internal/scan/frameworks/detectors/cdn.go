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

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func init() {
	// registered against fw.RegisterCDN, not fw.Register: these compete in
	// their own DetectCDN argmax, never against application frameworks. see
	// the comment on cdnRegistry in cdn.go for why.
	fw.RegisterCDN(&cloudflareDetector{})
	fw.RegisterCDN(&fastlyDetector{})
	fw.RegisterCDN(&akamaiDetector{})
	fw.RegisterCDN(&cloudfrontDetector{})
	fw.RegisterCDN(&vercelDetector{})
	fw.RegisterCDN(&netlifyDetector{})
}

// all CDN signatures are HeaderOnly and scoped to the specific edge-injected
// header the provider controls, never a bare brand substring: a page that
// merely mentions "cloudflare" in its body (a badge, a blog post, a status
// widget) must not fire, only the response the edge itself stamped.

type cloudflareDetector struct{}

func (d *cloudflareDetector) Name() string { return "Cloudflare" }

func (d *cloudflareDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		// header name cf-ray is injected by every Cloudflare-proxied response.
		{Pattern: "cf-ray", Weight: 0.6, HeaderOnly: true},
		{Pattern: "cloudflare", Weight: 0.4, HeaderOnly: true, Header: "Server"},
	}
}

func (d *cloudflareDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	return sigmoidConfidence(base.MatchSignatures(body, headers)), ""
}

type fastlyDetector struct{}

func (d *fastlyDetector) Name() string { return "Fastly" }

func (d *fastlyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		// x-fastly-request-id is only emitted by fastly's own edge; a plain
		// varnish deployment (fastly is varnish-based) never sends it, so this
		// stays clear of the generic "Via: 1.1 varnish" false positive.
		{Pattern: "x-fastly-request-id", Weight: 0.6, HeaderOnly: true},
		{Pattern: "fastly", Weight: 0.4, HeaderOnly: true, Header: "Via"},
	}
}

func (d *fastlyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	return sigmoidConfidence(base.MatchSignatures(body, headers)), ""
}

type akamaiDetector struct{}

func (d *akamaiDetector) Name() string { return "Akamai" }

func (d *akamaiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "akamai-grn", Weight: 0.5, HeaderOnly: true},
		{Pattern: "x-akamai", Weight: 0.5, HeaderOnly: true},
	}
}

func (d *akamaiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	return sigmoidConfidence(base.MatchSignatures(body, headers)), ""
}

type cloudfrontDetector struct{}

func (d *cloudfrontDetector) Name() string { return "Amazon CloudFront" }

func (d *cloudfrontDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-amz-cf-id", Weight: 0.5, HeaderOnly: true},
		{Pattern: "cloudfront", Weight: 0.5, HeaderOnly: true, Header: "Via"},
	}
}

func (d *cloudfrontDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	return sigmoidConfidence(base.MatchSignatures(body, headers)), ""
}

type vercelDetector struct{}

func (d *vercelDetector) Name() string { return "Vercel" }

func (d *vercelDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-vercel-id", Weight: 0.5, HeaderOnly: true},
		{Pattern: "vercel", Weight: 0.5, HeaderOnly: true, Header: "Server"},
	}
}

func (d *vercelDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	return sigmoidConfidence(base.MatchSignatures(body, headers)), ""
}

type netlifyDetector struct{}

func (d *netlifyDetector) Name() string { return "Netlify" }

func (d *netlifyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-nf-request-id", Weight: 0.5, HeaderOnly: true},
		{Pattern: "netlify", Weight: 0.5, HeaderOnly: true, Header: "Server"},
	}
}

func (d *netlifyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	return sigmoidConfidence(base.MatchSignatures(body, headers)), ""
}
