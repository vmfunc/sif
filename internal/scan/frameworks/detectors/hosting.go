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

package detectors

import (
	"net/http"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

// Detectors in this file identify the hosting platform or edge/CDN provider in
// front of a target rather than its application framework.

func init() {
	fw.Register(&vercelDetector{})
	fw.Register(&netlifyDetector{})
	fw.Register(&githubPagesDetector{})
	fw.Register(&cloudflareDetector{})
	fw.Register(&cloudfrontDetector{})
	fw.Register(&akamaiDetector{})
	fw.Register(&flyDetector{})
	fw.Register(&amazonS3Detector{})
}

type vercelDetector struct{}

func (d *vercelDetector) Name() string { return "Vercel" }

func (d *vercelDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-vercel", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *vercelDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

type netlifyDetector struct{}

func (d *netlifyDetector) Name() string { return "Netlify" }

func (d *netlifyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-nf-request-id", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *netlifyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

// githubPagesDetector detects GitHub Pages (and GitHub-hosted infrastructure).
type githubPagesDetector struct{}

func (d *githubPagesDetector) Name() string { return "GitHub Pages" }

func (d *githubPagesDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-github-request-id", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *githubPagesDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

type cloudflareDetector struct{}

func (d *cloudflareDetector) Name() string { return "Cloudflare" }

func (d *cloudflareDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "cf-ray", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *cloudflareDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

// cloudfrontDetector detects the Amazon CloudFront CDN.
type cloudfrontDetector struct{}

func (d *cloudfrontDetector) Name() string { return "Amazon CloudFront" }

func (d *cloudfrontDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "x-amz-cf-id", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *cloudfrontDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

type akamaiDetector struct{}

func (d *akamaiDetector) Name() string { return "Akamai" }

func (d *akamaiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Akamai-GRN", Weight: 0.5, HeaderOnly: true},
		{Pattern: "x-akamai", Weight: 0.4, HeaderOnly: true},
		{Pattern: "AkamaiGHost", Weight: 0.4, HeaderOnly: true},
	}
}

func (d *akamaiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

type flyDetector struct{}

func (d *flyDetector) Name() string { return "Fly.io" }

func (d *flyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "fly-request-id", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *flyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}

// amazonS3Detector detects content served from an Amazon S3 bucket.
type amazonS3Detector struct{}

func (d *amazonS3Detector) Name() string { return "Amazon S3" }

func (d *amazonS3Detector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "AmazonS3", Weight: 0.6, HeaderOnly: true},
		{Pattern: "x-amz-bucket-region", Weight: 0.4, HeaderOnly: true},
	}
}

func (d *amazonS3Detector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	return sigmoidConfidence(score), ""
}
