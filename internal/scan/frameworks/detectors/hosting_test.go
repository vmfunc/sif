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

func TestHostingDetectors_Positive(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		headers  http.Header
	}{
		{"Vercel", &vercelDetector{}, hdr("x-vercel-id", "sfo1::pdx1::dmmpr-1782439760448-608ebdfc")},
		{"Netlify", &netlifyDetector{}, hdr("x-nf-request-id", "01KW0V0MYRFJKYYNDRP7KC5DAJ")},
		{"GitHub Pages", &githubPagesDetector{}, hdr("x-github-request-id", "8714:20C798:191901:19DD8B:6A3DDD67")},
		{"Cloudflare", &cloudflareDetector{}, hdr("cf-ray", "a118ab5d9e7867e8-SJC")},
		{"CloudFront", &cloudfrontDetector{}, hdr("x-amz-cf-id", "0MsbJpMBovZpIG2KNmafF4RVM4GXD_iKAnm9friazwXUpC")},
		{"Akamai GRN", &akamaiDetector{}, hdr("Akamai-GRN", "0.1ea7cb17.1782439763.4a41c389")},
		{"Akamai server", &akamaiDetector{}, hdr("Server", "AkamaiGHost")},
		{"Fly.io", &flyDetector{}, hdr("fly-request-id", "01KW0V0QBEWMQ51YPTNZKE3EYJ-sjc")},
		{"Amazon S3 server", &amazonS3Detector{}, hdr("Server", "AmazonS3")},
		{"Amazon S3 region", &amazonS3Detector{}, hdr("x-amz-bucket-region", "us-east-2")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect("", tt.headers)
			if conf <= 0.5 {
				t.Errorf("%s: confidence = %.3f, want > 0.5", tt.name, conf)
			}
		})
	}
}

func TestHostingDetectors_Negative(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		headers  http.Header
	}{
		{"Vercel plain", &vercelDetector{}, hdr("Server", "nginx/1.25.3")},
		{"Netlify plain", &netlifyDetector{}, hdr("Server", "nginx")},
		{"Cloudflare plain", &cloudflareDetector{}, hdr("Server", "nginx")},
		{"GitHub link header", &githubPagesDetector{}, hdr("Link", "<https://github.com/o/r>; rel=canonical")},
		{"Akamai csp asset", &akamaiDetector{}, hdr("Content-Security-Policy", "img-src https://example.akamaihd.net")},
		{"S3 generic amz id", &amazonS3Detector{}, hdr("x-amz-request-id", "4Y0WES8AVK3ZQ98N")},
		{"Fly plain", &flyDetector{}, hdr("Server", "Cowboy")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect("", tt.headers)
			if conf > 0.5 {
				t.Errorf("%s: confidence = %.3f, want <= 0.5", tt.name, conf)
			}
		})
	}
}
