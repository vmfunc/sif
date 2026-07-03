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

package frameworks_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/scan/frameworks"
	// import detectors to register both the framework and CDN detector pools
	// via their respective init()s.
	_ "github.com/vmfunc/sif/internal/scan/frameworks/detectors"
)

// TestDetectFramework_CloudflareFrontedNextJS locks the anti-suppression fix: a
// Cloudflare-fronted Next.js site must report Next.js from DetectFramework and
// Cloudflare from the independent DetectCDN, not one crowding out the other. A
// Cloudflare detector in the shared registry would instead win the global argmax
// on cf-ray alone (see TestCDNSignatureWouldOutrankFramework).
func TestDetectFramework_CloudflareFrontedNextJS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-RAY", "7d1f4a2b3c4d5e6f-LAX")
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Test</title></head>
			<body>
				<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
				<script src="/_next/static/chunks/main.js"></script>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	fwResult, err := frameworks.DetectFramework(server.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("DetectFramework: unexpected error: %v", err)
	}
	if fwResult == nil {
		t.Fatal("DetectFramework: expected a result, got nil")
	}
	if fwResult.Name != "Next.js" {
		t.Fatalf("DetectFramework: expected 'Next.js' despite the Cloudflare headers, got %q (confidence %.3f): a CDN detector is suppressing framework detection",
			fwResult.Name, fwResult.Confidence)
	}

	// fetch the same response and run the CDN pool over it directly, the way a
	// caller that already holds a response runs both detections off one request.
	resp, err := http.Get(server.URL) //nolint:gosec,bodyclose // test server, closed below
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	cdnResult := frameworks.DetectCDN(string(body), resp.Header)
	if cdnResult == nil {
		t.Fatal("DetectCDN: expected a result, got nil")
	}
	if cdnResult.Name != "Cloudflare" {
		t.Errorf("DetectCDN: expected 'Cloudflare', got %q", cdnResult.Name)
	}
}

// TestCDNSignatureWouldOutrankFramework shows why CDN detectors stay out of
// DetectFramework's registry: a single-signature CDN detector (a bare cf-ray
// header, weight 1.0, no dilution) beats even a strong Next.js match under the
// shared sigmoidConfidence curve.
func TestCDNSignatureWouldOutrankFramework(t *testing.T) {
	cloudflare := frameworks.NewBaseDetector("Cloudflare", []frameworks.Signature{
		{Pattern: "cf-ray", Weight: 1.0, HeaderOnly: true},
	})
	nextjs := frameworks.NewBaseDetector("Next.js", []frameworks.Signature{
		{Pattern: "__NEXT_DATA__", Weight: 0.5},
		{Pattern: "_next/static", Weight: 0.4},
		{Pattern: "__next", Weight: 0.3},
		{Pattern: "x-nextjs", Weight: 0.3, HeaderOnly: true},
	})

	headers := http.Header{}
	headers.Set("CF-RAY", "7d1f4a2b3c4d5e6f-LAX")
	body := `<script id="__NEXT_DATA__">{}</script><script src="/_next/static/x.js"></script>`

	cfScore := cloudflare.MatchSignatures(body, headers)
	nextScore := nextjs.MatchSignatures(body, headers)

	if cfScore <= nextScore {
		t.Fatalf("expected the single-signature CDN score (%.3f) to exceed the diluted framework score (%.3f), the setup that motivated RegisterCDN as a separate pool", cfScore, nextScore)
	}
}
