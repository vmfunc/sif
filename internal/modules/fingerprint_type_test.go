package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fpTypeModule is a fingerprint expressed as its own module type: three weighted
// signatures (0.5 + 0.3 + 0.2) plus a version regex.
func fpTypeModule(confidence float32) *YAMLModule {
	return &YAMLModule{
		ID:   "fp-test",
		Type: TypeFingerprint,
		Info: YAMLModuleInfo{Severity: "info"},
		Fingerprint: &FingerprintConfig{
			Confidence: confidence,
			Signatures: []FPSignature{
				{Pattern: "alpha", Weight: 0.5},
				{Pattern: "beta", Weight: 0.3},
				{Pattern: "gamma", Weight: 0.2},
			},
			Version: &FPVersion{Regex: `alpha/(\d+\.\d+)`, Group: 1},
		},
	}
}

func TestFingerprintTypeScoring(t *testing.T) {
	// body matches alpha (0.5) + beta (0.3) = 0.8 of total weight; gamma absent.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("banner: alpha/2.4 and beta present"))
	}))
	defer srv.Close()

	opts := Options{Timeout: 5 * time.Second, Threads: 1}

	res, err := ExecuteFingerprintModule(context.Background(), srv.URL, fpTypeModule(0.5), opts)
	if err != nil {
		t.Fatalf("execute at 0.5: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("threshold 0.5: want 1 finding, got %d", len(res.Findings))
	}
	if got := res.Findings[0].Confidence; got < 0.79 || got > 0.81 {
		t.Errorf("confidence = %v, want ~0.8", got)
	}
	if got := res.Findings[0].Extracted["version"]; got != "2.4" {
		t.Errorf("version = %q, want 2.4", got)
	}

	res2, err := ExecuteFingerprintModule(context.Background(), srv.URL, fpTypeModule(0.9), opts)
	if err != nil {
		t.Fatalf("execute at 0.9: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Fatalf("threshold 0.9: want 0 findings (score 0.8 < 0.9), got %d", len(res2.Findings))
	}
}
