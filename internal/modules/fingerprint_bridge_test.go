package modules

import (
	"math/rand"
	"net/http"
	"testing"

	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// okFingerprintDef builds a root-path, default-confidence, all-positive-weight
// fingerprint module: the one shape the framework engine can reproduce exactly
// (the shared domain).
func okFingerprintDef(id string) *YAMLModule {
	return &YAMLModule{
		ID:   id,
		Type: TypeFingerprint,
		Fingerprint: &FingerprintConfig{
			Signatures: []FPSignature{
				{Pattern: "nginx", Weight: 1},
				{Pattern: "X-Powered-By", Weight: 2, Header: true},
			},
		},
	}
}

func TestBridgeFingerprint_RootDefaultPositiveWeight_Registers(t *testing.T) {
	def := okFingerprintDef("fp-bridge-ok")

	registered, reason := bridgeFingerprint(def)
	if !registered {
		t.Fatalf("bridgeFingerprint registered = false, reason %q, want true", reason)
	}

	det, ok := frameworks.GetDetector(def.ID)
	if !ok {
		t.Fatalf("frameworks.GetDetector(%q) not found after bridging", def.ID)
	}

	body := "served by nginx"
	headers := http.Header{"X-Powered-By": {"PHP"}}
	got, _ := det.Detect(body, headers)
	want, _ := scoreFingerprint(def.Fingerprint, body, headers)
	if got != want {
		t.Fatalf("bridged Detect = %v, scoreFingerprint = %v, want equal", got, want)
	}
}

func TestBridgeFingerprint_NonRootPath_Refuses(t *testing.T) {
	def := okFingerprintDef("fp-bridge-path")
	def.Fingerprint.Path = "/admin"

	registered, reason := bridgeFingerprint(def)
	if registered {
		t.Fatal("bridgeFingerprint registered a non-root fingerprint")
	}
	if reason == "" {
		t.Fatal("expected a non-empty refusal reason")
	}
	if _, ok := frameworks.GetDetector(def.ID); ok {
		t.Fatalf("frameworks.GetDetector(%q) found a detector that should have been refused", def.ID)
	}
}

func TestBridgeFingerprint_CustomConfidence_Refuses(t *testing.T) {
	def := okFingerprintDef("fp-bridge-conf")
	def.Fingerprint.Confidence = 0.7

	registered, reason := bridgeFingerprint(def)
	if registered {
		t.Fatal("bridgeFingerprint registered a custom-confidence fingerprint")
	}
	if reason == "" {
		t.Fatal("expected a non-empty refusal reason")
	}
	if _, ok := frameworks.GetDetector(def.ID); ok {
		t.Fatalf("frameworks.GetDetector(%q) found a detector that should have been refused", def.ID)
	}
}

// TestBridgeFingerprint_MatchesNativeAcrossSampledInputs proves the bridged
// detector and the native module scorer agree on the shared domain, mirroring
// TestScorerEquivalenceSharedDomain but through the bridge itself.
func TestBridgeFingerprint_MatchesNativeAcrossSampledInputs(t *testing.T) {
	def := okFingerprintDef("fp-bridge-sampled")
	registered, reason := bridgeFingerprint(def)
	if !registered {
		t.Fatalf("bridgeFingerprint registered = false, reason %q", reason)
	}
	det, ok := frameworks.GetDetector(def.ID)
	if !ok {
		t.Fatalf("frameworks.GetDetector(%q) not found after bridging", def.ID)
	}

	tokens := []string{"nginx", "X-Powered-By", "cloudflare", "wp-content"}
	r := rand.New(rand.NewSource(2))
	for iter := 0; iter < 500; iter++ {
		body := ""
		for _, tk := range tokens {
			if r.Intn(2) == 0 {
				body += tk + " "
			}
		}
		headers := http.Header{}
		for _, tk := range tokens {
			if r.Intn(2) == 0 {
				headers.Add(tk, "v")
			}
		}
		got, _ := det.Detect(body, headers)
		want, _ := scoreFingerprint(def.Fingerprint, body, headers)
		if got != want {
			t.Fatalf("iter %d: bridged=%v native=%v body=%q headers=%v", iter, got, want, body, headers)
		}
	}
}

// TestBridgeFingerprint_ExactlyHalfBoundaryDiverges pins the one documented
// residual: on the shared domain the scores agree, but the module engine
// fires at score >= threshold (inclusive) while the framework engine's gate
// (detectionThreshold, applied by the caller as best.confidence <=
// detectionThreshold) is exclusive of exactly 0.5. this test only pins the
// score-equality half from inside the bridge; the exclusivity of the
// framework gate itself is proven by TestFrameworkThresholdIsStrict.
func TestBridgeFingerprint_ExactlyHalfBoundaryDiverges(t *testing.T) {
	def := okFingerprintDef("fp-bridge-half")
	def.Fingerprint.Signatures = []FPSignature{
		{Pattern: "hit", Weight: 1},
		{Pattern: "miss", Weight: 1},
	}
	registered, reason := bridgeFingerprint(def)
	if !registered {
		t.Fatalf("bridgeFingerprint registered = false, reason %q", reason)
	}
	det, ok := frameworks.GetDetector(def.ID)
	if !ok {
		t.Fatalf("frameworks.GetDetector(%q) not found after bridging", def.ID)
	}

	body := "hit"
	bridgedScore, _ := det.Detect(body, http.Header{})
	if bridgedScore != 0.5 {
		t.Fatalf("bridged score = %v, want exactly 0.5", bridgedScore)
	}

	nativeScore, _ := scoreFingerprint(def.Fingerprint, body, http.Header{})
	if nativeScore != 0.5 {
		t.Fatalf("native score = %v, want exactly 0.5", nativeScore)
	}

	// module engine: score >= threshold(0.5) fires (fingerprint.go:130).
	moduleFires := nativeScore >= defaultFingerprintConfidence
	if !moduleFires {
		t.Fatal("module engine should fire at score == 0.5 (inclusive gate)")
	}

	// framework engine: DetectFramework/DetectFrameworks require
	// confidence > detectionThreshold(0.5) (detect.go:133/168), so an exact
	// 0.5 does not clear it even though the score itself matches.
	const detectionThreshold = 0.5
	frameworkFires := bridgedScore > detectionThreshold
	if frameworkFires {
		t.Fatal("framework engine should not fire at score == 0.5 (exclusive gate)")
	}
}

func TestBridgeFingerprint_ZeroWeightSignature_Refuses(t *testing.T) {
	def := okFingerprintDef("fp-bridge-zero")
	def.Fingerprint.Signatures = append(def.Fingerprint.Signatures, FPSignature{Pattern: "extra", Weight: 0})

	registered, reason := bridgeFingerprint(def)
	if registered {
		t.Fatal("bridgeFingerprint registered a zero-weight-signature fingerprint")
	}
	if reason == "" {
		t.Fatal("expected a non-empty refusal reason")
	}
	if _, ok := frameworks.GetDetector(def.ID); ok {
		t.Fatalf("frameworks.GetDetector(%q) found a detector that should have been refused", def.ID)
	}
}
