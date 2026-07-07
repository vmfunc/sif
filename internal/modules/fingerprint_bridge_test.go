package modules

import (
	"net/http"
	"testing"

	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// okFingerprintDef builds a root-path, default-confidence, all-positive-weight
// fingerprint module: the one shape the framework engine can reproduce exactly
// (C2's shared domain).
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
