package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFingerprintFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fp.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
	return p
}

const fingerprintYAML = `
id: acme-server
info:
  name: ACME Server
  severity: info
type: fingerprint
fingerprint:
  path: /
  confidence: 0.5
  signatures:
    - pattern: "acme"
      weight: 0.6
      header: true
    - pattern: "powered by acme"
      weight: 0.4
  version:
    regex: "acme/([0-9.]+)"
    group: 1
`

// Parse a fingerprint module from real YAML and run it through the module
// wrapper's dispatch, exercising parse -> validate -> Execute end to end.
func TestFingerprintParseRoundTrip(t *testing.T) {
	def, err := ParseYAMLModule(writeFingerprintFile(t, fingerprintYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if def.Type != TypeFingerprint {
		t.Fatalf("type = %q, want fingerprint", def.Type)
	}
	if def.Fingerprint == nil || len(def.Fingerprint.Signatures) != 2 {
		t.Fatalf("fingerprint config not parsed: %+v", def.Fingerprint)
	}
	if !def.Fingerprint.Signatures[0].Header {
		t.Errorf("first signature should be header-scoped")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "acme/3.1")
		_, _ = w.Write([]byte("powered by acme/3.1"))
	}))
	defer srv.Close()

	mod := newYAMLModuleWrapper(def, "fp.yaml")
	res, err := mod.Execute(context.Background(), srv.URL, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if got := res.Findings[0].Confidence; got < 0.99 {
		t.Errorf("confidence = %v, want ~1.0 (both signatures match)", got)
	}
	if got := res.Findings[0].Extracted["version"]; got != "3.1" {
		t.Errorf("version = %q, want 3.1", got)
	}
}

func TestFingerprintValidation(t *testing.T) {
	cases := map[string]string{
		"no signatures": `id: m
type: fingerprint
fingerprint:
  signatures: []`,
		"empty pattern": `id: m
type: fingerprint
fingerprint:
  signatures:
    - pattern: ""
      weight: 1`,
		"negative weight": `id: m
type: fingerprint
fingerprint:
  signatures:
    - pattern: x
      weight: -1`,
		"confidence over 1": `id: m
type: fingerprint
fingerprint:
  confidence: 1.5
  signatures:
    - pattern: x
      weight: 1`,
		"bad version regex": `id: m
type: fingerprint
fingerprint:
  signatures:
    - pattern: x
      weight: 1
  version:
    regex: "([0-9"
    group: 1`,
		"negative version group": `id: m
type: fingerprint
fingerprint:
  signatures:
    - pattern: x
      weight: 1
  version:
    regex: "(x)"
    group: -1`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseYAMLModule(writeFingerprintFile(t, body)); err == nil {
				t.Fatalf("expected a validation error for %q, got nil", name)
			}
		})
	}
}

// An omitted confidence threshold falls back to defaultFingerprintConfidence.
func TestFingerprintDefaultConfidence(t *testing.T) {
	cfg := &FingerprintConfig{
		Signatures: []FPSignature{
			{Pattern: "hit", Weight: 1},
			{Pattern: "miss-me", Weight: 1},
		},
	}
	def := &YAMLModule{ID: "m", Type: TypeFingerprint, Info: YAMLModuleInfo{Severity: "info"}, Fingerprint: cfg}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("only hit is here")) // 1 of 2 -> score 0.5 == default threshold
	}))
	defer srv.Close()

	res, err := ExecuteFingerprintModule(context.Background(), srv.URL, def, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("score 0.5 should clear the default 0.5 threshold; got %d findings", len(res.Findings))
	}

	// A target matching nothing scores 0 and stays silent.
	blank := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 8)))
	}))
	defer blank.Close()
	res2, err := ExecuteFingerprintModule(context.Background(), blank.URL, def, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("execute blank: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Fatalf("no signatures match -> want 0 findings, got %d", len(res2.Findings))
	}
}
