package modules

import (
	"math/rand"
	"net/http"
	"testing"

	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// pairedSigs builds a frameworks signature list and the matching fingerprint
// signature list from one source, so the two scorers see identical inputs.
func pairedSigs(src []FPSignature) ([]frameworks.Signature, *FingerprintConfig) {
	fw := make([]frameworks.Signature, len(src))
	for i, s := range src {
		fw[i] = frameworks.Signature{Pattern: s.Pattern, Weight: s.Weight, HeaderOnly: s.Header}
	}
	return fw, &FingerprintConfig{Signatures: src}
}

func TestScorerEquivalenceSharedDomain(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	tokens := []string{"nginx", "PHPSESSID", "wp-content", "X-Powered-By", "cloudflare", "django"}
	for iter := 0; iter < 2000; iter++ {
		n := 1 + r.Intn(len(tokens))
		src := make([]FPSignature, n)
		for i := 0; i < n; i++ {
			src[i] = FPSignature{
				Pattern: tokens[r.Intn(len(tokens))],
				Weight:  0.1 + r.Float32()*5, // strictly > 0: the shared domain
				Header:  r.Intn(2) == 0,
			}
		}
		fwSigs, fpCfg := pairedSigs(src)

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

		want := frameworks.NewBaseDetector("x", fwSigs).MatchSignatures(body, headers)
		got, _ := scoreFingerprint(fpCfg, body, headers)
		if got != want {
			t.Fatalf("iter %d: scoreFingerprint=%v MatchSignatures=%v sigs=%+v", iter, got, want, src)
		}
	}
}

func TestScorerDivergesAtZeroWeight(t *testing.T) {
	// one zero-weight sig that misses, one positive sig that hits.
	src := []FPSignature{
		{Pattern: "absent", Weight: 0, Header: false},
		{Pattern: "present", Weight: 1, Header: false},
	}
	fwSigs, fpCfg := pairedSigs(src)
	body := "present"

	fw := frameworks.NewBaseDetector("x", fwSigs).MatchSignatures(body, http.Header{})
	fp, _ := scoreFingerprint(fpCfg, body, http.Header{})

	// framework: matched 1 / total 1 = 1.0 (zero-weight sig contributes nothing).
	if fw != 1 {
		t.Fatalf("framework score = %v, want 1", fw)
	}
	// fingerprint: zero weight remapped to 1, absent sig misses: matched 1 / total 2 = 0.5.
	if fp != 0.5 {
		t.Fatalf("fingerprint score = %v, want 0.5", fp)
	}
	if fw == fp {
		t.Fatal("expected divergence at weight==0, got equality")
	}
}

func TestFrameworkThresholdIsStrict(t *testing.T) {
	// a signature set that scores exactly 0.5 must not clear the > 0.5 gate.
	src := []FPSignature{
		{Pattern: "hit", Weight: 1, Header: false},
		{Pattern: "miss", Weight: 1, Header: false},
	}
	fwSigs, _ := pairedSigs(src)
	score := frameworks.NewBaseDetector("x", fwSigs).MatchSignatures("hit", http.Header{})
	if score != 0.5 {
		t.Fatalf("score = %v, want exactly 0.5", score)
	}
}
