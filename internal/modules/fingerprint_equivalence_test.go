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
