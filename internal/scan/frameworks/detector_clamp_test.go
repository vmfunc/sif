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

package frameworks

import (
	"math"
	"net/http"
	"testing"
)

// MatchSignatures shares scoreFingerprint's math and the same trust-the-caller
// gap: a negative weight must not push the score outside [0, 1].
func TestMatchSignaturesClampsOutOfRangeWeights(t *testing.T) {
	// weights 1 and -0.9 -> total 0.1; only the +1 sig matches: raw 1/0.1 = 10.
	high := NewBaseDetector("x", []Signature{
		{Pattern: "yes", Weight: 1},
		{Pattern: "absent", Weight: -0.9},
	})
	if score := high.MatchSignatures("yes only", http.Header{}); score != 1 {
		t.Fatalf("score = %v, want clamped to 1", score)
	}

	// only the -0.9 sig matches: raw -0.9/0.1 = -9.
	low := NewBaseDetector("x", []Signature{
		{Pattern: "absent", Weight: 1},
		{Pattern: "neg", Weight: -0.9},
	})
	if score := low.MatchSignatures("neg only", http.Header{}); score != 0 {
		t.Fatalf("score = %v, want clamped to 0", score)
	}
}

// a NaN weight (unreachable through the validating custom-detector loader,
// but reachable by any caller that builds a Signature directly, as the
// exported BaseDetector/NewBaseDetector allow) must clamp to 0, not pass
// through: every ordered comparison against NaN is false, so a naive clamp
// of "< 0 -> 0, > 1 -> 1" silently returns NaN unchanged.
func TestMatchSignaturesClampsNaNWeight(t *testing.T) {
	d := NewBaseDetector("x", []Signature{
		{Pattern: "yes", Weight: float32(math.NaN())},
	})
	if score := d.MatchSignatures("yes only", http.Header{}); score != 0 {
		t.Fatalf("score = %v, want NaN clamped to 0", score)
	}
}

// the clamp must not touch scores already inside [0, 1].
func TestMatchSignaturesClampIsNoopOnValidatedScore(t *testing.T) {
	d := NewBaseDetector("x", []Signature{
		{Pattern: "alpha", Weight: 1},
		{Pattern: "beta", Weight: 1},
	})
	if score := d.MatchSignatures("only alpha here", http.Header{}); score != 0.5 {
		t.Fatalf("score = %v, want unchanged 0.5", score)
	}
}
