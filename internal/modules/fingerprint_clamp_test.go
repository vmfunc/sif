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

package modules

import (
	"math"
	"net/http"
	"testing"
)

// scoreFingerprint trusts validateFingerprint to keep weights non-negative;
// fed a negative weight directly (as any caller bypassing load validation
// would), the matched fraction must still be clamped to [0, 1] rather than
// escaping it.
func TestScoreFingerprintClampsOutOfRangeWeights(t *testing.T) {
	// weights 1 and -0.9 -> total 0.1; only the +1 sig matches: raw 1/0.1 = 10.
	cfgHigh := &FingerprintConfig{Signatures: []FPSignature{
		{Pattern: "yes", Weight: 1},
		{Pattern: "absent", Weight: -0.9},
	}}
	if score, _ := scoreFingerprint(cfgHigh, "yes only", make(http.Header)); score != 1 {
		t.Fatalf("score = %v, want clamped to 1", score)
	}

	// only the -0.9 sig matches: raw -0.9/0.1 = -9.
	cfgLow := &FingerprintConfig{Signatures: []FPSignature{
		{Pattern: "absent", Weight: 1},
		{Pattern: "neg", Weight: -0.9},
	}}
	if score, _ := scoreFingerprint(cfgLow, "neg only", make(http.Header)); score != 0 {
		t.Fatalf("score = %v, want clamped to 0", score)
	}
}

// a NaN weight (unreachable through validateFingerprint, but reachable by
// any caller that builds a FingerprintConfig directly) must clamp to 0, not
// pass through: every ordered comparison against NaN is false, so a naive
// clamp of "< 0 -> 0, > 1 -> 1" silently returns NaN unchanged.
func TestScoreFingerprintClampsNaNWeight(t *testing.T) {
	cfg := &FingerprintConfig{Signatures: []FPSignature{
		{Pattern: "yes", Weight: float32(math.NaN())},
	}}
	score, _ := scoreFingerprint(cfg, "yes only", make(http.Header))
	if score != 0 {
		t.Fatalf("score = %v, want NaN clamped to 0", score)
	}
}

// the clamp must be a no-op on the validated domain: any signature set that
// validateFingerprint would accept already scores within [0, 1].
func TestScoreFingerprintClampIsNoopOnValidatedScore(t *testing.T) {
	cfg := &FingerprintConfig{Signatures: []FPSignature{
		{Pattern: "alpha", Weight: 1},
		{Pattern: "beta", Weight: 1},
	}}
	score, _ := scoreFingerprint(cfg, "only alpha here", make(http.Header))
	if score != 0.5 {
		t.Fatalf("score = %v, want unchanged 0.5", score)
	}
}
