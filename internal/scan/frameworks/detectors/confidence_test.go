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

import "testing"

func TestSigmoidConfidence(t *testing.T) {
	// a weak match (small matched-weight fraction) must stay below the 0.5
	// detection threshold; a strong match must clear it. the old curve put any
	// match above 0.5, which is what false-detected magento on a plain page.
	if c := sigmoidConfidence(0); c >= 0.5 {
		t.Errorf("no match conf = %.3f, want < 0.5", c)
	}
	if c := sigmoidConfidence(0.2); c >= 0.5 {
		t.Errorf("weak match conf = %.3f, want < 0.5", c)
	}
	if c := sigmoidConfidence(0.5); c <= 0.5 {
		t.Errorf("strong match conf = %.3f, want > 0.5", c)
	}
}
