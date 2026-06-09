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

package output

import "testing"

// the non-tty milestone path divides current*100/total, so a zero-total bar
// used to panic with integer divide-by-zero when piped or redirected.
func TestProgressZeroTotalNoPanic(t *testing.T) {
	p := NewProgress(0, "scanning")
	p.Increment("item")
	p.Set(0, "item")
	p.Done()
}

func TestProgressCounts(t *testing.T) {
	p := NewProgress(4, "scanning")
	for i := 0; i < 4; i++ {
		p.Increment("x")
	}
	if p.current != 4 {
		t.Errorf("current = %d, want 4", p.current)
	}
}
