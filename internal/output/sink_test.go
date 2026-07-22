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

import (
	"bytes"
	"strings"
	"testing"
)

// TestSinkRoutesToOwnWriter is the seam a per-target buffer depends on: chrome
// written through a Sink must land on that sink's writer, not the process-wide
// default. Both the top-level funcs and a sink-bound module logger must honour
// it so a routed scan's output can be captured whole.
func TestSinkRoutesToOwnWriter(t *testing.T) {
	var buf bytes.Buffer
	s := NewSink(&buf, false)

	s.Info("info-marker")
	s.Success("success-marker")
	s.Warn("warn-marker")
	s.Error("error-marker")
	s.Module("MOD").Warn("module-marker")

	got := buf.String()
	for _, want := range []string{"info-marker", "success-marker", "warn-marker", "error-marker", "module-marker"} {
		if !strings.Contains(got, want) {
			t.Errorf("sink writer missing %q; got:\n%s", want, got)
		}
	}

	if s.Interactive() {
		t.Error("NewSink(w, false).Interactive() = true, want false")
	}
}

// TestSinkDoesNotLeakToDefault confirms a routed sink is isolated: writing to it
// must leave the process default sink untouched, which is what lets concurrent
// targets each own their buffer without stepping on each other.
func TestSinkDoesNotLeakToDefault(t *testing.T) {
	var target, other bytes.Buffer

	// point the default sink at `other` for the duration of this test.
	prev := sink
	sink = &other
	defer func() { sink = prev }()

	NewSink(&target, false).Info("only-in-target")

	if other.Len() != 0 {
		t.Errorf("routed write leaked to default sink: %q", other.String())
	}
	if !strings.Contains(target.String(), "only-in-target") {
		t.Errorf("routed write missing from target sink: %q", target.String())
	}
}

// TestDefaultSinkTracksGlobal pins that the package-level funcs still follow the
// SetSilent routing, so existing single-target behaviour is unchanged.
func TestDefaultSinkTracksGlobal(t *testing.T) {
	var buf bytes.Buffer
	prev := sink
	sink = &buf
	defer func() { sink = prev }()

	Info("default-path")
	if !strings.Contains(buf.String(), "default-path") {
		t.Errorf("package Info did not reach the default sink: %q", buf.String())
	}
	if DefaultSink().Writer() != Writer() {
		t.Error("DefaultSink().Writer() should equal the package Writer()")
	}
}
