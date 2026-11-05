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

package event

import (
	"sync"
	"testing"

	"github.com/vmfunc/sif/internal/finding"
)

func TestNopDiscards(t *testing.T) {
	// Nop must accept every kind without panicking.
	Nop.Emit(Event{Kind: FindingFound, Finding: &finding.Finding{}})
	Nop.Emit(Event{Kind: RunDone})
}

func TestMultiplexerFansOut(t *testing.T) {
	var a, b int
	m := NewMultiplexer(
		SinkFunc(func(Event) { a++ }),
		nil, // dropped
		SinkFunc(func(Event) { b++ }),
	)
	m.Emit(Event{Kind: TargetStarted})
	m.Emit(Event{Kind: TargetDone})
	if a != 2 || b != 2 {
		t.Fatalf("fan-out counts a=%d b=%d, want 2/2", a, b)
	}
}

func TestMultiplexerSerializesConcurrentEmits(t *testing.T) {
	// the multiplexer holds its lock across the fan-out, so a sink that is not
	// itself synchronized still never races. Run with -race to catch regressions.
	c := NewCollector()
	m := NewMultiplexer(c)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			target := "t"
			m.Emit(Event{Kind: TargetStarted, Target: target})
			m.Emit(Event{Kind: FindingFound, Target: target, Finding: &finding.Finding{Severity: finding.SeverityHigh}})
			m.Emit(Event{Kind: ScannerDone, Target: target, Scanner: "s"})
		}(i)
	}
	wg.Wait()

	sum := c.Summary()
	if sum.Findings != 8 {
		t.Errorf("Findings = %d, want 8", sum.Findings)
	}
	if sum.BySeverity["high"] != 8 {
		t.Errorf("BySeverity[high] = %d, want 8", sum.BySeverity["high"])
	}
}

func TestCollectorOrderedByInputOrder(t *testing.T) {
	c := NewCollector()
	// emit b's finding before a's, but Ordered must follow the given target order.
	c.Emit(Event{Kind: FindingFound, Target: "b", Finding: &finding.Finding{Target: "b", Title: "b1"}})
	c.Emit(Event{Kind: FindingFound, Target: "a", Finding: &finding.Finding{Target: "a", Title: "a1"}})
	c.Emit(Event{Kind: FindingFound, Target: "a", Finding: &finding.Finding{Target: "a", Title: "a2"}})

	got := c.Ordered([]string{"a", "b"})
	want := []string{"a1", "a2", "b1"}
	if len(got) != len(want) {
		t.Fatalf("Ordered len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Title != want[i] {
			t.Errorf("Ordered[%d].Title = %q, want %q", i, got[i].Title, want[i])
		}
	}
}

func TestCollectorFindingsForIsACopy(t *testing.T) {
	c := NewCollector()
	c.Emit(Event{Kind: FindingFound, Target: "a", Finding: &finding.Finding{Title: "x"}})
	got := c.FindingsFor("a")
	got[0].Title = "mutated"
	if again := c.FindingsFor("a"); again[0].Title != "x" {
		t.Errorf("FindingsFor returned a view into internal state; got %q after caller mutation", again[0].Title)
	}
}

func TestCollectorSummaryScanOrder(t *testing.T) {
	c := NewCollector()
	c.Emit(Event{Kind: TargetStarted, Target: "a"})
	c.Emit(Event{Kind: ScannerDone, Target: "a", Scanner: "headers"})
	c.Emit(Event{Kind: ScannerDone, Target: "a", Scanner: "git"})
	c.Emit(Event{Kind: ScannerDone, Target: "a", Scanner: "headers"}) // dup, first-seen order kept

	sum := c.Summary()
	if sum.Targets != 1 {
		t.Errorf("Targets = %d, want 1", sum.Targets)
	}
	want := []string{"headers", "git"}
	if len(sum.ScansRun) != len(want) {
		t.Fatalf("ScansRun = %v, want %v", sum.ScansRun, want)
	}
	for i := range want {
		if sum.ScansRun[i] != want[i] {
			t.Errorf("ScansRun[%d] = %q, want %q", i, sum.ScansRun[i], want[i])
		}
	}
}
