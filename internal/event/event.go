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

// Package event defines the scan event stream: the typed events a run emits as
// it progresses and the Sink interface that consumes them. The line/console
// output and the live TUI (and anything else) are just Sinks, so the scan
// engine drives one stream regardless of who is watching.
//
// This lives in its own package, not in internal/scan, on purpose: internal/
// finding imports internal/scan (finding.Flatten type-switches on scan result
// types), so internal/scan cannot import finding without a cycle. The event
// stream carries finding.Finding values, so it sits one level up where it can
// import finding freely. The scan engine (package main's scanTarget) emits onto
// it; the scanners themselves stay unaware of it.
package event

import (
	"sync"
	"time"

	"github.com/vmfunc/sif/internal/finding"
)

// Kind enumerates the event types a run emits, in the order a single target
// produces them: TargetStarted, then per scanner a ScannerStarted / zero or
// more FindingFound / ScannerDone, then TargetDone. RunDone is emitted once,
// after every target is finished.
type Kind int

const (
	// TargetStarted is emitted once when a target's scan begins.
	TargetStarted Kind = iota
	// ScannerStarted is emitted before a scanner runs against a target.
	ScannerStarted
	// FindingFound carries one normalized finding from a scanner.
	FindingFound
	// ScannerDone is emitted after a scanner finishes, with the number of
	// findings it produced and how long it took.
	ScannerDone
	// TargetDone is emitted once when a target's scan completes.
	TargetDone
	// RunDone is emitted once at the end of the whole run, carrying the summary.
	RunDone
)

// Event is one point in the scan stream. Which fields are set depends on Kind:
//
//   - TargetStarted / TargetDone: Target.
//   - ScannerStarted:             Target, Scanner.
//   - FindingFound:               Target, Scanner, Finding.
//   - ScannerDone:                Target, Scanner, Count, Duration.
//   - RunDone:                    Summary.
type Event struct {
	Kind     Kind
	Target   string
	Scanner  string
	Finding  *finding.Finding
	Count    int
	Duration time.Duration
	Summary  *Summary
}

// Summary is the run-wide tally carried by the RunDone event. It is enough to
// render a closing screen (totals, per-severity counts, which scanners ran)
// without re-walking every finding.
type Summary struct {
	Targets    int
	Findings   int
	BySeverity map[string]int
	ScansRun   []string
}

// Sink consumes scan events. Emit must be safe to call from multiple goroutines
// concurrently, because targets scan in parallel under -concurrency; the
// Multiplexer below provides that guarantee for sinks composed through it.
type Sink interface {
	Emit(Event)
}

// SinkFunc adapts a plain function to a Sink.
type SinkFunc func(Event)

// Emit calls the underlying function.
func (f SinkFunc) Emit(e Event) { f(e) }

// Nop is a Sink that discards every event. It is the safe default when no
// consumer is attached, so emission sites never need a nil check.
var Nop Sink = SinkFunc(func(Event) {})

// Multiplexer fans one event stream out to several sinks under a single lock,
// so each downstream sink sees a consistent, non-interleaved sequence even when
// several targets emit concurrently.
type Multiplexer struct {
	mu    sync.Mutex
	sinks []Sink
}

// NewMultiplexer builds a Multiplexer over the given sinks (nil entries are
// dropped). With no sinks it behaves like Nop.
func NewMultiplexer(sinks ...Sink) *Multiplexer {
	m := &Multiplexer{}
	for _, s := range sinks {
		if s != nil {
			m.sinks = append(m.sinks, s)
		}
	}
	return m
}

// Emit forwards the event to every sink, holding the lock across the whole
// fan-out so downstream sinks observe one serialized order.
func (m *Multiplexer) Emit(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sinks {
		s.Emit(e)
	}
}

// Collector is a Sink that accumulates findings per target and tracks the
// scanners each target ran. It is the run's aggregation point: the ordered,
// run-wide finding slice that notify/diff/report consume is assembled from it
// in input order, independent of the order concurrent targets finished.
type Collector struct {
	mu        sync.Mutex
	findings  map[string][]finding.Finding
	scansRun  map[string][]string
	targets   map[string]bool
	allCount  int
	severity  map[string]int
	scanOrder []string // run-wide scanner labels, first-seen order
	seenScan  map[string]bool
}

// NewCollector returns an empty Collector ready to attach to the stream.
func NewCollector() *Collector {
	return &Collector{
		findings: make(map[string][]finding.Finding),
		scansRun: make(map[string][]string),
		targets:  make(map[string]bool),
		severity: make(map[string]int),
		seenScan: make(map[string]bool),
	}
}

// Emit records findings, scanner labels and severity tallies. Only the event
// kinds it aggregates are handled; the rest are ignored.
func (c *Collector) Emit(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch e.Kind {
	case TargetStarted:
		c.targets[e.Target] = true
	case FindingFound:
		if e.Finding != nil {
			c.findings[e.Target] = append(c.findings[e.Target], *e.Finding)
			c.allCount++
			c.severity[e.Finding.Severity.String()]++
		}
	case ScannerDone:
		if e.Scanner != "" {
			c.scansRun[e.Target] = append(c.scansRun[e.Target], e.Scanner)
			if !c.seenScan[e.Scanner] {
				c.seenScan[e.Scanner] = true
				c.scanOrder = append(c.scanOrder, e.Scanner)
			}
		}
	}
}

// FindingsFor returns a copy of the findings collected for one target, in the
// order they were emitted.
func (c *Collector) FindingsFor(target string) []finding.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := c.findings[target]
	out := make([]finding.Finding, len(src))
	copy(out, src)
	return out
}

// Ordered returns every finding assembled in the given target order, matching
// the run's input order so the aggregate is deterministic regardless of which
// worker finished first.
func (c *Collector) Ordered(targets []string) []finding.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]finding.Finding, 0, c.allCount)
	for _, t := range targets {
		out = append(out, c.findings[t]...)
	}
	return out
}

// Summary snapshots the run-wide tally for the RunDone event.
func (c *Collector) Summary() *Summary {
	c.mu.Lock()
	defer c.mu.Unlock()
	bySev := make(map[string]int, len(c.severity))
	for k, v := range c.severity {
		bySev[k] = v
	}
	scans := make([]string, len(c.scanOrder))
	copy(scans, c.scanOrder)
	return &Summary{
		Targets:    len(c.targets),
		Findings:   c.allCount,
		BySeverity: bySev,
		ScansRun:   scans,
	}
}
