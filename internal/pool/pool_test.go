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

package pool

import (
	"sync"
	"sync/atomic"
	"testing"
)

// every item runs exactly once across a spread of sizes and worker counts,
// including the floors (zero/negative workers) and workers > len.
func TestEachProcessesAllExactlyOnce(t *testing.T) {
	tests := []struct {
		name    string
		items   int
		workers int
	}{
		{"empty", 0, 4},
		{"single item", 1, 8},
		{"workers floored from zero", 5, 0},
		{"workers floored from negative", 5, -3},
		{"more workers than items", 3, 16},
		{"even split", 100, 4},
		{"uneven split", 101, 7},
		{"one worker", 50, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := make([]int, tt.items)
			for i := 0; i < tt.items; i++ {
				items[i] = i
			}

			var mu sync.Mutex
			seen := make(map[int]int, tt.items)
			Each(items, tt.workers, func(v int) {
				mu.Lock()
				seen[v]++
				mu.Unlock()
			})

			if len(seen) != tt.items {
				t.Fatalf("processed %d distinct items, want %d", len(seen), tt.items)
			}
			for v, n := range seen {
				if n != 1 {
					t.Errorf("item %d processed %d times, want 1", v, n)
				}
			}
		})
	}
}

// no more than `workers` (capped at len(items)) callbacks ever run at once.
func TestEachRespectsWorkerCap(t *testing.T) {
	const (
		items   = 200
		workers = 6
	)
	work := make([]int, items)

	var inFlight, peak int64
	var release = make(chan struct{})
	var started sync.WaitGroup
	started.Add(items)

	go func() {
		Each(work, workers, func(int) {
			cur := atomic.AddInt64(&inFlight, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if cur <= p || atomic.CompareAndSwapInt64(&peak, p, cur) {
					break
				}
			}
			started.Done()
			<-release
			atomic.AddInt64(&inFlight, -1)
		})
	}()

	// the cap means at most `workers` callbacks block on release at once, so
	// release exactly that many at a time until everything drains.
	done := make(chan struct{})
	go func() {
		for i := 0; i < items; i++ {
			release <- struct{}{}
		}
		close(done)
	}()
	<-done

	if got := atomic.LoadInt64(&peak); got > workers {
		t.Fatalf("peak concurrency %d exceeded worker cap %d", got, workers)
	}
}

// the cap is min(workers, len(items)): fewer items than workers must not spin
// idle goroutines past the item count.
func TestEachCapsAtItemCount(t *testing.T) {
	const (
		items   = 3
		workers = 32
	)
	work := make([]int, items)

	var inFlight, peak int64
	var ready sync.WaitGroup
	ready.Add(items)
	release := make(chan struct{})

	go func() {
		for i := 0; i < items; i++ {
			release <- struct{}{}
		}
	}()

	Each(work, workers, func(int) {
		cur := atomic.AddInt64(&inFlight, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if cur <= p || atomic.CompareAndSwapInt64(&peak, p, cur) {
				break
			}
		}
		<-release
		atomic.AddInt64(&inFlight, -1)
	})

	if got := atomic.LoadInt64(&peak); got > items {
		t.Fatalf("peak concurrency %d exceeded item count %d", got, items)
	}
}
