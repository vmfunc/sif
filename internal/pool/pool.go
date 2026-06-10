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

// Package pool spreads independent per-item work across a fixed set of workers
// that all pull from one shared channel. that's the point over a static
// modulo-stride partition: a slow or timing-out item only stalls the one worker
// holding it, the rest keep draining the queue instead of idling behind it.
package pool

import "sync"

// Each runs fn for every item in items, concurrently, across at most workers
// goroutines. order isn't preserved - fn must be safe to call from multiple
// goroutines and guard any shared state itself. blocks until every item is done.
func Each[T any](items []T, workers int, fn func(T)) {
	if len(items) == 0 {
		return
	}
	// floor at one worker; a non-positive count would otherwise spawn nothing
	// and silently drop the work.
	if workers < 1 {
		workers = 1
	}
	// never spin more workers than there is work for.
	if workers > len(items) {
		workers = len(items)
	}

	queue := make(chan T, len(items))
	for i := 0; i < len(items); i++ {
		queue <- items[i]
	}
	close(queue)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			// pull until the queue is drained; a worker that finishes its
			// current item just grabs the next, which is the work-stealing.
			for item := range queue {
				fn(item)
			}
		}()
	}
	wg.Wait()
}
