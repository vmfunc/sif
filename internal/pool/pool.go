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

import (
	"context"
	"sync"
)

// Each runs fn for every item in items, concurrently, across at most workers
// goroutines. order isn't preserved - fn must be safe to call from multiple
// goroutines and guard any shared state itself. blocks until every item is done.
func Each[T any](items []T, workers int, fn func(T)) {
	EachCtx(context.Background(), items, workers, func(_ context.Context, item T) {
		fn(item)
	})
}

// EachCtx is Each with a context: once ctx is cancelled, workers stop pulling
// new items off the queue (fn still gets called with ctx for the item it's
// already holding, so it can bail out mid-item too). this is what lets a
// fan-out scanner - a full port sweep, a directory brute-force - stop
// promptly on ctrl-c / -max-time instead of draining the whole queue first.
func EachCtx[T any](ctx context.Context, items []T, workers int, fn func(context.Context, T)) {
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
			// pull until the queue is drained or ctx is cancelled; a worker
			// that finishes its current item just grabs the next, which is
			// the work-stealing.
			for item := range queue {
				if ctx.Err() != nil {
					return
				}
				fn(ctx, item)
			}
		}()
	}
	wg.Wait()
}
