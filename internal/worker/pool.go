/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

// Package worker provides a generic worker pool for concurrent task processing.
package worker

import "sync"

// Pool manages a pool of workers that process items concurrently.
// It uses channel-based distribution for efficient load balancing.
type Pool[T any, R any] struct {
	workers int
	fn      func(T) R
}

// New creates a new worker pool with the specified number of workers
// and a processing function.
func New[T any, R any](workers int, fn func(T) R) *Pool[T, R] {
	if workers < 1 {
		workers = 1
	}
	return &Pool[T, R]{
		workers: workers,
		fn:      fn,
	}
}

// Run processes all items concurrently and returns the results.
// Items are distributed via a channel for optimal load balancing.
func (p *Pool[T, R]) Run(items []T) []R {
	if len(items) == 0 {
		return nil
	}

	input := make(chan T, len(items))
	output := make(chan R, len(items))

	var wg sync.WaitGroup
	wg.Add(p.workers)

	// Start workers
	for i := 0; i < p.workers; i++ {
		go func() {
			defer wg.Done()
			for item := range input {
				output <- p.fn(item)
			}
		}()
	}

	// Feed items to workers
	for _, item := range items {
		input <- item
	}
	close(input)

	// Wait for all workers to finish, then close output
	go func() {
		wg.Wait()
		close(output)
	}()

	// Collect results
	results := make([]R, 0, len(items))
	for r := range output {
		results = append(results, r)
	}

	return results
}

// RunWithFilter processes items concurrently and returns only non-zero results.
// Useful when the processing function may return zero values for filtered items.
func (p *Pool[T, R]) RunWithFilter(items []T, filter func(R) bool) []R {
	if len(items) == 0 {
		return nil
	}

	input := make(chan T, len(items))
	output := make(chan R, len(items))

	var wg sync.WaitGroup
	wg.Add(p.workers)

	// Start workers
	for i := 0; i < p.workers; i++ {
		go func() {
			defer wg.Done()
			for item := range input {
				result := p.fn(item)
				if filter(result) {
					output <- result
				}
			}
		}()
	}

	// Feed items to workers
	for _, item := range items {
		input <- item
	}
	close(input)

	// Wait for all workers to finish, then close output
	go func() {
		wg.Wait()
		close(output)
	}()

	// Collect results
	results := make([]R, 0, len(items)/2) // Estimate half will pass filter
	for r := range output {
		results = append(results, r)
	}

	return results
}

// ForEach processes items concurrently without collecting results.
// Useful for side-effect operations like logging or writing to external stores.
func (p *Pool[T, R]) ForEach(items []T, callback func(R)) {
	if len(items) == 0 {
		return
	}

	input := make(chan T, len(items))
	output := make(chan R, len(items))

	var wg sync.WaitGroup
	wg.Add(p.workers)

	// Start workers
	for i := 0; i < p.workers; i++ {
		go func() {
			defer wg.Done()
			for item := range input {
				output <- p.fn(item)
			}
		}()
	}

	// Feed items to workers
	for _, item := range items {
		input <- item
	}
	close(input)

	// Process results as they come in
	var outputWg sync.WaitGroup
	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		for r := range output {
			callback(r)
		}
	}()

	wg.Wait()
	close(output)
	outputWg.Wait()
}
