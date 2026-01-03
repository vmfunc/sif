/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package worker

import (
	"sort"
	"sync/atomic"
	"testing"
)

func TestPoolRun(t *testing.T) {
	pool := New(4, func(x int) int {
		return x * 2
	})

	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	results := pool.Run(items)

	if len(results) != len(items) {
		t.Errorf("Expected %d results, got %d", len(items), len(results))
	}

	// Sort results since order is not guaranteed
	sort.Ints(results)
	expected := []int{2, 4, 6, 8, 10, 12, 14, 16, 18, 20}
	for i, v := range results {
		if v != expected[i] {
			t.Errorf("Expected results[%d] = %d, got %d", i, expected[i], v)
		}
	}
}

func TestPoolRunEmpty(t *testing.T) {
	pool := New(4, func(x int) int {
		return x * 2
	})

	results := pool.Run(nil)
	if results != nil {
		t.Errorf("Expected nil for empty input, got %v", results)
	}

	results = pool.Run([]int{})
	if results != nil {
		t.Errorf("Expected nil for empty slice, got %v", results)
	}
}

func TestPoolRunWithFilter(t *testing.T) {
	pool := New(4, func(x int) int {
		return x * 2
	})

	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	results := pool.RunWithFilter(items, func(r int) bool {
		return r > 10 // Only keep results > 10
	})

	// Should have 5 results: 12, 14, 16, 18, 20
	if len(results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(results))
	}

	sort.Ints(results)
	expected := []int{12, 14, 16, 18, 20}
	for i, v := range results {
		if v != expected[i] {
			t.Errorf("Expected results[%d] = %d, got %d", i, expected[i], v)
		}
	}
}

func TestPoolForEach(t *testing.T) {
	var sum atomic.Int64

	pool := New(4, func(x int) int {
		return x * 2
	})

	items := []int{1, 2, 3, 4, 5}
	pool.ForEach(items, func(r int) {
		sum.Add(int64(r))
	})

	// Sum should be 2+4+6+8+10 = 30
	if sum.Load() != 30 {
		t.Errorf("Expected sum = 30, got %d", sum.Load())
	}
}

func TestPoolSingleWorker(t *testing.T) {
	pool := New(1, func(x int) int {
		return x + 1
	})

	items := []int{1, 2, 3}
	results := pool.Run(items)

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	sort.Ints(results)
	expected := []int{2, 3, 4}
	for i, v := range results {
		if v != expected[i] {
			t.Errorf("Expected results[%d] = %d, got %d", i, expected[i], v)
		}
	}
}

func TestPoolZeroWorkers(t *testing.T) {
	// Zero workers should default to 1
	pool := New(0, func(x int) int {
		return x
	})

	if pool.workers != 1 {
		t.Errorf("Expected workers = 1, got %d", pool.workers)
	}
}

func TestPoolStringProcessing(t *testing.T) {
	pool := New(2, func(s string) int {
		return len(s)
	})

	items := []string{"a", "bb", "ccc", "dddd"}
	results := pool.Run(items)

	sort.Ints(results)
	expected := []int{1, 2, 3, 4}
	for i, v := range results {
		if v != expected[i] {
			t.Errorf("Expected results[%d] = %d, got %d", i, expected[i], v)
		}
	}
}

func TestPoolStructProcessing(t *testing.T) {
	type input struct {
		a int
		b int
	}
	type output struct {
		sum  int
		prod int
	}

	pool := New(3, func(in input) output {
		return output{sum: in.a + in.b, prod: in.a * in.b}
	})

	items := []input{{1, 2}, {3, 4}, {5, 6}}
	results := pool.Run(items)

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Verify all expected outputs are present
	found := make(map[output]bool)
	for _, r := range results {
		found[r] = true
	}

	expectedOutputs := []output{{3, 2}, {7, 12}, {11, 30}}
	for _, exp := range expectedOutputs {
		if !found[exp] {
			t.Errorf("Expected output %v not found in results", exp)
		}
	}
}
