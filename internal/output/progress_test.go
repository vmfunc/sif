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
	"os"
	"strings"
	"sync"
	"testing"
)

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

// many concurrent workers used to spam the same milestone bucket (e.g. ten
// "[25%] .../1000" lines). each bucket must now print at most once.
func TestProgressNonTTYDedupesMilestones(t *testing.T) {
	savedTTY, savedAPI := IsTTY, apiMode
	IsTTY, apiMode = false, false
	defer func() { IsTTY, apiMode = savedTTY, savedAPI }()

	out := captureStdout(t, func() {
		p := NewProgress(1000, "scanning")
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 25; j++ {
					p.Increment("x")
				}
			}()
		}
		wg.Wait()
	})

	lines := strings.Count(out, "\n")
	if lines > 5 {
		t.Errorf("printed %d milestone lines, want <=5:\n%s", lines, out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, rerr := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if rerr != nil {
				break
			}
		}
		done <- string(buf)
	}()

	fn()
	os.Stdout = saved
	w.Close()
	return <-done
}
