/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package output

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Progress bar configuration
const (
	progressWidth   = 30
	progressFilled  = "="
	progressCurrent = ">"
	progressEmpty   = " "
)

// Progress displays a progress bar for operations with known counts
type Progress struct {
	total    int64
	current  int64
	message  string
	lastItem string
	mu       sync.Mutex
	paused   bool
}

// NewProgress creates a new progress bar
func NewProgress(total int, message string) *Progress {
	return &Progress{
		total:   int64(total),
		message: message,
	}
}

// Increment advances the progress by 1 and optionally updates the current item
func (p *Progress) Increment(item string) {
	atomic.AddInt64(&p.current, 1)

	p.mu.Lock()
	p.lastItem = item
	paused := p.paused
	p.mu.Unlock()

	if !paused {
		p.render()
	}
}

// Set sets the progress to a specific value
func (p *Progress) Set(current int, item string) {
	atomic.StoreInt64(&p.current, int64(current))

	p.mu.Lock()
	p.lastItem = item
	paused := p.paused
	p.mu.Unlock()

	if !paused {
		p.render()
	}
}

// Pause temporarily stops rendering (use before printing other output)
func (p *Progress) Pause() {
	p.mu.Lock()
	p.paused = true
	p.mu.Unlock()
	ClearLine()
}

// Resume resumes rendering after a pause
func (p *Progress) Resume() {
	p.mu.Lock()
	p.paused = false
	p.mu.Unlock()
	p.render()
}

// Done clears the progress bar line
func (p *Progress) Done() {
	if apiMode || !IsTTY {
		return
	}
	ClearLine()
}

func (p *Progress) render() {
	if apiMode {
		return
	}

	// In non-TTY mode, print progress at milestones only
	if !IsTTY {
		current := atomic.LoadInt64(&p.current)
		total := p.total
		percent := int(current * 100 / total)

		// Print at 0%, 25%, 50%, 75%, 100%
		if current == 1 || percent == 25 || percent == 50 || percent == 75 || current == total {
			fmt.Printf("    [%d%%] %d/%d\n", percent, current, total)
		}
		return
	}

	current := atomic.LoadInt64(&p.current)
	total := p.total

	p.mu.Lock()
	lastItem := p.lastItem
	p.mu.Unlock()

	// Calculate percentage
	percent := 0
	if total > 0 {
		percent = int(current * 100 / total)
	}

	// Build progress bar
	filled := 0
	if total > 0 {
		filled = int(progressWidth * current / total)
	}
	if filled > progressWidth {
		filled = progressWidth
	}

	bar := ""
	for i := 0; i < progressWidth; i++ {
		if i < filled {
			bar += progressFilled
		} else if i == filled && current < total {
			bar += progressCurrent
		} else {
			bar += progressEmpty
		}
	}

	// Truncate item if too long
	maxItemLen := 30
	if len(lastItem) > maxItemLen {
		lastItem = lastItem[:maxItemLen-3] + "..."
	}

	// Format: [========>          ] 45% (4500/10000) /admin
	line := fmt.Sprintf("    [%s] %3d%% (%d/%d) %s",
		prefixInfo.Render(bar),
		percent,
		current,
		total,
		Muted.Render(lastItem),
	)

	ClearLine()
	fmt.Print(line)
}
