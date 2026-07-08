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
	"fmt"
	"sync"
	"sync/atomic"
	"unicode/utf8"
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
	total     int64
	current   int64
	message   string
	lastItem  string
	mu        sync.Mutex
	paused    bool
	lastShown int // last printed milestone bucket in non-tty mode
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
	if apiMode || silent {
		return
	}

	// In non-TTY mode, print progress at milestones only
	if !IsTTY {
		current := atomic.LoadInt64(&p.current)
		total := p.total
		if total <= 0 {
			return
		}
		percent := int(current * 100 / total)

		// map current to a milestone bucket (0=none,1..5). concurrent workers
		// hammer the same bucket, so only print when the bucket advances.
		bucket := 0
		switch {
		case current >= total:
			bucket = 5
		case percent >= 75:
			bucket = 4
		case percent >= 50:
			bucket = 3
		case percent >= 25:
			bucket = 2
		case current >= 1:
			bucket = 1
		}

		p.mu.Lock()
		advanced := bucket > p.lastShown
		if advanced {
			p.lastShown = bucket
		}
		p.mu.Unlock()

		if advanced {
			fmt.Fprintf(sink, "    [%d%%] %d/%d\n", percent, current, total)
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
		switch {
		case i < filled:
			bar += progressFilled
		case i == filled && current < total:
			bar += progressCurrent
		default:
			bar += progressEmpty
		}
	}

	lastItem = truncateItem(lastItem, 30)

	// Format: [========>          ] 45% (4500/10000) /admin
	line := fmt.Sprintf("    [%s] %3d%% (%d/%d) %s",
		prefixInfo.Render(bar),
		percent,
		current,
		total,
		Muted.Render(lastItem),
	)

	ClearLine()
	fmt.Fprint(sink, line)
}

// truncateItem shortens item to at most limit columns for the progress line,
// cutting on a rune boundary so a multibyte path never leaves a half-rune that
// renders as a replacement glyph. width is counted in runes, not bytes.
func truncateItem(item string, limit int) string {
	if utf8.RuneCountInString(item) <= limit {
		return item
	}
	runes := []rune(item)
	// the ellipsis is 3 columns; a smaller cap can't hold it, so cut plainly and
	// never let limit-3 go negative (a negative slice bound panics).
	if limit < 3 {
		if limit < 0 {
			limit = 0
		}
		return string(runes[:limit])
	}
	return string(runes[:limit-3]) + "..."
}
