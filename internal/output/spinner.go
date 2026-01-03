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

package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Spinner frames using simple ASCII
var spinnerFrames = []string{"|", "/", "-", "\\"}

// Spinner displays an animated spinner for indeterminate operations
type Spinner struct {
	message  string
	running  bool
	done     chan struct{}
	mu       sync.Mutex
	interval time.Duration
}

// NewSpinner creates a new spinner with the given message
func NewSpinner(message string) *Spinner {
	return &Spinner{
		message:  message,
		interval: 100 * time.Millisecond,
		done:     make(chan struct{}),
	}
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	if apiMode {
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.done = make(chan struct{})
	s.mu.Unlock()

	// In non-TTY mode, just print the message once
	if !IsTTY {
		fmt.Printf("    %s...\n", s.message)
		return
	}

	go s.animate()
}

// Stop halts the spinner and clears the line
func (s *Spinner) Stop() {
	if apiMode {
		return
	}

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	// Give animation goroutine time to exit
	time.Sleep(s.interval)

	// Clear the spinner line
	if IsTTY {
		ClearLine()
	}
}

// Update changes the spinner message while running
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

func (s *Spinner) animate() {
	frame := 0
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			msg := s.message
			s.mu.Unlock()

			spinnerChar := prefixInfo.Render(spinnerFrames[frame])
			line := fmt.Sprintf("\r    %s %s", spinnerChar, msg)

			fmt.Fprint(os.Stdout, "\033[2K") // Clear line
			fmt.Fprint(os.Stdout, line)

			frame = (frame + 1) % len(spinnerFrames)
		}
	}
}
