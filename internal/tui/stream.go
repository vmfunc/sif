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

// Package tui is the bubbletea front-end for a scan: a live dashboard and a
// closing summary, driven entirely by the internal/event stream. The scan
// engine runs in a background goroutine and knows nothing about the tui; it
// just emits onto an event.Sink, so the tui is one more sink alongside the
// console and report writers.
package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmfunc/sif/internal/event"
)

// eventMsg carries one scan event into the bubbletea update loop.
type eventMsg event.Event

// streamClosedMsg signals that the scan goroutine finished and the event
// channel is drained, so no further eventMsg will arrive.
type streamClosedMsg struct{}

// streamSink is an event.Sink that forwards events onto a buffered channel for
// the bubbletea program to drain. The engine emits from its own goroutine(s);
// the buffer keeps a burst of findings from blocking the scan while the ui
// renders a frame.
type streamSink struct {
	ch chan event.Event
}

// newStreamSink makes a sink with a buffered channel. The buffer is generous so
// a fast scanner never stalls on a slow repaint; overflow simply blocks the
// emitting goroutine briefly, which is harmless.
func newStreamSink() *streamSink {
	return &streamSink{ch: make(chan event.Event, 1024)}
}

// Emit forwards one event to the channel.
func (s *streamSink) Emit(e event.Event) { s.ch <- e }

// close signals no more events will be sent. Called after the scan goroutine
// returns so the drain command can emit streamClosedMsg.
func (s *streamSink) close() { close(s.ch) }

// waitForEvent returns a command that blocks on the next event and wraps it as
// a message. Re-issued from Update after each event so the loop keeps draining
// without ever blocking Update itself. When the channel is closed it reports
// streamClosedMsg once.
func (s *streamSink) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		e, ok := <-s.ch
		if !ok {
			return streamClosedMsg{}
		}
		return eventMsg(e)
	}
}
