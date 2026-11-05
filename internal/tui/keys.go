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

package tui

import "github.com/charmbracelet/bubbles/key"

// keyMap declares every dashboard binding as a key.Binding so the help line
// renders them from one source of truth.
type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Focus    key.Binding
	Filter   key.Binding
	Severity key.Binding
	Expand   key.Binding
	Follow   key.Binding
	Top      key.Binding
	Bottom   key.Binding
	OnlyHits key.Binding
	Copy     key.Binding
	Write    key.Binding
	Help     key.Binding
	Quit     key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Focus:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "switch pane")),
		Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Severity: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "severity floor")),
		Expand:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "expand")),
		Follow:   key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "follow")),
		Top:      key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
		Bottom:   key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
		OnlyHits: key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "only hits")),
		Copy:     key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "copy url")),
		Write:    key.NewBinding(key.WithKeys("w"), key.WithHelp("w", "write report")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

// ShortHelp implements help.KeyMap: the one-line binding list.
func (k *keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Focus, k.Filter, k.Severity, k.Follow, k.Expand, k.Help, k.Quit}
}

// FullHelp implements help.KeyMap: the expanded grid shown on `?`.
func (k *keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Top, k.Bottom},
		{k.Focus, k.Filter, k.Severity, k.OnlyHits},
		{k.Follow, k.Expand, k.Copy, k.Write},
		{k.Help, k.Quit},
	}
}
