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

// ItemKind distinguishes a plain on/off scan from one that takes an intensity
// (a size or scope), so the picker can render an inline selector for the latter.
type ItemKind int

const (
	// KindToggle is a boolean scan flag (e.g. -cors).
	KindToggle ItemKind = iota
	// KindSized is a scan that takes one of a fixed set of levels (e.g. -dirlist
	// small|medium|large, -ports common|full). Off is represented by the empty
	// selection; Levels lists the on-values.
	KindSized
)

// Item is one selectable scan in the picker, mapping a user-facing label to the
// CLI flag it drives.
type Item struct {
	Flag   string   // the flag name without the dash, e.g. "cors" or "dirlist"
	Label  string   // short human label
	Desc   string   // one-line description (teaches the flag)
	Kind   ItemKind // toggle or sized
	Levels []string // for KindSized: the ordered level values, e.g. small,medium,large
}

// Group is a named, collapsible set of items (Recon, Web vulns, …).
type Group struct {
	Name  string
	Items []Item
}

// Preset is a named bundle of flag choices the picker can apply in one key,
// mapping to the README's real example combos. For a sized flag the value is a
// level; for a toggle it is "on".
type Preset struct {
	Name   string
	Values map[string]string
}

// PickerSpec is everything the picker needs that it can't infer: the target
// being configured, the grouped item catalog, and the presets.
type PickerSpec struct {
	Target  string
	Groups  []Group
	Presets []Preset
}

// Selection is the picker's output: which toggle flags are on, and the chosen
// level for each sized flag. It is what the caller applies to the scan settings.
type Selection struct {
	// Toggles holds the on-state of KindToggle flags by flag name.
	Toggles map[string]bool
	// Sizes holds the chosen level of KindSized flags by flag name; absent or
	// empty means the scan is off.
	Sizes map[string]string
	// Options carries the http-options form values (empty when untouched).
	Options Options
}

// Options is the secondary http-options form (the `o` overlay).
type Options struct {
	Proxy     string
	Header    string
	Cookie    string
	RateLimit string
}

// NewSelection returns an empty selection with initialized maps.
func NewSelection() Selection {
	return Selection{Toggles: map[string]bool{}, Sizes: map[string]string{}}
}

// Any reports whether the selection would run at least one scan, so the caller
// can refuse to launch an empty run.
func (s *Selection) Any() bool {
	for _, on := range s.Toggles {
		if on {
			return true
		}
	}
	for _, lvl := range s.Sizes {
		if lvl != "" {
			return true
		}
	}
	return false
}
