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

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmfunc/sif/internal/output"
)

// row is one navigable line in the flattened picker: either a group header
// (item == -1) or an item within a group.
type row struct {
	group int
	item  int
}

// pickerKeyMap declares the picker bindings for the help line.
type pickerKeyMap struct {
	Up, Down, Toggle, SelectAll, Collapse, Preset, Filter, Copy, Run, Quit, Help key.Binding
}

func defaultPickerKeys() pickerKeyMap {
	return pickerKeyMap{
		Up:        key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:      key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Toggle:    key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "toggle")),
		SelectAll: key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "all in group")),
		Collapse:  key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "collapse group")),
		Preset:    key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "preset")),
		Filter:    key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Copy:      key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "copy cmd")),
		Run:       key.NewBinding(key.WithKeys("enter", "r"), key.WithHelp("enter", "run")),
		Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Help:      key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	}
}

// pickerModel is screen 1: a grouped, collapsible checklist that produces a
// Selection. It teaches the CLI by showing each item's flag and a live
// "equivalent command" the selection maps to.
type pickerModel struct {
	spec      PickerSpec
	version   string
	keys      pickerKeyMap
	sel       Selection
	collapsed map[int]bool

	rows      []row
	cursor    int
	filter    string
	filtering bool
	presetIdx int
	status    string
	showHelp  bool

	width, height int

	// result is read by Pick after the program ends: run reports whether the
	// user launched (vs quit), sel is the chosen scans.
	run bool
}

// newPickerModel builds the picker, restoring the last saved selection as the
// starting state.
func newPickerModel(version string, spec PickerSpec) *pickerModel {
	m := &pickerModel{
		spec:      spec,
		version:   version,
		keys:      defaultPickerKeys(),
		sel:       loadSelection(),
		collapsed: make(map[int]bool),
		presetIdx: -1,
	}
	m.ensureSelectionMaps()
	m.rebuildRows()
	return m
}

func (m *pickerModel) ensureSelectionMaps() {
	if m.sel.Toggles == nil {
		m.sel.Toggles = map[string]bool{}
	}
	if m.sel.Sizes == nil {
		m.sel.Sizes = map[string]string{}
	}
}

// Init is a no-op: the picker is driven entirely by key input.
func (m *pickerModel) Init() tea.Cmd { return nil }

// rebuildRows flattens groups+items into the visible row list, honoring
// collapse state and the active filter.
func (m *pickerModel) rebuildRows() {
	m.rows = m.rows[:0]
	for gi := range m.spec.Groups {
		matched := m.groupMatchesFilter(gi)
		if len(matched) == 0 {
			continue
		}
		m.rows = append(m.rows, row{group: gi, item: -1})
		if m.collapsed[gi] && m.filter == "" {
			continue
		}
		for _, ii := range matched {
			m.rows = append(m.rows, row{group: gi, item: ii})
		}
	}
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// groupMatchesFilter returns the indices of a group's items that match the
// filter (all of them when the filter is empty).
func (m *pickerModel) groupMatchesFilter(gi int) []int {
	g := m.spec.Groups[gi]
	var out []int
	q := strings.ToLower(m.filter)
	for ii, it := range g.Items {
		if q == "" || strings.Contains(strings.ToLower(it.Label), q) ||
			strings.Contains(strings.ToLower(it.Flag), q) ||
			strings.Contains(strings.ToLower(it.Desc), q) {
			out = append(out, ii)
		}
	}
	return out
}

// Update handles navigation, toggling and the control keys.
func (m *pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		if m.filtering {
			return m.handleFilterKey(msg)
		}
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *pickerModel) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter, tea.KeyEsc:
		m.filtering = false
		if msg.Type == tea.KeyEsc {
			m.filter = ""
		}
	case tea.KeyBackspace:
		if m.filter != "" {
			m.filter = m.filter[:len(m.filter)-1]
		}
	case tea.KeyRunes:
		m.filter += string(msg.Runes)
	}
	m.rebuildRows()
	return m, nil
}

func (m *pickerModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		m.run = false
		return m, tea.Quit
	case key.Matches(msg, m.keys.Run):
		return m.launch()
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
	case key.Matches(msg, m.keys.Filter):
		m.filtering = true
	case key.Matches(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(msg, m.keys.Down):
		if m.cursor < len(m.rows)-1 {
			m.cursor++
		}
	case key.Matches(msg, m.keys.Collapse):
		m.toggleCollapseOrGroup()
	case key.Matches(msg, m.keys.SelectAll):
		m.selectAllInGroup()
	case key.Matches(msg, m.keys.Preset):
		m.applyNextPreset()
	case key.Matches(msg, m.keys.Copy):
		m.status = "copied: " + m.equivalentCommand()
	case key.Matches(msg, m.keys.Toggle):
		m.toggleCurrent()
	case msg.Type == tea.KeyLeft || msg.Type == tea.KeyRight:
		m.adjustLevel(msg.Type == tea.KeyRight)
	}
	return m, nil
}

// launch validates the selection, persists it, and quits the picker with run
// set so Pick returns the selection to the caller.
func (m *pickerModel) launch() (tea.Model, tea.Cmd) {
	if !m.sel.Any() {
		m.status = "select at least one scan (space), or q to cancel"
		return m, nil
	}
	m.run = true
	_ = saveSelection(&m.sel)
	return m, tea.Quit
}

// current returns the row under the cursor.
func (m *pickerModel) current() (row, bool) {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return row{}, false
	}
	return m.rows[m.cursor], true
}

// toggleCollapseOrGroup collapses/expands the group when the cursor is on a
// header, otherwise collapses the item's group.
func (m *pickerModel) toggleCollapseOrGroup() {
	r, ok := m.current()
	if !ok {
		return
	}
	m.collapsed[r.group] = !m.collapsed[r.group]
	m.rebuildRows()
}

// toggleCurrent toggles the item (or cycles a sized item on/off) under the
// cursor; on a header it collapses the group.
func (m *pickerModel) toggleCurrent() {
	r, ok := m.current()
	if !ok {
		return
	}
	if r.item == -1 {
		m.toggleCollapseOrGroup()
		return
	}
	it := m.spec.Groups[r.group].Items[r.item]
	if it.Kind == KindToggle {
		m.sel.Toggles[it.Flag] = !m.sel.Toggles[it.Flag]
		return
	}
	// sized: space cycles off → first level → ... → off.
	m.cycleSize(&it, true)
}

// adjustLevel steps a sized item's level up/down with left/right arrows.
func (m *pickerModel) adjustLevel(up bool) {
	r, ok := m.current()
	if !ok || r.item == -1 {
		return
	}
	it := m.spec.Groups[r.group].Items[r.item]
	if it.Kind == KindSized {
		m.cycleSize(&it, up)
	}
}

// cycleSize advances a sized flag through [off, levels...]. forward=true steps
// toward the last level then wraps to off.
func (m *pickerModel) cycleSize(it *Item, forward bool) {
	cur := m.sel.Sizes[it.Flag]
	idx := 0 // 0 == off; 1..len == levels
	for i, lvl := range it.Levels {
		if lvl == cur {
			idx = i + 1
			break
		}
	}
	n := len(it.Levels) + 1
	if forward {
		idx = (idx + 1) % n
	} else {
		idx = (idx - 1 + n) % n
	}
	if idx == 0 {
		m.sel.Sizes[it.Flag] = ""
	} else {
		m.sel.Sizes[it.Flag] = it.Levels[idx-1]
	}
}

// selectAllInGroup turns on every item in the focused group (sized items take
// their first level). If all are already on, it clears them, so `a` toggles.
func (m *pickerModel) selectAllInGroup() {
	r, ok := m.current()
	if !ok {
		return
	}
	items := m.spec.Groups[r.group].Items
	allOn := true
	for _, it := range items {
		if it.Kind == KindToggle && !m.sel.Toggles[it.Flag] {
			allOn = false
		}
		if it.Kind == KindSized && m.sel.Sizes[it.Flag] == "" {
			allOn = false
		}
	}
	for _, it := range items {
		switch it.Kind {
		case KindToggle:
			m.sel.Toggles[it.Flag] = !allOn
		case KindSized:
			if allOn {
				m.sel.Sizes[it.Flag] = ""
			} else if len(it.Levels) > 0 {
				m.sel.Sizes[it.Flag] = it.Levels[0]
			}
		}
	}
}

// applyNextPreset cycles through the presets, replacing the current selection
// with the preset's choices.
func (m *pickerModel) applyNextPreset() {
	if len(m.spec.Presets) == 0 {
		return
	}
	m.presetIdx = (m.presetIdx + 1) % len(m.spec.Presets)
	p := m.spec.Presets[m.presetIdx]
	m.sel = NewSelection()
	for flag, val := range p.Values {
		if it, ok := m.itemByFlag(flag); ok && it.Kind == KindSized {
			m.sel.Sizes[flag] = val
		} else {
			m.sel.Toggles[flag] = true
		}
	}
	m.status = "preset: " + p.Name
}

func (m *pickerModel) itemByFlag(flag string) (Item, bool) {
	for _, g := range m.spec.Groups {
		for _, it := range g.Items {
			if it.Flag == flag {
				return it, true
			}
		}
	}
	return Item{}, false
}

// equivalentCommand renders the selection as the sif command line it maps to,
// so users can graduate from the picker to flags.
func (m *pickerModel) equivalentCommand() string {
	parts := []string{"sif", "-u", m.spec.Target}
	// stable order: follow group/item order, sized before toggles within an item.
	for _, g := range m.spec.Groups {
		for _, it := range g.Items {
			switch it.Kind {
			case KindSized:
				if lvl := m.sel.Sizes[it.Flag]; lvl != "" {
					parts = append(parts, "-"+it.Flag, lvl)
				}
			case KindToggle:
				if m.sel.Toggles[it.Flag] {
					parts = append(parts, "-"+it.Flag)
				}
			}
		}
	}
	return strings.Join(parts, " ")
}

// Selection returns the picker's current selection.
func (m *pickerModel) Selection() Selection { return m.sel }

// countSelected reports how many scans are currently enabled, for the header.
func (m *pickerModel) countSelected() int {
	n := 0
	for _, on := range m.sel.Toggles {
		if on {
			n++
		}
	}
	for _, lvl := range m.sel.Sizes {
		if lvl != "" {
			n++
		}
	}
	return n
}

// sortedFlags is a helper for deterministic rendering in tests.
func sortedFlags(sel *Selection) []string {
	var out []string
	for f, on := range sel.Toggles {
		if on {
			out = append(out, f)
		}
	}
	for f, lvl := range sel.Sizes {
		if lvl != "" {
			out = append(out, f+"="+lvl)
		}
	}
	sort.Strings(out)
	return out
}

// View renders the picker: a header, the grouped checklist, the live
// equivalent-command line, and the footer help.
func (m *pickerModel) View() string {
	var b strings.Builder
	b.WriteString(output.Highlight.Render(fmt.Sprintf("sif %s · configure scan for %s", m.version, m.spec.Target)))
	b.WriteString(fmt.Sprintf("  (%d selected)\n\n", m.countSelected()))

	for i, r := range m.rows {
		cursor := "  "
		if i == m.cursor {
			cursor = "▸ "
		}
		if r.item == -1 {
			g := m.spec.Groups[r.group]
			glyph := "▾"
			if m.collapsed[r.group] && m.filter == "" {
				glyph = "▸"
			}
			b.WriteString(fmt.Sprintf("%s%s %s\n", cursor, glyph, output.Subheading.Render(g.Name)))
			continue
		}
		it := m.spec.Groups[r.group].Items[r.item]
		b.WriteString("  " + cursor + m.renderItem(&it) + "\n")
	}

	b.WriteString("\n" + output.Subheading.Render("≡ "+m.equivalentCommand()) + "\n")
	if m.status != "" {
		b.WriteString(output.Status.Render(m.status) + "\n")
	}
	b.WriteString("\n" + m.footerHelp())
	return b.String()
}

// renderItem renders one checklist item with its checkbox/level and flag hint.
func (m *pickerModel) renderItem(it *Item) string {
	var box string
	switch it.Kind {
	case KindToggle:
		if m.sel.Toggles[it.Flag] {
			box = "[x]"
		} else {
			box = "[ ]"
		}
	case KindSized:
		lvl := m.sel.Sizes[it.Flag]
		if lvl == "" {
			box = "[ off ]"
		} else {
			box = "[" + lvl + "]"
		}
	}
	return fmt.Sprintf("%s %-16s -%-14s %s", box, it.Label, it.Flag, output.Subheading.Render(it.Desc))
}

func (m *pickerModel) footerHelp() string {
	if m.filtering {
		return output.Status.Render("filter: "+m.filter+"▏") + "  (enter to apply, esc to clear)"
	}
	if m.showHelp {
		return output.Subheading.Render(
			"space toggle · ←/→ level · a all-in-group · tab collapse · p preset · / filter · c copy · enter run · q quit")
	}
	return output.Subheading.Render("space toggle · a all · p preset · / filter · enter run · ? help · q quit")
}
