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
	"github.com/charmbracelet/lipgloss"
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

// picker column widths for the aligned checklist.
const (
	colCheck = 8  // checkbox / level pill column
	colLabel = 16 // human label
	colFlag  = 16 // -flag hint
)

// contentWidth is how wide the picker body renders, bounded so it stays tidy on
// very wide terminals and never overflows narrow ones.
func (m *pickerModel) contentWidth() int {
	w := m.width
	if w <= 0 {
		w = 90
	}
	if w > 96 {
		w = 96
	}
	if w < 48 {
		w = 48
	}
	return w
}

// View renders the picker: a header bar, the grouped checklist, the live
// equivalent-command panel, and the footer help.
func (m *pickerModel) View() string {
	w := m.contentWidth()

	var b strings.Builder
	b.WriteString(m.headerBar(w))
	b.WriteString("\n\n")

	for i, r := range m.rows {
		b.WriteString(m.renderRow(i, r, w))
		b.WriteByte('\n')
	}

	b.WriteString("\n")
	b.WriteString(m.commandPanel(w))
	b.WriteString("\n\n")
	b.WriteString(m.footerHelp())
	return b.String()
}

// headerBar is the top title strip: product/target on the left, selected count
// on the right, filling the content width with a background accent.
func (m *pickerModel) headerBar(w int) string {
	onBar := lipgloss.NewStyle().Background(colorBarBg)
	left := onBar.Foreground(colorText).Bold(true).Render(" sif "+m.version) +
		onBar.Foreground(colorMuted).Render("  configure scan · ") +
		onBar.Foreground(colorText).Render(m.spec.Target)
	right := onBar.Foreground(colorText).Bold(true).Render(fmt.Sprintf("%d selected ", m.countSelected()))

	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + onBar.Render(spaces(gap)) + right
}

// renderRow renders one flattened row (group header or item), highlighting the
// cursor row with a full-width background.
func (m *pickerModel) renderRow(i int, r row, w int) string {
	selected := i == m.cursor
	cursor := "  "
	if selected {
		cursor = styleCursor.Render("▸ ")
	}

	var line string
	if r.item == -1 {
		g := m.spec.Groups[r.group]
		caret := "▾"
		if m.collapsed[r.group] && m.filter == "" {
			caret = "▸"
		}
		line = cursor + styleGroup.Render(caret+" "+g.Name)
	} else {
		it := m.spec.Groups[r.group].Items[r.item]
		line = "    " + cursor + m.renderItem(&it, w-6)
	}

	if selected {
		return styleSelected.Width(w).Render(line)
	}
	return line
}

// renderItem renders one checklist item: a colored checkbox/level pill, the
// label, its -flag, and a dim description truncated to fit the row.
func (m *pickerModel) renderItem(it *Item, avail int) string {
	var box string
	switch it.Kind {
	case KindToggle:
		if m.sel.Toggles[it.Flag] {
			box = styleOn.Render(padRight("◉ on", colCheck))
		} else {
			box = styleFaint.Render(padRight("○ off", colCheck))
		}
	case KindSized:
		lvl := m.sel.Sizes[it.Flag]
		if lvl == "" {
			box = styleFaint.Render(padRight("○ off", colCheck))
		} else {
			box = stylePill.Render(lvl) + spaces(max0(colCheck-len([]rune(lvl))-2))
		}
	}

	label := styleLabel.Render(padRight(it.Label, colLabel))
	flag := styleFlag.Render(padRight("-"+it.Flag, colFlag))

	used := colCheck + 1 + colLabel + 1 + colFlag + 1
	descW := avail - used
	if descW < 8 {
		descW = 8
	}
	desc := styleDesc.Render(padRight(it.Desc, descW))
	return box + " " + label + " " + flag + " " + desc
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// commandPanel shows the live equivalent command in a bordered box so users can
// learn the flags their selection maps to.
func (m *pickerModel) commandPanel(w int) string {
	cmd := styleFaint.Render("≡ ") + styleCmd.Render(m.equivalentCommand())
	if m.status != "" {
		cmd += "\n" + styleOn.Render("» "+m.status)
	}
	return stylePanel.Width(w - 2).Render(cmd)
}

func (m *pickerModel) footerHelp() string {
	if m.filtering {
		return styleKey.Render("filter ") + styleTitle.Render(m.filter+"▏") +
			"  " + styleMuted.Render("enter apply · esc clear")
	}
	hints := []string{
		keyHint("space", "toggle"), keyHint("←/→", "level"), keyHint("a", "group"),
		keyHint("p", "preset"), keyHint("/", "filter"), keyHint("enter", "run"),
		keyHint("?", "help"), keyHint("q", "quit"),
	}
	if !m.showHelp {
		hints = []string{
			keyHint("space", "toggle"), keyHint("p", "preset"),
			keyHint("/", "filter"), keyHint("enter", "run"),
			keyHint("?", "more"), keyHint("q", "quit"),
		}
	}
	return strings.Join(hints, styleFaint.Render("  ·  "))
}
