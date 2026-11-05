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
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func testSpec() PickerSpec {
	return PickerSpec{
		Target: "https://example.com",
		Groups: []Group{
			{Name: "Recon", Items: []Item{
				{Flag: "dnslist", Label: "DNS", Desc: "dns fuzzing", Kind: KindSized, Levels: []string{"small", "medium", "large"}},
				{Flag: "crawl", Label: "Crawl", Desc: "spider the site", Kind: KindToggle},
			}},
			{Name: "Web vulns", Items: []Item{
				{Flag: "cors", Label: "CORS", Desc: "cors probe", Kind: KindToggle},
				{Flag: "xss", Label: "XSS", Desc: "reflected xss", Kind: KindToggle},
			}},
		},
		Presets: []Preset{
			{Name: "quick", Values: map[string]string{"cors": "on"}},
			{Name: "recon", Values: map[string]string{"dnslist": "small", "crawl": "on"}},
		},
	}
}

// newTestPicker builds a picker with persistence pointed at a temp HOME so tests
// never read or write the real config.
func newTestPicker(t *testing.T) *pickerModel {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	m := newPickerModel("test", testSpec())
	m.width, m.height = 100, 30
	return m
}

func sendP(m *pickerModel, msg tea.Msg) { m.Update(msg) }

func runes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// cursorTo moves the cursor onto the row for the given flag.
func cursorTo(m *pickerModel, flag string) {
	for i, r := range m.rows {
		if r.item >= 0 && m.spec.Groups[r.group].Items[r.item].Flag == flag {
			m.cursor = i
			return
		}
	}
}

func TestPickerToggle(t *testing.T) {
	m := newTestPicker(t)
	cursorTo(m, "cors")
	sendP(m, runes(" "))
	if !m.sel.Toggles["cors"] {
		t.Fatal("space should toggle cors on")
	}
	sendP(m, runes(" "))
	if m.sel.Toggles["cors"] {
		t.Fatal("space again should toggle cors off")
	}
}

func TestPickerSizedCycle(t *testing.T) {
	m := newTestPicker(t)
	cursorTo(m, "dnslist")
	// space cycles off → small → medium → large → off
	want := []string{"small", "medium", "large", ""}
	for i, w := range want {
		sendP(m, runes(" "))
		if got := m.sel.Sizes["dnslist"]; got != w {
			t.Fatalf("cycle step %d: dnslist = %q, want %q", i, got, w)
		}
	}
}

func TestPickerEquivalentCommand(t *testing.T) {
	m := newTestPicker(t)
	cursorTo(m, "dnslist")
	sendP(m, runes(" ")) // small
	cursorTo(m, "cors")
	sendP(m, runes(" ")) // on
	got := m.equivalentCommand()
	want := "sif -u https://example.com -dnslist small -cors"
	if got != want {
		t.Errorf("equivalent command = %q, want %q", got, want)
	}
}

func TestPickerPresetCycle(t *testing.T) {
	m := newTestPicker(t)
	sendP(m, runes("p")) // quick
	if !m.sel.Toggles["cors"] || m.sel.Toggles["xss"] {
		t.Fatalf("quick preset: cors on, xss off; got %v", sortedFlags(&m.sel))
	}
	sendP(m, runes("p")) // recon, replaces selection
	flags := strings.Join(sortedFlags(&m.sel), ",")
	if flags != "crawl,dnslist=small" {
		t.Fatalf("recon preset flags = %q, want crawl,dnslist=small", flags)
	}
	if m.sel.Toggles["cors"] {
		t.Error("switching preset should replace, not accumulate (cors still on)")
	}
}

func TestPickerSelectAllInGroup(t *testing.T) {
	m := newTestPicker(t)
	cursorTo(m, "cors") // focus the Web vulns group
	sendP(m, runes("a"))
	if !m.sel.Toggles["cors"] || !m.sel.Toggles["xss"] {
		t.Fatalf("a should select all in group; got %v", sortedFlags(&m.sel))
	}
	sendP(m, runes("a")) // all on → toggle clears
	if m.sel.Toggles["cors"] || m.sel.Toggles["xss"] {
		t.Errorf("a on a full group should clear it; got %v", sortedFlags(&m.sel))
	}
}

func TestPickerFilter(t *testing.T) {
	m := newTestPicker(t)
	sendP(m, runes("/"))
	sendP(m, runes("xss"))
	// only the Web vulns group with the xss item should remain (plus its header).
	items := 0
	for _, r := range m.rows {
		if r.item >= 0 {
			items++
			if m.spec.Groups[r.group].Items[r.item].Flag != "xss" {
				t.Errorf("filter leaked non-matching item: %s", m.spec.Groups[r.group].Items[r.item].Flag)
			}
		}
	}
	if items != 1 {
		t.Fatalf("filter xss: %d items visible, want 1", items)
	}
}

func TestPickerCollapseGroup(t *testing.T) {
	m := newTestPicker(t)
	before := len(m.rows)
	m.cursor = 0 // first Recon header
	sendP(m, tea.KeyMsg{Type: tea.KeyTab})
	if len(m.rows) >= before {
		t.Fatalf("collapsing a group should hide its items: rows %d -> %d", before, len(m.rows))
	}
}

func TestPickerLaunchRequiresSelection(t *testing.T) {
	m := newTestPicker(t)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.run {
		t.Fatal("empty selection must not launch")
	}
	if cmd != nil {
		t.Fatal("empty-selection launch should not quit")
	}
	if !strings.Contains(m.status, "select at least one") {
		t.Errorf("expected a guard message, got %q", m.status)
	}

	cursorTo(m, "cors")
	sendP(m, runes(" "))
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.run {
		t.Fatal("selection present: enter should launch")
	}
	if cmd == nil {
		t.Fatal("launch should return a quit command")
	}
}

func TestPickerPersistenceRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sel := NewSelection()
	sel.Toggles["cors"] = true
	sel.Sizes["dnslist"] = "medium"
	if err := saveSelection(&sel); err != nil {
		t.Fatalf("saveSelection: %v", err)
	}
	got := loadSelection()
	if !got.Toggles["cors"] || got.Sizes["dnslist"] != "medium" {
		t.Errorf("round-trip lost data: %v", sortedFlags(&got))
	}
}
