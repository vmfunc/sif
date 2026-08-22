package output

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// regression guard: Highlight.Render must strip embedded control/OSC bytes
// from its argument before styling it, even under NO_COLOR, so an
// attacker-controlled string (a response title, header, ...) can't rewrite
// the terminal title or move the cursor when it's highlighted for display.
func TestHighlightRenderStripsEmbeddedESC(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	lipgloss.SetColorProfile(4)
	evil := "\x1b]0;PWNED\x07x"
	out := Highlight.Render(evil)
	if strings.Contains(out, "\x1b]0;PWNED\x07") {
		t.Fatalf("NO_COLOR path let attacker OSC sequence through: %q", out)
	}
	if !strings.Contains(out, "x") {
		t.Fatalf("legitimate content was lost, got %q", out)
	}
	t.Logf("CONFIRMED: Render strips attacker control bytes from content: %q", out)
}
