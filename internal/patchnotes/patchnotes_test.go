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

package patchnotes

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSeenRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sif", "seen_version")

	if hasSeen(path, "2026.6.7") {
		t.Fatal("nothing recorded yet, hasSeen should be false")
	}

	recordSeen(path, "2026.6.7")
	if !hasSeen(path, "2026.6.7") {
		t.Error("recorded version should read back as seen")
	}
	if hasSeen(path, "2026.6.8") {
		t.Error("a different version should not be seen")
	}
}

func TestRenderIncludesTag(t *testing.T) {
	out := render(&release{TagName: "v2026.6.7", Body: "## what's changed\n- a thing"})
	if !strings.Contains(out, "v2026.6.7") {
		t.Errorf("rendered notes should include the tag, got %q", out)
	}
}
