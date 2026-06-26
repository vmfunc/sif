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

package frameworks_test

import (
	"testing"

	frameworks "github.com/vmfunc/sif/internal/scan/frameworks"
)

func TestExtractVersion_NoDecoyMisextraction(t *testing.T) {
	got := frameworks.ExtractVersionOptimized(`<!-- rails app --><link href="/app-7.8.9.css">`, "Ruby on Rails").Version
	if got == "7.8.9" {
		t.Errorf("Rails: mis-extracted decoy asset version %q", got)
	}

	got = frameworks.ExtractVersionOptimized(`Server: Rails/7.1.3`, "Ruby on Rails").Version
	if got != "7.1.3" {
		t.Errorf("Rails: version = %q, want 7.1.3", got)
	}
}

func TestExtractVersion_SingleInteger(t *testing.T) {
	got := frameworks.ExtractVersionOptimized(`<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">`, "Drupal").Version
	if got != "10" {
		t.Errorf("Drupal: version = %q, want 10", got)
	}
}
