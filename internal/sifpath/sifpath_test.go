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

package sifpath

import (
	"path/filepath"
	"testing"
)

func TestUserSubdirLayout(t *testing.T) {
	got, err := UserSubdir("modules")
	if err != nil {
		t.Fatalf("UserSubdir returned error: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("UserSubdir(%q) = %q, want an absolute path", "modules", got)
	}
	if base := filepath.Base(got); base != "modules" {
		t.Errorf("UserSubdir(%q) base = %q, want %q", "modules", base, "modules")
	}
	if parent := filepath.Base(filepath.Dir(got)); parent != "sif" {
		t.Errorf("UserSubdir(%q) parent = %q, want %q", "modules", parent, "sif")
	}
}

func TestUserSubdirSiblings(t *testing.T) {
	mods, err := UserSubdir("modules")
	if err != nil {
		t.Fatalf("UserSubdir(modules): %v", err)
	}
	sigs, err := UserSubdir("signatures")
	if err != nil {
		t.Fatalf("UserSubdir(signatures): %v", err)
	}
	if filepath.Dir(mods) != filepath.Dir(sigs) {
		t.Errorf("modules dir %q and signatures dir %q should share a parent", mods, sigs)
	}
}
