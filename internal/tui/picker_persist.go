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
	"os"
	"path/filepath"

	"github.com/vmfunc/sif/internal/sifpath"
	"gopkg.in/yaml.v3"
)

// persistedSelection is the on-disk shape of the last picker selection, stored
// at <user-config>/sif/tui.yaml so a returning user starts where they left off.
type persistedSelection struct {
	Toggles map[string]bool   `yaml:"toggles,omitempty"`
	Sizes   map[string]string `yaml:"sizes,omitempty"`
}

// selectionPath is the persistence file location.
func selectionPath() (string, error) {
	return sifpath.UserSubdir("tui.yaml")
}

// loadSelection reads the last saved selection, returning an empty one if the
// file is missing or unreadable (persistence is best-effort, never fatal).
func loadSelection() Selection {
	sel := NewSelection()
	path, err := selectionPath()
	if err != nil {
		return sel
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sel
	}
	var p persistedSelection
	if yaml.Unmarshal(data, &p) != nil {
		return sel
	}
	for k, v := range p.Toggles {
		sel.Toggles[k] = v
	}
	for k, v := range p.Sizes {
		sel.Sizes[k] = v
	}
	return sel
}

// saveSelection writes the selection for next launch. Errors are returned for
// the caller to log at debug level, but never block a run.
func saveSelection(sel *Selection) error {
	path, err := selectionPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := yaml.Marshal(persistedSelection{Toggles: sel.Toggles, Sizes: sel.Sizes})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
