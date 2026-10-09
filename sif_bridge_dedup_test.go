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

package sif

import (
	"context"
	"testing"

	"github.com/vmfunc/sif/internal/config"
	"github.com/vmfunc/sif/internal/modules"
)

// stubModule is a registry entry with an id and tags and nothing else; these
// tests only exercise selection, never execution.
type stubModule struct {
	id   string
	tags []string
}

func (m stubModule) Info() modules.Info {
	return modules.Info{ID: m.id, Name: m.id, Tags: m.tags}
}
func (m stubModule) Type() modules.ModuleType { return modules.TypeFingerprint }
func (m stubModule) Execute(context.Context, string, modules.Options) (*modules.Result, error) {
	return &modules.Result{}, nil
}

func ids(ms []modules.Module) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Info().ID)
	}
	return out
}

func has(ms []modules.Module, id string) bool {
	for _, m := range ms {
		if m.Info().ID == id {
			return true
		}
	}
	return false
}

// a bridged fingerprint is reported by the framework engine, so running it as a
// module too names the same technology twice. that is the whole point of
// BridgeFingerprints returning its id set, and nothing else enforces it.
func TestSelectModulesDropsBridgedFromImplicitSelections(t *testing.T) {
	bridgedID := "sif-test-bridged-fp"
	otherID := "sif-test-plain-fp"
	modules.Register(stubModule{id: bridgedID, tags: []string{"sif-test-tag"}})
	modules.Register(stubModule{id: otherID, tags: []string{"sif-test-tag"}})

	newApp := func(s *config.Settings) *App {
		return &App{settings: s, bridgedFingerprints: map[string]bool{bridgedID: true}}
	}

	t.Run("-all-modules skips it", func(t *testing.T) {
		got := newApp(&config.Settings{AllModules: true}).selectModules()
		if has(got, bridgedID) {
			t.Errorf("%s ran under -all-modules despite being bridged; it would be reported twice", bridgedID)
		}
		if !has(got, otherID) {
			t.Errorf("%s was dropped too, want only the bridged id filtered (got %v)", otherID, ids(got))
		}
	})

	t.Run("-tags skips it", func(t *testing.T) {
		got := newApp(&config.Settings{ModuleTags: "sif-test-tag"}).selectModules()
		if has(got, bridgedID) {
			t.Errorf("%s ran under -tags despite being bridged", bridgedID)
		}
		if !has(got, otherID) {
			t.Errorf("%s was dropped from the tag selection, got %v", otherID, ids(got))
		}
	})

	// naming a module is a direct request, not an implicit sweep, so the
	// filter must not silently swallow it.
	t.Run("-modules still runs it", func(t *testing.T) {
		got := newApp(&config.Settings{Modules: bridgedID}).selectModules()
		if !has(got, bridgedID) {
			t.Errorf("-modules %s selected nothing; an explicitly named module must run even when bridged", bridgedID)
		}
	})

	// with no framework scan there is nothing to be covered by, so the
	// selection must be untouched.
	t.Run("nothing bridged is a passthrough", func(t *testing.T) {
		app := &App{settings: &config.Settings{AllModules: true}}
		got := app.selectModules()
		if !has(got, bridgedID) || !has(got, otherID) {
			t.Errorf("an empty bridged set must not filter anything, got %v", ids(got))
		}
	})
}

// the tag branch unions several ByTag results, which can name the same module
// twice; the executor must not run it twice.
func TestSelectModulesDedupesOverlappingTags(t *testing.T) {
	id := "sif-test-two-tags"
	modules.Register(stubModule{id: id, tags: []string{"sif-test-a", "sif-test-b"}})

	app := &App{settings: &config.Settings{ModuleTags: "sif-test-a,sif-test-b"}}
	got := app.selectModules()

	n := 0
	for _, m := range got {
		if m.Info().ID == id {
			n++
		}
	}
	if n != 1 {
		t.Errorf("module matching both tags selected %d times, want 1", n)
	}
}
