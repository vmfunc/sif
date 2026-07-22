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
	"embed"
	"io/fs"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/modules"
)

// builtinModules embeds the module tree into the binary. this file lives at the
// repo root because go:embed cannot reference a parent directory, and modules/
// sits above internal/modules where the loader lives.
//
//go:embed modules
var builtinModules embed.FS

// register the embedded modules with the loader once, rooted at the modules
// directory so paths match the on-disk layout. the loader only uses this as a
// fallback when no filesystem modules/ dir is present.
func init() {
	sub, err := fs.Sub(builtinModules, "modules")
	if err != nil {
		log.Debugf("embedded modules unavailable: %v", err)
		return
	}
	modules.SetBuiltinFS(sub)
}
