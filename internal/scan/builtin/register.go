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

package builtin

import "github.com/vmfunc/sif/internal/modules"

// Register registers all Go-based built-in scans as modules.
// Allows complex Go scans to participate in the module system
func Register() {
	modules.Register(&ShodanModule{})
	modules.Register(&FrameworksModule{})
	modules.Register(&CDNModule{})
	modules.Register(&NucleiModule{})
	modules.Register(&WhoisModule{})
	modules.Register(&SecurityTrailsModule{})
}
