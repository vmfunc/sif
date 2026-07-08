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

package modules

import "testing"

func FuzzParseYAMLModule(f *testing.F) {
	f.Add([]byte("id: t\ntype: http\n"))
	f.Add([]byte("id: x\ntype: http\nhttp:\n  matchers:\n    - type: word\n      words: [foo]\n"))
	f.Add([]byte("type: http\n"))
	f.Add([]byte("id: x\ntype: dns\n"))
	f.Add([]byte(""))
	f.Add([]byte("id: x\ntype: http\nhttp:\n  matchers-condition: xor\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		parseYAMLModuleBytes(data)
	})
}
