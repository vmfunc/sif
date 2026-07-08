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

package scan

import "testing"

func FuzzParseOpenAPISpec(f *testing.F) {
	f.Add([]byte(`{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}`))
	f.Add([]byte(`{"swagger":"2.0","paths":{"/y":{}}}`))
	f.Add([]byte("openapi: 3.0.0\npaths:\n  /z:\n    get: {}\n"))
	f.Add([]byte(`{"paths":{}}`))
	f.Add([]byte("not a spec"))
	f.Add([]byte(""))
	f.Add([]byte("{"))

	f.Fuzz(func(t *testing.T, body []byte) {
		spec, ok := parseOpenAPISpec(body)
		if ok && spec == nil {
			t.Fatal("parseOpenAPISpec returned ok with a nil spec")
		}
	})
}
