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

func FuzzExtractTitle(f *testing.F) {
	f.Add([]byte("<html><head><title>Hi</title></head></html>"))
	f.Add([]byte("<TITLE class=x>  spaced  </TITLE>"))
	f.Add([]byte("<title>unclosed"))
	f.Add([]byte("<title></title>"))
	f.Add([]byte("no title here"))
	f.Add([]byte(""))
	f.Add([]byte("<title>a</title><title>b</title>"))

	f.Fuzz(func(t *testing.T, body []byte) {
		extractTitle(body)
	})
}
