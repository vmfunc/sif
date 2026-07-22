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

func FuzzAnalyzeJWT(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")
	f.Add("a.b.c")
	f.Add("..")
	f.Add("")
	f.Add("not-a-jwt")

	f.Fuzz(func(t *testing.T, raw string) {
		analyzeJWT("fuzz", raw)
	})
}

func FuzzDecodeJWTSegment(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiJ9")
	f.Add("eyJzdWIiOiIxMjM0In0")
	f.Add("bm90LWpzb24")
	f.Add("!!!!")
	f.Add("")
	f.Add("eyJhIjp7ImIiOnsiYyI6MX19fQ")

	f.Fuzz(func(t *testing.T, seg string) {
		decodeJWTSegment(seg)
	})
}
