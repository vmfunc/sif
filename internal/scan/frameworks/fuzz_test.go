/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package frameworks

import "testing"

func FuzzIsValidVersionString(f *testing.F) {
	f.Add("1.0")
	f.Add("1.0.0")
	f.Add("10.2.3.4")
	f.Add("999.999.999")
	f.Add("")
	f.Add("abc")
	f.Add("1.")
	f.Add(".1")
	f.Add("1.2.3.4.5")
	f.Add("aaaaaaaaaaaaaaaaaaaaaaaaa")

	f.Fuzz(func(t *testing.T, v string) {
		// should never panic
		isValidVersionString(v)
	})
}

func FuzzExtractVersionOptimized(f *testing.F) {
	f.Add("<meta name=\"generator\" content=\"WordPress 6.4.2\">", "WordPress")
	f.Add("Laravel v10.0.1", "Laravel")
	f.Add("<html>nothing</html>", "Django")
	f.Add("", "unknown")
	f.Add("X-Powered-By: Express/4.18.2", "Express")

	f.Fuzz(func(t *testing.T, body string, framework string) {
		// should never panic
		ExtractVersionOptimized(body, framework)
	})
}
