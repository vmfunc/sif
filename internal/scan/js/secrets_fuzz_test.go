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

package js

import (
	"strings"
	"testing"
)

func FuzzScanSecrets(f *testing.F) {
	f.Add(`const key = "AKIAIOSFODNN7EXAMPLE"`, "https://example.com/app.js")
	f.Add(`apikey: "sk-1234567890abcdefghij"`, "")
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxyz01", "src")
	f.Add("-----BEGIN RSA PRIVATE KEY-----", "")
	f.Add(`var token = ""`, "")
	f.Add("", "")
	f.Add("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "js")

	f.Fuzz(func(t *testing.T, content, srcURL string) {
		for _, m := range ScanSecrets(content, srcURL) {
			// a reported match must be a non-empty run lifted verbatim from the
			// input; anything else means the capture-group indexing is off
			if m.Match == "" {
				t.Fatalf("empty Match for rule %q", m.Rule)
			}
			if !strings.Contains(content, m.Match) {
				t.Fatalf("Match %q (rule %q) not found in input", m.Match, m.Rule)
			}
		}
	})
}
