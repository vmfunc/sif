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
	"slices"
	"testing"
)

func FuzzExtractEndpoints(f *testing.F) {
	f.Add(`fetch("/api/users")`, "https://example.com/app.js")
	f.Add(`url: "https://cdn.example.com/v1/data.json"`, "")
	f.Add(`const p = "../relative/path"`, "https://example.com/a/b/")
	f.Add(`"text/html"`, "https://example.com")
	f.Add("", "")
	f.Add(`axios.get("/x").then()`, "not a url")

	f.Fuzz(func(t *testing.T, content, baseURL string) {
		got := ExtractEndpoints(content, baseURL)
		for _, e := range got {
			if e == "" {
				t.Fatal("ExtractEndpoints returned an empty endpoint")
			}
		}
		if !slices.IsSorted(got) {
			t.Fatalf("ExtractEndpoints result not sorted: %v", got)
		}
	})
}
