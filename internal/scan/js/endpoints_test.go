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

func TestExtractEndpoints(t *testing.T) {
	const base = "https://example.com/static/app.js"

	tests := []struct {
		name       string
		content    string
		wantSome   []string // each must appear in the result
		wantAbsent []string // none of these may appear
	}{
		{
			name:     "root-relative api path resolves to absolute",
			content:  `fetch("/api/users")`,
			wantSome: []string{"https://example.com/api/users"},
		},
		{
			name:     "absolute url passes through untouched",
			content:  `const u = "https://api.example.org/v1/login";`,
			wantSome: []string{"https://api.example.org/v1/login"},
		},
		{
			name:     "dotted-relative path resolves against base dir",
			content:  `import("./chunks/main.js")`,
			wantSome: []string{"https://example.com/static/chunks/main.js"},
		},
		{
			name:     "query string is preserved",
			content:  `axios.get("/api/search?q=test")`,
			wantSome: []string{"https://example.com/api/search?q=test"},
		},
		{
			name:       "mime types are filtered out",
			content:    `headers["Content-Type"] = "application/json"; var t = "text/html";`,
			wantAbsent: []string{"application/json", "text/html"},
		},
		{
			name:       "single words without a slash are ignored",
			content:    `var x = "hello"; var y = "world";`,
			wantAbsent: []string{"hello", "world"},
		},
		{
			name:    "multiple endpoints deduped",
			content: `fetch("/api/users"); fetch("/api/users"); fetch("/api/posts");`,
			wantSome: []string{
				"https://example.com/api/users",
				"https://example.com/api/posts",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractEndpoints(tt.content, base)

			for _, want := range tt.wantSome {
				if !slices.Contains(got, want) {
					t.Errorf("expected %q in %v", want, got)
				}
			}
			for _, absent := range tt.wantAbsent {
				if slices.Contains(got, absent) {
					t.Errorf("did not expect %q in %v", absent, got)
				}
			}
		})
	}
}

func TestExtractEndpointsDedupes(t *testing.T) {
	got := ExtractEndpoints(`fetch("/api/x"); fetch("/api/x");`, "https://example.com/app.js")
	count := 0
	for i := 0; i < len(got); i++ {
		if got[i] == "https://example.com/api/x" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected /api/x once, got %d times in %v", count, got)
	}
}

func TestExtractEndpointsBadBaseKeepsRelatives(t *testing.T) {
	// a base url that won't parse must not drop findings; relatives stay as-is.
	got := ExtractEndpoints(`fetch("/api/users")`, "::not a url::")
	if !slices.Contains(got, "/api/users") {
		t.Errorf("expected relative /api/users preserved, got %v", got)
	}
}
