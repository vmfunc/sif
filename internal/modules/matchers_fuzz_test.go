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

import (
	"strings"
	"testing"
)

// FuzzCheckWords exercises the word matcher with arbitrary content/word pairs
// under both conditions. The matcher must never panic, and an "or" over a set
// that includes the word must agree with a plain substring test.
func FuzzCheckWords(f *testing.F) {
	f.Add("versionInfo cluster config", "cluster", false)
	f.Add("", "", false)
	f.Add("AbCdEf", "abcdef", true)
	f.Add("a\x00b", "\x00", false)

	f.Fuzz(func(t *testing.T, content, word string, caseInsensitive bool) {
		// single-word "or": result must equal a direct Contains on the same
		// (optionally folded) operands.
		got := checkWords(content, []string{word}, "or", caseInsensitive)
		c, w := content, word
		if caseInsensitive {
			c, w = strings.ToLower(content), strings.ToLower(word)
		}
		if want := strings.Contains(c, w); got != want {
			t.Fatalf("checkWords(or) = %v, want %v (content=%q word=%q ci=%v)", got, want, content, word, caseInsensitive)
		}

		// an empty word list under "and" matches vacuously; under "or" it never
		// matches. Both must be panic-free regardless of content.
		_ = checkWords(content, nil, "and", caseInsensitive)
		if checkWords(content, nil, "or", caseInsensitive) {
			t.Fatalf("checkWords(or, empty) matched content=%q", content)
		}
	})
}

// FuzzCheckRegex ensures the regex matcher never panics on arbitrary patterns
// (invalid patterns are treated as a non-match, not a crash) and that a valid
// literal pattern agrees with a substring test.
func FuzzCheckRegex(f *testing.F) {
	f.Add("hello world", "world")
	f.Add("", "")
	f.Add("abc", "(")        // invalid pattern
	f.Add("a.b.c", `a\.b`)   // escaped literal
	f.Add("status 200", "2") // digit

	f.Fuzz(func(t *testing.T, content, pattern string) {
		// must not panic under either condition.
		or := checkRegex(content, []string{pattern}, "or")
		and := checkRegex(content, []string{pattern}, "and")

		// a single pattern makes and/or equivalent.
		if or != and {
			t.Fatalf("checkRegex and/or disagree for content=%q pattern=%q: and=%v or=%v", content, pattern, and, or)
		}
	})
}
