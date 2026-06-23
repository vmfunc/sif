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
	"fmt"
	"math"

	"github.com/vmfunc/sif/internal/fingerprint"
)

// checkFaviconHash reports whether the body's shodan mmh3 hash matches any
// configured value. only the body (the icon) is hashed; part is ignored.
func checkFaviconHash(body string, want []int64) bool {
	if len(want) == 0 {
		return false
	}
	got := fingerprint.FaviconHash([]byte(body))
	for _, w := range want {
		if n, ok := normalizeFaviconHash(w); ok && n == got {
			return true
		}
	}
	return false
}

// normalizeFaviconHash folds a hash to the signed int32 shodan stores, accepting
// either 32-bit form so a signed or unsigned value pastes in as-is. out-of-range
// values are rejected so a stray number can't wrap into a false match.
func normalizeFaviconHash(v int64) (int32, bool) {
	if v < math.MinInt32 || v > math.MaxUint32 {
		return 0, false
	}
	return int32(uint32(v)), true //nolint:gosec // intentional 32-bit fold to shodan's signed form
}

// faviconEvidence gives the hash as evidence for a favicon-only finding, and
// nothing when a word/regex matcher is present so its body evidence stands.
func faviconEvidence(matchers []Matcher, body string) (string, bool) {
	favicon := false
	for i := range matchers {
		switch matchers[i].Type {
		case "word", "regex":
			return "", false
		case "favicon":
			favicon = true
		}
	}
	if !favicon {
		return "", false
	}
	return fmt.Sprintf("favicon mmh3=%d", fingerprint.FaviconHash([]byte(body))), true
}

// validateMatchers fails favicon matchers that would silently never fire (no
// hash, or one out of 32-bit range) at load rather than at match time.
func validateMatchers(matchers []Matcher) error {
	for i := range matchers {
		if matchers[i].Type != "favicon" {
			continue
		}
		if len(matchers[i].Hash) == 0 {
			return fmt.Errorf("favicon matcher requires at least one hash")
		}
		for _, h := range matchers[i].Hash {
			if _, ok := normalizeFaviconHash(h); !ok {
				return fmt.Errorf("favicon hash %d out of range (use a signed int32 or unsigned uint32 value)", h)
			}
		}
	}
	return nil
}
