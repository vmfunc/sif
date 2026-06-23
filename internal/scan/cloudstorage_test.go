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

import (
	"slices"
	"testing"
)

func TestExtractPotentialBuckets(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		want   []string // candidates that must be generated
		absent []string // candidates that must not be generated
	}{
		{
			name:   "strips the tld and pairs labels both ways",
			host:   "shop.example.com",
			want:   []string{"shop", "shop-s3", "s3-shop", "example", "shop-example", "example-shop"},
			absent: []string{"com", "com-s3", "s3-com", "example-com", "com-example"},
		},
		{
			name:   "combines non-adjacent labels",
			host:   "a.b.c.example.com",
			want:   []string{"a-c", "c-a", "a-example", "example-a", "b-example"},
			absent: []string{"com", "example-com"},
		},
		{
			name:   "single-label host keeps its only label and makes no pairs",
			host:   "localhost",
			want:   []string{"localhost", "localhost-s3", "s3-localhost"},
			absent: []string{"localhost-localhost", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPotentialBuckets(tt.host)
			for _, w := range tt.want {
				if !slices.Contains(got, w) {
					t.Errorf("extractPotentialBuckets(%q) missing %q; got %v", tt.host, w, got)
				}
			}
			for _, a := range tt.absent {
				if slices.Contains(got, a) {
					t.Errorf("extractPotentialBuckets(%q) should not generate %q; got %v", tt.host, a, got)
				}
			}
		})
	}
}
