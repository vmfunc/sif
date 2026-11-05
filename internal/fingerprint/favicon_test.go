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

package fingerprint

import (
	"strings"
	"testing"
)

// goldenFaviconBytes is a fixed payload long enough to span multiple base64
// lines, so the python-style 76-char chunking is actually exercised by the hash.
var goldenFaviconBytes = []byte(strings.Repeat("sif-favicon-golden-test-bytes-", 8))

// goldenFaviconHash is the pinned shodan mmh3 hash of goldenFaviconBytes: the python
// base64.encodebytes byte stream (76-char lines + trailing newline) through murmur3-32,
// reinterpreted as a signed int32. if the chunking or signedness regress, this test fails.
const goldenFaviconHash int32 = -1554620260

// goldenHelloHash pins a short single-line case so a regression in the trailing
// newline (which the small case still has) is caught independently.
const goldenHelloHash int32 = 1155597304

func TestFaviconHashGolden(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int32
	}{
		{name: "multi-line fixture", in: goldenFaviconBytes, want: goldenFaviconHash},
		{name: "single-line hello", in: []byte("hello"), want: goldenHelloHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FaviconHash(tt.in); got != tt.want {
				t.Errorf("FaviconHash = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestLookupFaviconTech proves the SSOT table is the single place all twelve
// facts are resolved: every entry round-trips, an unknown hash misses, and the
// count is pinned so an accidental addition/removal is caught.
func TestLookupFaviconTech(t *testing.T) {
	if len(faviconTech) != 12 {
		t.Fatalf("faviconTech has %d entries, want 12", len(faviconTech))
	}
	for hash, want := range faviconTech {
		got, ok := LookupFaviconTech(hash)
		if !ok {
			t.Errorf("LookupFaviconTech(%d) ok = false, want true", hash)
		}
		if got != want {
			t.Errorf("LookupFaviconTech(%d) = %q, want %q", hash, got, want)
		}
	}

	if tech, ok := LookupFaviconTech(0); ok {
		t.Errorf("LookupFaviconTech(0) = (%q, true), want (\"\", false)", tech)
	}

	tests := []struct {
		hash int32
		want string
	}{
		{hash: -1255347784, want: "GitLab"},
		{hash: 116323821, want: "Apache Tomcat"},
	}
	for _, tt := range tests {
		if got, ok := LookupFaviconTech(tt.hash); !ok || got != tt.want {
			t.Errorf("LookupFaviconTech(%d) = (%q, %v), want (%q, true)", tt.hash, got, ok, tt.want)
		}
	}
}

// TestFaviconBase64Chunking pins the encode step against python's
// base64.encodebytes: a 60-byte input encodes to 80 base64 chars, so it must
// wrap into two newline-terminated lines.
func TestFaviconBase64Chunking(t *testing.T) {
	in := []byte(strings.Repeat("A", 60))
	got := string(encodeFaviconBase64(in))

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 wrapped lines, got %d: %q", len(lines), got)
	}
	if len(lines[0]) != b64LineLen {
		t.Errorf("first line = %d chars, want %d", len(lines[0]), b64LineLen)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("encoding must end in a trailing newline, got %q", got)
	}
}

// a tech that reskinned its default icon needs one entry per generation, so
// pin that every known gitea icon resolves rather than just the newest.
func TestGiteaFaviconGenerationsAllResolve(t *testing.T) {
	for _, hash := range []int32{-754147112, -1668137428, -1893514588} {
		tech, ok := LookupFaviconTech(hash)
		if !ok {
			t.Errorf("gitea favicon %d is absent from the table", hash)
			continue
		}
		if tech != "Gitea" {
			t.Errorf("LookupFaviconTech(%d) = %q, want Gitea", hash, tech)
		}
	}
}
