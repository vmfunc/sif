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
