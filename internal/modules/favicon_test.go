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
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/fingerprint"
	"github.com/vmfunc/sif/internal/httpx"
)

// faviconFixture hashes to a negative int32, so its signed and unsigned forms
// differ and the unsigned-match case below actually exercises the fold.
var faviconFixture = []byte(strings.Repeat("sif-favicon-golden-test-bytes-", 8))

func TestCheckMatcherFavicon(t *testing.T) {
	body := string(faviconFixture)
	signed := int64(fingerprint.FaviconHash(faviconFixture))
	if signed >= 0 {
		t.Fatalf("fixture must hash to a negative int32 for the unsigned case to be meaningful, got %d", signed)
	}
	unsigned := int64(uint32(fingerprint.FaviconHash(faviconFixture)))

	tests := []struct {
		name   string
		hashes []int64
		expect bool
	}{
		{name: "signed match", hashes: []int64{signed}, expect: true},
		{name: "unsigned match", hashes: []int64{unsigned}, expect: true},
		{name: "one of many", hashes: []int64{1, 2, signed}, expect: true},
		{name: "no match", hashes: []int64{1, 2, 3}, expect: false},
		{name: "empty list", hashes: nil, expect: false},
		{name: "out-of-range ignored", hashes: []int64{1 << 40}, expect: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "favicon", Hash: tt.hashes}
			resp := fakeResponse(t, 200, nil)
			if got := checkMatcher(m, resp, body); got != tt.expect {
				t.Errorf("checkMatcher favicon = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestNormalizeFaviconHash(t *testing.T) {
	tests := []struct {
		name   string
		in     int64
		want   int32
		wantOK bool
	}{
		{name: "signed passthrough", in: -235701012, want: -235701012, wantOK: true},
		{name: "unsigned folds to signed", in: 4059266284, want: -235701012, wantOK: true},
		{name: "positive in range", in: 116323821, want: 116323821, wantOK: true},
		{name: "min int32", in: math.MinInt32, want: math.MinInt32, wantOK: true},
		{name: "max uint32 folds to -1", in: math.MaxUint32, want: -1, wantOK: true},
		{name: "above uint32 rejected", in: math.MaxUint32 + 1, wantOK: false},
		{name: "below int32 rejected", in: math.MinInt32 - 1, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeFaviconHash(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("normalizeFaviconHash(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestFaviconEvidence(t *testing.T) {
	body := string(faviconFixture)
	hashLine := fmt.Sprintf("favicon mmh3=%d", fingerprint.FaviconHash(faviconFixture))
	tests := []struct {
		name     string
		matchers []Matcher
		want     string
		wantOK   bool
	}{
		{name: "favicon only", matchers: []Matcher{{Type: "favicon"}}, want: hashLine, wantOK: true},
		{name: "favicon with status", matchers: []Matcher{{Type: "status"}, {Type: "favicon"}}, want: hashLine, wantOK: true},
		{name: "favicon with word keeps body", matchers: []Matcher{{Type: "word"}, {Type: "favicon"}}, wantOK: false},
		{name: "favicon with regex keeps body", matchers: []Matcher{{Type: "regex"}, {Type: "favicon"}}, wantOK: false},
		{name: "no favicon matcher", matchers: []Matcher{{Type: "status"}}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := faviconEvidence(tt.matchers, body)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("evidence = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFaviconEvidenceNamesCanonicalTech proves faviconEvidence consults the same
// SSOT table as fingerprint.LookupFaviconTech rather than a private copy: the
// evidence line must always match the format built directly from the shared
// hash + lookup functions, whether or not the fixture hash is canonical.
func TestFaviconEvidenceNamesCanonicalTech(t *testing.T) {
	body := string(faviconFixture)
	hash := fingerprint.FaviconHash(faviconFixture)
	want := fmt.Sprintf("favicon mmh3=%d", hash)
	if tech, ok := fingerprint.LookupFaviconTech(hash); ok {
		want = fmt.Sprintf("favicon mmh3=%d tech=%s", hash, tech)
	}

	got, ok := faviconEvidence([]Matcher{{Type: "favicon"}}, body)
	if !ok {
		t.Fatal("faviconEvidence ok = false, want true")
	}
	if got != want {
		t.Errorf("evidence = %q, want %q", got, want)
	}
}

// favicon demo modules must reference a hash from fingerprint.LookupFaviconTech
// that names the service in their filename, so a demo cannot drift from the
// canonical hash->tech table.
func TestFaviconDemoModulesMatchCanonicalMap(t *testing.T) {
	matches, err := filepath.Glob("../../modules/info/favicon-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no favicon demo modules present")
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			def, err := ParseYAMLModule(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if def.HTTP == nil {
				t.Fatal("favicon demo is not an http module")
			}

			var hashes []int64
			for _, m := range def.HTTP.Matchers {
				if m.Type == "favicon" {
					hashes = append(hashes, m.Hash...)
				}
			}
			if len(hashes) == 0 {
				t.Fatal("no favicon hash in module")
			}

			service := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "favicon-"), ".yaml")
			for _, h := range hashes {
				// hashes are range-checked at parse, so int32(h) is the canonical fold.
				tech, ok := fingerprint.LookupFaviconTech(int32(h))
				if !ok {
					t.Errorf("hash %d is absent from the canonical table; demo references a hash the scanner does not know", h)
					continue
				}
				if !strings.Contains(strings.ToLower(tech), service) {
					t.Errorf("hash %d maps to %q, but the file names service %q", h, tech, service)
				}
			}
		})
	}
}

func TestValidateMatchers(t *testing.T) {
	tests := []struct {
		name     string
		matchers []Matcher
		wantErr  bool
	}{
		{name: "valid signed", matchers: []Matcher{{Type: "favicon", Hash: []int64{-235701012}}}, wantErr: false},
		{name: "valid unsigned", matchers: []Matcher{{Type: "favicon", Hash: []int64{4059266284}}}, wantErr: false},
		{name: "favicon with no hash", matchers: []Matcher{{Type: "favicon"}}, wantErr: true},
		{name: "out-of-range hash", matchers: []Matcher{{Type: "favicon", Hash: []int64{99999999999}}}, wantErr: true},
		{name: "non-favicon ignored", matchers: []Matcher{{Type: "word", Words: []string{"x"}}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateMatchers(tt.matchers); (err != nil) != tt.wantErr {
				t.Errorf("validateMatchers err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// favicon composes with the negative flag like any other matcher.
func TestCheckMatcherFaviconNegative(t *testing.T) {
	signed := int64(fingerprint.FaviconHash(faviconFixture))
	matchers := []Matcher{{Type: "favicon", Hash: []int64{signed}, Negative: true}}
	resp := fakeResponse(t, 200, nil)
	if checkMatchers(matchers, "", resp, string(faviconFixture)) {
		t.Error("negative favicon matcher should not match its own hash")
	}
}

// drives the full executor: fetch favicon, match on its hash, report the hash.
func TestExecuteHTTPModuleFavicon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(faviconFixture)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// unsigned form must still match end to end
	unsigned := int64(uint32(fingerprint.FaviconHash(faviconFixture)))
	def := &YAMLModule{
		ID:   "favicon-fp",
		Type: TypeHTTP,
		Info: YAMLModuleInfo{Severity: "info"},
		HTTP: &HTTPConfig{
			Method: "GET",
			Paths:  []string{"{{BaseURL}}/favicon.ico"},
			Matchers: []Matcher{
				{Type: "status", Status: []int{200}},
				{Type: "favicon", Hash: []int64{unsigned}},
			},
		},
	}

	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}
	result, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}

	wantEvidence := fmt.Sprintf("favicon mmh3=%d", fingerprint.FaviconHash(faviconFixture))
	if got := result.Findings[0].Evidence; got != wantEvidence {
		t.Errorf("evidence = %q, want %q", got, wantEvidence)
	}
}
