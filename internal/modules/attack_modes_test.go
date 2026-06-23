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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/vmfunc/sif/internal/httpx"
)

func reqURLs(reqs []*httpRequest) []string {
	urls := make([]string, len(reqs))
	for i, r := range reqs {
		urls[i] = r.URL
	}
	sort.Strings(urls)
	return urls
}

func TestGenerateHTTPRequestsAttack(t *testing.T) {
	const target = "http://t"
	paths2 := []string{"{{BaseURL}}/a?x={{payload}}", "{{BaseURL}}/b?x={{payload}}"}
	pay2 := []string{"1", "2"}
	cross := []string{"http://t/a?x=1", "http://t/a?x=2", "http://t/b?x=1", "http://t/b?x=2"}
	paired := []string{"http://t/a?x=1", "http://t/b?x=2"}

	tests := []struct {
		name     string
		paths    []string
		payloads []string
		attack   string
		want     []string
	}{
		{"clusterbomb default crosses all", paths2, pay2, "", cross},
		{"clusterbomb explicit crosses all", paths2, pay2, "clusterbomb", cross},
		{"pitchfork pairs by index", paths2, pay2, "pitchfork", paired},
		{"pitchfork stops at fewer payloads", append(paths2, "{{BaseURL}}/c?x={{payload}}"), pay2, "pitchfork", paired},
		{"pitchfork stops at fewer paths", paths2, []string{"1", "2", "3"}, "pitchfork", paired},
		{"attack is case insensitive", paths2, pay2, "Pitchfork", paired},
		{"no payloads ignores attack", []string{"{{BaseURL}}/a", "{{BaseURL}}/b"}, nil, "pitchfork", []string{"http://t/a", "http://t/b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &HTTPConfig{Paths: tt.paths, Payloads: tt.payloads, Attack: tt.attack}
			reqs, err := generateHTTPRequests(target, cfg)
			if err != nil {
				t.Fatalf("generateHTTPRequests: %v", err)
			}
			got := reqURLs(reqs)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("attack %q:\n got %v\nwant %v", tt.attack, got, want)
			}
		})
	}
}

func TestValidateAttack(t *testing.T) {
	for _, ok := range []string{"", "clusterbomb", "pitchfork", "Pitchfork", "CLUSTERBOMB"} {
		if err := validateAttack(ok); err != nil {
			t.Errorf("validateAttack(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"sniper", "batteringram", "bogus"} {
		if err := validateAttack(bad); err == nil {
			t.Errorf("validateAttack(%q) = nil, want error", bad)
		}
	}
}

func TestParseAttackValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.yaml", "id: ok\ntype: http\nhttp:\n  attack: pitchfork\n  paths: [\"{{BaseURL}}/\"]\n")
	if _, err := ParseYAMLModule(good); err != nil {
		t.Fatalf("valid attack rejected: %v", err)
	}

	bad := write("bad.yaml", "id: bad\ntype: http\nhttp:\n  attack: sniper\n  paths: [\"{{BaseURL}}/\"]\n")
	if _, err := ParseYAMLModule(bad); err == nil {
		t.Fatal("invalid attack accepted")
	}
}

// TestExecuteHTTPModulePitchfork drives the executor end to end and confirms
// pitchfork only fires the index-paired requests, not the full cross product.
func TestExecuteHTTPModulePitchfork(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "pf",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Attack:   "pitchfork",
			Paths:    []string{"{{BaseURL}}/a?x={{payload}}", "{{BaseURL}}/b?x={{payload}}"},
			Payloads: []string{"1", "2"},
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}

	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}
	if _, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts); err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), hits...)
	mu.Unlock()
	sort.Strings(got)
	want := []string{"/a?x=1", "/b?x=2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pitchfork hit %v, want %v (clusterbomb would also hit /a?x=2 and /b?x=1)", got, want)
	}
}
