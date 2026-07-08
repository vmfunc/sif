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
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vmfunc/sif/internal/httpx"
)

// legacyPayloads builds the single anonymous set the sequence form desugars to,
// so existing tests that used a flat []string keep their exact meaning.
func legacyPayloads(vals []string) PayloadSets {
	if len(vals) == 0 {
		return PayloadSets{}
	}
	return PayloadSets{Sets: []PayloadSet{{Name: "payload", Values: vals}}}
}

func TestPayloadSetsUnmarshalSequence(t *testing.T) {
	var cfg HTTPConfig
	if err := yaml.Unmarshal([]byte("payloads: [\"a\", \"b\"]\n"), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []PayloadSet{{Name: "payload", Values: []string{"a", "b"}}}
	if !reflect.DeepEqual(cfg.Payloads.Sets, want) {
		t.Errorf("sequence form = %+v, want %+v", cfg.Payloads.Sets, want)
	}
}

func TestPayloadSetsUnmarshalMappingOrdered(t *testing.T) {
	// both keys are inline here (not file-backed): a file-backed entry is
	// rejected by validate() in this task (see TestPayloadSetsValidation), so
	// mixing one in would make this parse fail rather than exercise ordering.
	var cfg HTTPConfig
	src := "payloads:\n  user: [\"admin\", \"root\"]\n  role: [\"admin\", \"user\"]\n"
	if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []PayloadSet{
		{Name: "user", Values: []string{"admin", "root"}},
		{Name: "role", Values: []string{"admin", "user"}},
	}
	if !reflect.DeepEqual(cfg.Payloads.Sets, want) {
		t.Errorf("mapping form = %+v, want %+v", cfg.Payloads.Sets, want)
	}
}

func TestPayloadSetsValidation(t *testing.T) {
	// duplicate set name
	if err := yaml.Unmarshal([]byte("payloads:\n  x: [\"1\"]\n  x: [\"2\"]\n"), &HTTPConfig{}); err == nil {
		t.Error("duplicate set name accepted")
	}
	// reserved builtin name
	if err := yaml.Unmarshal([]byte("payloads:\n  BaseURL: [\"1\"]\n"), &HTTPConfig{}); err == nil {
		t.Error("BaseURL set name accepted")
	}
	// file-backed set now parses (loaded at resolve time)
	if err := yaml.Unmarshal([]byte("payloads:\n  p: creds.txt\n"), &HTTPConfig{}); err != nil {
		t.Errorf("file-backed set rejected: %v", err)
	}
}

func TestResolveSetsLoadsFile(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(wl, []byte("admin\nroot\n\nguest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &HTTPConfig{
		Paths: []string{"{{BaseURL}}/?u={{user}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", File: wl},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// loadWordlist skips the blank line, leaving 3 words.
	want := []string{"http://t/?u=admin", "http://t/?u=guest", "http://t/?u=root"}
	urls := reqURLs(got)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("file-set urls = %v, want %v", urls, want)
	}
}

func TestResolveSetsMissingFile(t *testing.T) {
	cfg := &HTTPConfig{
		Paths:    []string{"{{BaseURL}}/?u={{user}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{{Name: "user", File: "/no/such/wordlist"}}},
	}
	if _, err := generateHTTPRequests("http://t", cfg); err == nil {
		t.Error("missing wordlist accepted")
	}
}

func TestStreamRequestsMultiSetClusterbomb(t *testing.T) {
	cfg := &HTTPConfig{
		Paths: []string{"{{BaseURL}}/x?u={{user}}&p={{pass}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", Values: []string{"a", "b"}},
			{Name: "pass", Values: []string{"1", "2"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// paths outer, sets in declaration order, rightmost (pass) fastest.
	want := []string{
		"http://t/x?u=a&p=1", "http://t/x?u=a&p=2",
		"http://t/x?u=b&p=1", "http://t/x?u=b&p=2",
	}
	urls := reqURLs(got) // reqURLs sorts; sort want too
	sort.Strings(want)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("clusterbomb urls = %v, want %v", urls, want)
	}
}

func TestStreamRequestsMultiSetPitchfork(t *testing.T) {
	cfg := &HTTPConfig{
		Attack: "pitchfork",
		Paths:  []string{"{{BaseURL}}/a?u={{user}}&p={{pass}}", "{{BaseURL}}/b?u={{user}}&p={{pass}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", Values: []string{"a", "b", "c"}},
			{Name: "pass", Values: []string{"1", "2"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// zip paths(2) x user(3) x pass(2) -> stop at 2
	want := []string{"http://t/a?u=a&p=1", "http://t/b?u=b&p=2"}
	urls := reqURLs(got)
	sort.Strings(want)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("pitchfork urls = %v, want %v", urls, want)
	}
}

func TestStreamRequestsHeaderSubstitution(t *testing.T) {
	cfg := &HTTPConfig{
		Paths:   []string{"{{BaseURL}}/"},
		Headers: map[string]string{"X-Token": "t-{{payload}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "payload", Values: []string{"abc"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(got) != 1 || got[0].Headers["X-Token"] != "t-abc" {
		t.Errorf("header not substituted: %+v", got[0].Headers)
	}
}

func TestExecuteHTTPModuleBudgetTruncates(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// 10 x 10 = 100 combinations, capped at 15.
	users := make([]string, 10)
	passes := make([]string, 10)
	for i := range users {
		users[i] = string(rune('a' + i))
		passes[i] = string(rune('0' + i))
	}
	def := &YAMLModule{
		ID:   "fz",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths: []string{"{{BaseURL}}/?u={{user}}&p={{pass}}"},
			Payloads: PayloadSets{Sets: []PayloadSet{
				{Name: "user", Values: users},
				{Name: "pass", Values: passes},
			}},
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout), FuzzMaxRequests: 15}
	if _, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts); err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 15 {
		t.Errorf("sent %d requests, want 15 (budget cap)", got)
	}
}

func TestExecuteHTTPModuleBudgetUnlimited(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "fz",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/?p={{payload}}"},
			Payloads: legacyPayloads([]string{"1", "2", "3", "4", "5"}),
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout), FuzzMaxRequests: 0}
	if _, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts); err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 5 {
		t.Errorf("sent %d requests, want 5 (0 = unlimited)", got)
	}
}
