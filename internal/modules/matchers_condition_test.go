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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vmfunc/sif/internal/httpx"
)

func TestCheckMatchersCondition(t *testing.T) {
	const body = "hello world"
	resp := fakeResponse(t, 200, nil)

	status200 := Matcher{Type: "status", Status: []int{200}}
	status500 := Matcher{Type: "status", Status: []int{500}}
	wordHit := Matcher{Type: "word", Part: "body", Words: []string{"hello"}}
	wordMiss := Matcher{Type: "word", Part: "body", Words: []string{"absent"}}

	tests := []struct {
		name      string
		condition string
		matchers  []Matcher
		expect    bool
	}{
		{"and both match", "and", []Matcher{status200, wordHit}, true},
		{"and one fails", "and", []Matcher{status200, wordMiss}, false},
		{"empty defaults to and", "", []Matcher{status200, wordMiss}, false},
		{"or one matches", "or", []Matcher{status500, wordHit}, true},
		{"or none match", "or", []Matcher{status500, wordMiss}, false},
		{"or all match", "or", []Matcher{status200, wordHit}, true},
		{"or is case-insensitive", "OR", []Matcher{status500, wordHit}, true},
		{"and is case-insensitive", "AND", []Matcher{status200, wordMiss}, false},
		{"or with negative pass", "or", []Matcher{{Type: "word", Part: "body", Words: []string{"absent"}, Negative: true}}, true},
		{"or all fail with negative", "or", []Matcher{{Type: "word", Part: "body", Words: []string{"hello"}, Negative: true}, wordMiss}, false},
		{"empty matcher list", "or", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkMatchers(tt.matchers, tt.condition, resp, body); got != tt.expect {
				t.Errorf("checkMatchers(%q) = %v, want %v", tt.condition, got, tt.expect)
			}
		})
	}
}

func TestValidateMatchersCondition(t *testing.T) {
	for _, ok := range []string{"", "and", "or", "AND", "Or"} {
		if err := validateMatchersCondition(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"xor", "nand", "any", "&&"} {
		if err := validateMatchersCondition(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestParseMatchersConditionValidation(t *testing.T) {
	write := func(cond string) string {
		p := filepath.Join(t.TempDir(), "m.yaml")
		body := fmt.Sprintf("id: mc\ntype: http\nhttp:\n  method: GET\n  paths: [\"{{BaseURL}}\"]\n  matchers-condition: %s\n  matchers:\n    - type: status\n      status: [200]\n", cond)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := ParseYAMLModule(write("or")); err != nil {
		t.Errorf("matchers-condition: or should parse: %v", err)
	}
	if _, err := ParseYAMLModule(write("xor")); err == nil {
		t.Error("matchers-condition: xor should be rejected at load")
	}
}

// or fires on the word match alone; and does not (status:500 fails).
func TestExecuteHTTPModuleMatchersConditionOr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "mc",
		Type: TypeHTTP,
		Info: YAMLModuleInfo{Severity: "info"},
		HTTP: &HTTPConfig{
			Method: "GET",
			Paths:  []string{"{{BaseURL}}/"},
			Matchers: []Matcher{
				{Type: "status", Status: []int{500}},
				{Type: "word", Part: "body", Words: []string{"hello"}},
			},
		},
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}

	def.HTTP.MatchersCondition = "or"
	res, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatalf("or: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("or: got %d findings, want 1", len(res.Findings))
	}

	def.HTTP.MatchersCondition = ""
	res, err = ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatalf("and: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("and: got %d findings, want 0 (status:500 fails)", len(res.Findings))
	}
}

func TestExecuteTCPModuleMatchersConditionOr(t *testing.T) {
	withFakeTCP(t, "+PONG\r\n")
	def := tcpDef(&TCPConfig{
		Port:              6379,
		Matchers:          []Matcher{tcpWord("absent-token"), tcpWord("+PONG")},
		MatchersCondition: "or",
	})

	res, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{})
	if err != nil {
		t.Fatalf("or: %v", err)
	}
	// or: the second matcher hits, so the finding fires even though the first
	// missed; default and would suppress it.
	if len(res.Findings) != 1 {
		t.Fatalf("or: got %d findings, want 1", len(res.Findings))
	}
}
