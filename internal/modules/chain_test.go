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
	"testing"

	"github.com/vmfunc/sif/internal/httpx"
)

// TestParseYAMLChainModule pins that the requests: chain schema round-trips from
// yaml into HTTPStep, so a module file can express a chain end to end.
func TestParseYAMLChainModule(t *testing.T) {
	const src = `
id: chain-example
type: http
info:
  name: chain example
  severity: high
http:
  requests:
    - name: login
      path: "{{BaseURL}}/login"
      extractors:
        - type: json
          name: token
          json: ["token"]
    - name: authed
      path: "{{BaseURL}}/secret"
      headers:
        Authorization: "Bearer {{token}}"
      matchers:
        - type: word
          part: body
          words: ["TOP SECRET"]
`
	path := filepath.Join(t.TempDir(), "chain-example.yaml")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
	def, err := ParseYAMLModule(path)
	if err != nil {
		t.Fatalf("ParseYAMLModule: %v", err)
	}
	if def.HTTP == nil || len(def.HTTP.Requests) != 2 {
		t.Fatalf("want 2 chain steps, got %+v", def.HTTP)
	}
	if def.HTTP.Requests[0].Extractors[0].Name != "token" {
		t.Errorf("step 1 extractor name = %q, want token", def.HTTP.Requests[0].Extractors[0].Name)
	}
	if def.HTTP.Requests[1].Headers["Authorization"] != "Bearer {{token}}" {
		t.Errorf("step 2 auth header = %q, want templated bearer", def.HTTP.Requests[1].Headers["Authorization"])
	}
}

// chainServer is a two-endpoint app: /login hands back a token, /secret only
// serves its body when that token rides in the Authorization header. it's the
// canonical fetch-token-then-use-it flow the request chain exists to express.
func chainServer() *httptest.Server {
	const token = "tok-abc123"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"` + token + `"}`))
		case "/secret":
			if r.Header.Get("Authorization") == "Bearer "+token {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("TOP SECRET DATA"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("denied"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func chainModule() *YAMLModule {
	return &YAMLModule{
		ID:   "test-chain",
		Type: TypeHTTP,
		Info: YAMLModuleInfo{Severity: "high"},
		HTTP: &HTTPConfig{
			Requests: []HTTPStep{
				{
					Name:       "login",
					Path:       "{{BaseURL}}/login",
					Extractors: []Extractor{{Type: "json", Name: "token", Part: "body", JSON: []string{"token"}}},
				},
				{
					Name:     "authed",
					Path:     "{{BaseURL}}/secret",
					Headers:  map[string]string{"Authorization": "Bearer {{token}}"},
					Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"TOP SECRET"}}},
				},
			},
		},
	}
}

// TestExecuteHTTPChainPropagatesVariable checks the core of chaining: step 1
// extracts a token, step 2 injects it into a header and only then can match the
// protected body. it fails unless the value actually crossed between requests.
func TestExecuteHTTPChainPropagatesVariable(t *testing.T) {
	srv := chainServer()
	defer srv.Close()

	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}
	result, err := ExecuteHTTPModule(context.Background(), srv.URL, chainModule(), opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (chain should reach the protected step)", len(result.Findings))
	}
	f := result.Findings[0]
	if f.URL != srv.URL+"/secret" {
		t.Errorf("finding url = %q, want the protected step %q", f.URL, srv.URL+"/secret")
	}
	if f.Extracted["token"] != "tok-abc123" {
		t.Errorf("extracted token = %q, want tok-abc123", f.Extracted["token"])
	}
}

// TestExecuteHTTPChainHaltsWithoutToken proves the value really gates access:
// drop the extractor so {{token}} never resolves, and the authed step must miss
// its matcher, leaving no finding.
func TestExecuteHTTPChainHaltsWithoutToken(t *testing.T) {
	srv := chainServer()
	defer srv.Close()

	def := chainModule()
	def.HTTP.Requests[0].Extractors = nil // never learn the token

	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}
	result, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("got %d findings, want 0 (unauthed step must not match)", len(result.Findings))
	}
}

// TestExecuteHTTPChainStepMatcherHalts confirms a failed matcher on an early
// step stops the chain before the later step records a finding.
func TestExecuteHTTPChainStepMatcherHalts(t *testing.T) {
	srv := chainServer()
	defer srv.Close()

	def := chainModule()
	// gate the login step on a body word it never returns; the chain must stop
	// there and never reach /secret.
	def.HTTP.Requests[0].Matchers = []Matcher{{Type: "word", Part: "body", Words: []string{"nonexistent-marker"}}}

	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}
	result, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("got %d findings, want 0 (chain should halt on the failed login matcher)", len(result.Findings))
	}
}
