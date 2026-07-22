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
	"testing"

	"github.com/vmfunc/sif/internal/httpx"
)

// a target whose root 302-redirects to a landing page: the redirect response
// carries the signal (a Location header, the 302 status), the landing page does
// not. matching that signal requires stopping at the 3xx.
func redirectServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landing" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("landed"))
			return
		}
		w.Header().Set("Location", "/landing")
		w.WriteHeader(http.StatusFound)
	}))
}

func TestExecuteHTTPModuleDisableRedirects(t *testing.T) {
	srv := redirectServer()
	defer srv.Close()

	mod := func(disable bool) *YAMLModule {
		return &YAMLModule{
			ID:   "redirect",
			Type: TypeHTTP,
			HTTP: &HTTPConfig{
				Paths:            []string{"{{BaseURL}}/"},
				DisableRedirects: disable,
				Matchers: []Matcher{
					{Type: "status", Status: []int{http.StatusFound}},
				},
			},
		}
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}

	followed, err := ExecuteHTTPModule(context.Background(), srv.URL, mod(false), opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule(follow): %v", err)
	}
	if len(followed.Findings) != 0 {
		t.Fatalf("with redirects followed, got %d findings matching 302, want 0", len(followed.Findings))
	}

	stopped, err := ExecuteHTTPModule(context.Background(), srv.URL, mod(true), opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule(no-follow): %v", err)
	}
	if len(stopped.Findings) != 1 {
		t.Fatalf("with redirects disabled, got %d findings matching 302, want 1", len(stopped.Findings))
	}
}
