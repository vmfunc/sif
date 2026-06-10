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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/httpx"
)

const testTimeout = 5 * time.Second

// TestExecuteHTTPModuleMatchAndExtract drives the full executor against a live
// httptest server: a request hits a path, a matcher fires, an extractor captures.
func TestExecuteHTTPModuleMatchAndExtract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Header().Set("X-App", "demo")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`flag{found-it} session=sess-4242`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "test-http-hit",
		Type: TypeHTTP,
		Info: YAMLModuleInfo{Severity: "high"},
		HTTP: &HTTPConfig{
			Method: "GET",
			Paths:  []string{"{{BaseURL}}/admin", "{{BaseURL}}/missing"},
			Matchers: []Matcher{
				{Type: "status", Status: []int{200}},
				{Type: "word", Part: "body", Words: []string{"flag{found-it}"}},
			},
			Extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`session=(\S+)`}, Group: 1},
			},
		},
	}

	// route through the shared httpx client so proxy/-H/-rate-limit would apply.
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}

	result, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}

	// only /admin satisfies status+word, /missing returns 404.
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high (carried from Info)", f.Severity)
	}
	if f.Extracted["session"] != "sess-4242" {
		t.Errorf("extracted session = %q, want sess-4242", f.Extracted["session"])
	}
	if f.URL != srv.URL+"/admin" {
		t.Errorf("finding url = %q, want %q", f.URL, srv.URL+"/admin")
	}
}

// TestExecuteHTTPModuleNoMatch confirms a module that matches nothing reports
// zero findings without erroring.
func TestExecuteHTTPModuleNoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("nothing interesting"))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "test-http-miss",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths: []string{"{{BaseURL}}/"},
			Matchers: []Matcher{
				{Type: "word", Part: "body", Words: []string{"never-present"}},
			},
		},
	}

	result, err := ExecuteHTTPModule(context.Background(), srv.URL, def, Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)})
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(result.Findings))
	}
}

// TestExecuteHTTPModulePayloadExpansion verifies payload templates reach the
// server and the matching response is captured.
func TestExecuteHTTPModulePayloadExpansion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// only the "boom" payload triggers the vulnerable branch.
		if r.URL.Query().Get("q") == "boom" {
			_, _ = w.Write([]byte("error: sql syntax near boom"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "test-http-payload",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/search?q={{payload}}"},
			Payloads: []string{"safe", "boom"},
			Matchers: []Matcher{
				{Type: "word", Part: "body", Words: []string{"sql syntax"}},
			},
		},
	}

	result, err := ExecuteHTTPModule(context.Background(), srv.URL, def, Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)})
	if err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only boom payload)", len(result.Findings))
	}
}

func TestExecuteHTTPModuleNoConfig(t *testing.T) {
	def := &YAMLModule{ID: "x", Type: TypeHTTP}
	if _, err := ExecuteHTTPModule(context.Background(), "http://h", def, Options{}); err == nil {
		t.Fatal("expected error when HTTP config is nil")
	}
}

// TestExecuteHTTPModuleContextCancel pins the cancellation path. The dispatch
// loop selects between ctx.Done() and the concurrency semaphore, so a cancelled
// context can either short-circuit with ctx.Err() or let the in-flight request
// fail on the dead context. Both are correct: the contract is "never hang, never
// invent a finding", which is what we assert here rather than forcing one race
// winner (that made this test flaky under -count).
func TestExecuteHTTPModuleContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	def := &YAMLModule{
		ID:   "test-http-cancel",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/a"},
			Matchers: []Matcher{{Type: "status", Status: []int{200}}},
		},
	}

	result, err := ExecuteHTTPModule(ctx, srv.URL, def, Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled or nil", err)
		}
		return
	}
	// no error means the request was dispatched but failed on the dead context;
	// either way a cancelled scan must not surface findings.
	if len(result.Findings) != 0 {
		t.Fatalf("cancelled scan produced %d findings, want 0", len(result.Findings))
	}
}

// TestExecuteDNSModuleUnsupported pins the current behavior: DNS execution is
// not implemented and must signal it via ErrUnsupportedModuleType, not by
// quietly returning an empty (successful-looking) result.
func TestExecuteDNSModuleUnsupported(t *testing.T) {
	def := &YAMLModule{ID: "dns-mod", Type: TypeDNS, DNS: &DNSConfig{Type: "A"}}
	result, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{})
	if result != nil {
		t.Errorf("result = %v, want nil for unsupported type", result)
	}
	if !errors.Is(err, ErrUnsupportedModuleType) {
		t.Fatalf("err = %v, want ErrUnsupportedModuleType", err)
	}
}

func TestExecuteTCPModuleUnsupported(t *testing.T) {
	def := &YAMLModule{ID: "tcp-mod", Type: TypeTCP, TCP: &TCPConfig{Port: 22}}
	result, err := ExecuteTCPModule(context.Background(), "example.com", def, Options{})
	if result != nil {
		t.Errorf("result = %v, want nil for unsupported type", result)
	}
	if !errors.Is(err, ErrUnsupportedModuleType) {
		t.Fatalf("err = %v, want ErrUnsupportedModuleType", err)
	}
}

// TestWrapperExecuteRoutesByType confirms the Module wrapper dispatches each
// type to the right executor and propagates the unsupported-type sentinel.
func TestWrapperExecuteRoutesByType(t *testing.T) {
	t.Run("dns routes to unsupported", func(t *testing.T) {
		def := &YAMLModule{ID: "d", Type: TypeDNS, DNS: &DNSConfig{}}
		w := newYAMLModuleWrapper(def, "d.yaml")
		if _, err := w.Execute(context.Background(), "t", Options{}); !errors.Is(err, ErrUnsupportedModuleType) {
			t.Fatalf("err = %v, want ErrUnsupportedModuleType", err)
		}
	})

	t.Run("tcp routes to unsupported", func(t *testing.T) {
		def := &YAMLModule{ID: "t", Type: TypeTCP, TCP: &TCPConfig{}}
		w := newYAMLModuleWrapper(def, "t.yaml")
		if _, err := w.Execute(context.Background(), "t", Options{}); !errors.Is(err, ErrUnsupportedModuleType) {
			t.Fatalf("err = %v, want ErrUnsupportedModuleType", err)
		}
	})

	t.Run("missing http config errors", func(t *testing.T) {
		def := &YAMLModule{ID: "h", Type: TypeHTTP}
		w := newYAMLModuleWrapper(def, "h.yaml")
		if _, err := w.Execute(context.Background(), "t", Options{}); err == nil {
			t.Fatal("expected error for missing http config")
		}
	})

	t.Run("unknown type errors", func(t *testing.T) {
		def := &YAMLModule{ID: "z", Type: ModuleType("bogus")}
		w := newYAMLModuleWrapper(def, "z.yaml")
		if _, err := w.Execute(context.Background(), "t", Options{}); err == nil {
			t.Fatal("expected error for unknown module type")
		}
	})
}

func TestTruncateEvidence(t *testing.T) {
	short := "short evidence"
	if got := truncateEvidence(short); got != short {
		t.Errorf("short evidence changed: %q", got)
	}

	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	got := truncateEvidence(string(long))
	// 500 chars of content plus the ellipsis marker.
	if len(got) != 503 {
		t.Errorf("truncated len = %d, want 503", len(got))
	}
	if got[len(got)-3:] != "..." {
		t.Errorf("truncated evidence missing ellipsis: %q", got[len(got)-3:])
	}
}
