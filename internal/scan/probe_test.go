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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbe_TitleServerStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>  Welcome Home  </title></head><body>hi</body></html>"))
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !result.Alive {
		t.Fatalf("expected alive, got %+v", result)
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	// title text is trimmed of surrounding whitespace
	if result.Title != "Welcome Home" {
		t.Errorf("expected trimmed title, got %q", result.Title)
	}
	if result.Server != "nginx/1.25.3" {
		t.Errorf("expected server header, got %q", result.Server)
	}
}

func TestProbe_RedirectChain(t *testing.T) {
	// /a -> /b -> /c(final); the chain should record both intermediate hops the
	// client followed before landing on the final 200.
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/c", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<title>final</title>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	result, err := Probe(srv.URL+"/a", 5*time.Second, "")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !result.Alive || result.StatusCode != http.StatusOK {
		t.Fatalf("expected alive 200 after redirects, got %+v", result)
	}
	if result.Title != "final" {
		t.Errorf("expected title of final hop, got %q", result.Title)
	}
	// two hops were followed (/b and /c are the urls requested after the first)
	if len(result.RedirectChain) != 2 {
		t.Fatalf("expected 2 redirect hops, got %d: %v", len(result.RedirectChain), result.RedirectChain)
	}
	if !hasSuffix(result.RedirectChain[0], "/b") || !hasSuffix(result.RedirectChain[1], "/c") {
		t.Errorf("expected chain to walk /b then /c, got %v", result.RedirectChain)
	}
}

func TestProbe_DeadHost(t *testing.T) {
	// a server we immediately close so the dial fails; a dead host is a reported
	// result, not an error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	result, err := Probe(deadURL, 2*time.Second, "")
	if err != nil {
		t.Fatalf("Probe should not error on a dead host: %v", err)
	}
	if result.Alive {
		t.Errorf("expected dead host, got %+v", result)
	}
}

func TestProbe_ExtractTitle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"simple", "<title>hello</title>", "hello"},
		{"trimmed", "<title>  spaced  </title>", "spaced"},
		{"attrs", `<title lang="en">attr</title>`, "attr"},
		{"multiline", "<title>line one\nline two</title>", "line one\nline two"},
		{"none", "<html><body>no title</body></html>", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTitle([]byte(tt.body))
			if got != tt.want {
				t.Errorf("extractTitle(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestProbeResult_ResultType(t *testing.T) {
	r := &ProbeResult{}
	if r.ResultType() != "probe" {
		t.Errorf("expected result type 'probe', got %q", r.ResultType())
	}
}

// hasSuffix is a tiny local helper so the redirect-chain assertions read clearly.
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
