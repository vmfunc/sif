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

func TestRunExtractorsJSON(t *testing.T) {
	const body = `{"version":"1.2.3","app":{"name":"sif"},"items":[{"id":7}]}`
	resp := fakeResponse(t, 200, nil)

	tests := []struct {
		name  string
		paths []string
		want  string // "" means the extractor should set nothing
	}{
		{"top level", []string{"version"}, "1.2.3"},
		{"nested", []string{"app.name"}, "sif"},
		{"array index", []string{"items.0.id"}, "7"},
		{"first existing wins", []string{"missing", "version"}, "1.2.3"},
		{"no match", []string{"nope"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := []Extractor{{Type: "json", Name: "v", Part: "body", JSON: tt.paths}}
			got := runExtractors(ex, resp, body)
			if tt.want == "" {
				if v, ok := got["v"]; ok {
					t.Errorf("expected no extraction, got %q", v)
				}
				return
			}
			if got["v"] != tt.want {
				t.Errorf("got %q, want %q", got["v"], tt.want)
			}
		})
	}
}

func TestExecuteHTTPModuleJSONExtractor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"9.9.9"}`))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "j",
		Type: TypeHTTP,
		Info: YAMLModuleInfo{Severity: "info"},
		HTTP: &HTTPConfig{
			Method:     "GET",
			Paths:      []string{"{{BaseURL}}/"},
			Matchers:   []Matcher{{Type: "status", Status: []int{200}}},
			Extractors: []Extractor{{Type: "json", Name: "version", Part: "body", JSON: []string{"version"}}},
		},
	}

	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout)}
	res, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Extracted["version"]; got != "9.9.9" {
		t.Errorf("extracted version = %q, want 9.9.9", got)
	}
}
