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

package modules_test

import (
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/modules"
)

// wordModule builds an http module that matches a word in the body and extracts
// a json field, for driving the fixture runner.
func wordModule(tests []modules.ModuleTest) *modules.YAMLModule {
	return &modules.YAMLModule{
		ID:   "demo",
		Type: modules.TypeHTTP,
		Info: modules.YAMLModuleInfo{Name: "demo", Severity: "high", Description: "d"},
		HTTP: &modules.HTTPConfig{
			Method: "GET",
			Paths:  []string{"{{BaseURL}}/status"},
			Matchers: []modules.Matcher{
				{Type: "word", Part: "body", Words: []string{"leak"}},
			},
			Extractors: []modules.Extractor{
				{Type: "json", Name: "version", Part: "body", JSON: []string{"version"}},
			},
		},
		Tests: tests,
	}
}

func TestRunModuleTests(t *testing.T) {
	def := wordModule([]modules.ModuleTest{
		{
			Name:     "matches and extracts",
			Response: &modules.TestResponse{Status: 200, Body: `{"leak":true,"version":"1.2.3"}`},
			Expect:   modules.TestExpect{Match: true, Extracted: map[string]string{"version": "1.2.3"}},
		},
		{
			Name:     "no match on clean body",
			Response: &modules.TestResponse{Status: 200, Body: "all good"},
			Expect:   modules.TestExpect{Match: false},
		},
	})

	results, err := modules.RunModuleTests(def)
	if err != nil {
		t.Fatalf("RunModuleTests: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("case %q failed: %s", r.Name, r.Reason)
		}
	}
}

func TestRunModuleTestsCatchesWrongExpectation(t *testing.T) {
	cases := []struct {
		name   string
		test   modules.ModuleTest
		reason string // substring expected in the failure reason
	}{
		{
			name:   "expected match but body is clean",
			test:   modules.ModuleTest{Response: &modules.TestResponse{Status: 200, Body: "clean"}, Expect: modules.TestExpect{Match: true}},
			reason: "expected match=true",
		},
		{
			name:   "wrong extracted value",
			test:   modules.ModuleTest{Response: &modules.TestResponse{Status: 200, Body: `{"leak":1,"version":"9"}`}, Expect: modules.TestExpect{Match: true, Extracted: map[string]string{"version": "1"}}},
			reason: `got "9"`,
		},
		{
			name:   "missing extracted key",
			test:   modules.ModuleTest{Response: &modules.TestResponse{Status: 200, Body: `{"leak":1}`}, Expect: modules.TestExpect{Match: true, Extracted: map[string]string{"missing": "x"}}},
			reason: "was not extracted",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := modules.RunModuleTests(wordModule([]modules.ModuleTest{tc.test}))
			if err != nil {
				t.Fatalf("RunModuleTests: %v", err)
			}
			if results[0].Passed {
				t.Fatalf("case should have failed but passed")
			}
			if !strings.Contains(results[0].Reason, tc.reason) {
				t.Errorf("reason = %q, want it to contain %q", results[0].Reason, tc.reason)
			}
		})
	}
}

func TestRunModuleTestsDefaultsStatusTo200(t *testing.T) {
	// a fixture with no explicit status should serve 200, so a status:200
	// matcher still fires.
	def := &modules.YAMLModule{
		ID:   "status200",
		Type: modules.TypeHTTP,
		Info: modules.YAMLModuleInfo{Name: "s", Severity: "info", Description: "d"},
		HTTP: &modules.HTTPConfig{
			Paths:    []string{"{{BaseURL}}/"},
			Matchers: []modules.Matcher{{Type: "status", Status: []int{200}}},
		},
		Tests: []modules.ModuleTest{
			{Name: "default 200", Response: &modules.TestResponse{Body: "x"}, Expect: modules.TestExpect{Match: true}},
		},
	}
	results, err := modules.RunModuleTests(def)
	if err != nil {
		t.Fatalf("RunModuleTests: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("default-status case failed: %s", results[0].Reason)
	}
}

func TestRunModuleTestsErrors(t *testing.T) {
	t.Run("no tests", func(t *testing.T) {
		def := &modules.YAMLModule{ID: "x", Type: modules.TypeHTTP, HTTP: &modules.HTTPConfig{}}
		if _, err := modules.RunModuleTests(def); err == nil {
			t.Fatal("expected an error for a module with no tests")
		}
	})
	t.Run("unsupported type", func(t *testing.T) {
		def := &modules.YAMLModule{
			ID:    "tcpmod",
			Type:  modules.TypeTCP,
			Tests: []modules.ModuleTest{{Name: "x", Expect: modules.TestExpect{Match: false}}},
		}
		if _, err := modules.RunModuleTests(def); err == nil {
			t.Fatal("expected an error for a tcp module's fixtures")
		}
	})
}
