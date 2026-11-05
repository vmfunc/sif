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
	"sort"
	"strings"
	"time"
)

// ModuleTest is one inline fixture: a canned response and the verdict the
// module is expected to reach against it. Tests live in the module yaml under
// `tests:` and are run by `sif modules test`. The fixture drives the real
// executor through a local httptest server, so a passing test proves the
// module's own matchers and extractors, not a reimplementation of them.
type ModuleTest struct {
	Name     string        `yaml:"name"`
	Response *TestResponse `yaml:"response,omitempty"`
	Expect   TestExpect    `yaml:"expect"`
}

// TestResponse is the response the fixture server returns for every request the
// module makes during one test case. An omitted status defaults to 200.
type TestResponse struct {
	Status  int               `yaml:"status,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
}

// TestExpect is the asserted outcome of a test case. Match is whether the module
// should report a finding; Extracted, when set, is the subset of extractor
// values the finding must carry (other extracted keys are ignored).
type TestExpect struct {
	Match     bool              `yaml:"match"`
	Extracted map[string]string `yaml:"extracted,omitempty"`
}

// TestCaseResult is the outcome of running one ModuleTest. Reason explains a
// failure (empty when Passed).
type TestCaseResult struct {
	Name   string
	Passed bool
	Reason string
}

// moduleTestTimeout bounds a single fixture request so a wedged executor can't
// hang the whole `modules test` run.
const moduleTestTimeout = 10 * time.Second

// RunModuleTests runs every inline fixture in def and returns one result per
// case, in file order. It returns an error only for a problem that invalidates
// the whole module's tests (an unsupported type, or no fixtures at all); a case
// that simply fails its assertion comes back as a TestCaseResult with Passed
// false, not an error.
func RunModuleTests(def *YAMLModule) ([]TestCaseResult, error) {
	if len(def.Tests) == 0 {
		return nil, fmt.Errorf("module %q has no tests", def.ID)
	}
	switch def.Type {
	case TypeHTTP, TypeFingerprint:
		// both drive an http server; supported below.
	default:
		return nil, fmt.Errorf("module %q: `modules test` fixtures support http and fingerprint modules, not %q", def.ID, def.Type)
	}

	results := make([]TestCaseResult, 0, len(def.Tests))
	for i := range def.Tests {
		tc := &def.Tests[i]
		name := tc.Name
		if name == "" {
			name = fmt.Sprintf("case %d", i+1)
		}
		results = append(results, runOneModuleTest(def, tc, name))
	}
	return results, nil
}

// runOneModuleTest stands up a server that answers every request with the
// fixture response, runs the module against it, and checks the verdict.
func runOneModuleTest(def *YAMLModule, tc *ModuleTest, name string) TestCaseResult {
	fail := func(format string, a ...any) TestCaseResult {
		return TestCaseResult{Name: name, Passed: false, Reason: fmt.Sprintf(format, a...)}
	}

	resp := tc.Response
	if resp == nil {
		resp = &TestResponse{}
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp.Body))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), moduleTestTimeout)
	defer cancel()

	var (
		res *Result
		err error
	)
	switch def.Type {
	case TypeFingerprint:
		res, err = ExecuteFingerprintModule(ctx, srv.URL, def, Options{Timeout: moduleTestTimeout})
	default:
		res, err = ExecuteHTTPModule(ctx, srv.URL, def, Options{Timeout: moduleTestTimeout})
	}
	if err != nil {
		return fail("execute: %v", err)
	}

	gotMatch := len(res.Findings) > 0
	if gotMatch != tc.Expect.Match {
		return fail("expected match=%t, got match=%t (%d findings)", tc.Expect.Match, gotMatch, len(res.Findings))
	}

	if len(tc.Expect.Extracted) > 0 {
		got := mergeExtracted(res.Findings)
		for k, want := range tc.Expect.Extracted {
			if have, ok := got[k]; !ok {
				return fail("expected extracted %q=%q, but it was not extracted (have: %s)", k, want, extractedKeys(got))
			} else if have != want {
				return fail("expected extracted %q=%q, got %q", k, want, have)
			}
		}
	}

	return TestCaseResult{Name: name, Passed: true}
}

// mergeExtracted flattens the extracted maps of all findings into one. Later
// findings win on a key collision, which is fine: fixtures assert specific
// values, and a module that extracts the same key with two values from one
// response is already ambiguous.
func mergeExtracted(findings []Finding) map[string]string {
	out := make(map[string]string)
	for _, f := range findings {
		for k, v := range f.Extracted {
			out[k] = v
		}
	}
	return out
}

// extractedKeys lists the keys present, sorted, for a readable failure message.
func extractedKeys(m map[string]string) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
