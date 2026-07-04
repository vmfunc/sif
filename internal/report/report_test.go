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

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// fakeResults are a couple of representative findings across two targets used by
// every test below.
func fakeResults() []Result {
	return []Result{
		{Target: "https://a.example.com", Module: "cors", Data: json.RawMessage(`{"severity":"high"}`)},
		{Target: "https://a.example.com", Module: "probe", Data: json.RawMessage(`{"status_code":200}`)},
		{Target: "https://b.example.com", Module: "redirect", Data: json.RawMessage(`{"parameter":"next"}`)},
	}
}

func TestSARIF_ValidAndContainsFindings(t *testing.T) {
	out, err := SARIF(fakeResults())
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	// the output must parse back into the sarif shape
	var doc sarifLog
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("sarif output is not valid json: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("expected sarif version 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected exactly one run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "sif" {
		t.Errorf("expected tool name sif, got %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}

	// each finding's module id surfaces as the ruleId and its target as the uri
	tests := []struct {
		ruleID string
		target string
	}{
		{"cors", "https://a.example.com"},
		{"probe", "https://a.example.com"},
		{"redirect", "https://b.example.com"},
	}
	for _, tt := range tests {
		if !sarifHasResult(run.Results, tt.ruleID, tt.target) {
			t.Errorf("expected sarif result rule=%q target=%q, got %+v", tt.ruleID, tt.target, run.Results)
		}
	}

	// rules list each module id once, deduped across targets
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 deduped rules, got %d: %+v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules)
	}
}

func TestSARIF_DedupesRulesAcrossTargets(t *testing.T) {
	// the same module on two targets must yield one rule but two results.
	results := []Result{
		{Target: "https://a.example.com", Module: "cors", Data: json.RawMessage(`{}`)},
		{Target: "https://b.example.com", Module: "cors", Data: json.RawMessage(`{}`)},
	}
	out, err := SARIF(results)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 deduped rule, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(run.Results))
	}
}

func TestSARIF_RulesOrderIsDeterministic(t *testing.T) {
	// the same input must serialize to byte-identical sarif every run; the rules
	// list is built from a set, so its order has to be sorted rather than left to
	// map iteration order.
	results := []Result{
		{Target: "https://t", Module: "aaa", Data: json.RawMessage(`{}`)},
		{Target: "https://t", Module: "bbb", Data: json.RawMessage(`{}`)},
		{Target: "https://t", Module: "ccc", Data: json.RawMessage(`{}`)},
		{Target: "https://t", Module: "ddd", Data: json.RawMessage(`{}`)},
		{Target: "https://t", Module: "eee", Data: json.RawMessage(`{}`)},
	}
	first, err := SARIF(results)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	for i := 0; i < 200; i++ {
		out, err := SARIF(results)
		if err != nil {
			t.Fatalf("SARIF: %v", err)
		}
		if !bytes.Equal(out, first) {
			t.Fatalf("sarif output not reproducible across runs:\nfirst:\n%s\ngot:\n%s", first, out)
		}
	}

	// and the ids come out in sorted order.
	var doc sarifLog
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	rules := doc.Runs[0].Tool.Driver.Rules
	for i := 1; i < len(rules); i++ {
		if rules[i-1].ID > rules[i].ID {
			t.Errorf("rules not sorted: %q before %q", rules[i-1].ID, rules[i].ID)
		}
	}
}

func TestSARIF_Empty(t *testing.T) {
	out, err := SARIF(nil)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("empty sarif is not valid json: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected one run even when empty, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected no results, got %d", len(doc.Runs[0].Results))
	}
}

func TestMarkdown_ContainsTargetsAndModules(t *testing.T) {
	out := string(Markdown(fakeResults()))

	wants := []string{
		"# sif scan report",
		"## https://a.example.com",
		"## https://b.example.com",
		"### cors",
		"### probe",
		"### redirect",
		`"severity": "high"`, // re-indented finding body
		`"parameter": "next"`,
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("markdown report missing %q\n---\n%s", want, out)
		}
	}
}

func TestMarkdown_GroupsByTarget(t *testing.T) {
	// a.example.com's two modules must both appear before b.example.com's header.
	out := string(Markdown(fakeResults()))
	aHeader := strings.Index(out, "## https://a.example.com")
	bHeader := strings.Index(out, "## https://b.example.com")
	if aHeader < 0 || bHeader < 0 {
		t.Fatalf("missing target headers in:\n%s", out)
	}
	if aHeader > bHeader {
		t.Errorf("expected target a before target b, got a=%d b=%d", aHeader, bHeader)
	}
	// both of a's modules sit between a's header and b's header
	corsIdx := strings.Index(out, "### cors")
	probeIdx := strings.Index(out, "### probe")
	if corsIdx < aHeader || corsIdx > bHeader || probeIdx < aHeader || probeIdx > bHeader {
		t.Errorf("expected a's modules grouped under a, cors=%d probe=%d (a=%d b=%d)", corsIdx, probeIdx, aHeader, bHeader)
	}
}

// sarifHasResult reports whether any result carries the given rule id and target
// uri, the pairing that proves a finding survived serialization.
func sarifHasResult(results []sarifResult, ruleID, target string) bool {
	for i := 0; i < len(results); i++ {
		r := results[i]
		if r.RuleID != ruleID {
			continue
		}
		for j := 0; j < len(r.Locations); j++ {
			if r.Locations[j].PhysicalLocation.ArtifactLocation.URI == target {
				return true
			}
		}
	}
	return false
}
